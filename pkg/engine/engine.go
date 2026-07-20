package engine

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pmezard/adblock/adblock"
)

type Engine struct {
	matcher  *adblock.RuleMatcher
	urls     []string
	cacheDir string
	RuleCount int
}

func NewEngine(urls []string) *Engine {
	// Setup App Support Directory for fixed caching
	home, _ := os.UserConfigDir()
	cacheDir := filepath.Join(home, "CleanGate", "lists")
	os.MkdirAll(cacheDir, 0755)

	return &Engine{
		matcher:  adblock.NewMatcher(),
		urls:     urls,
		cacheDir: cacheDir,
	}
}

// StartAutoUpdate initializes the engine and starts the auto-updater
func (e *Engine) StartAutoUpdate(interval time.Duration) {
	e.updateLists() // Initial load/download

	go func() {
		ticker := time.NewTicker(interval)
		for range ticker.C {
			e.updateLists()
		}
	}()
}

func (e *Engine) updateLists() {
	newMatcher := adblock.NewMatcher()
	seenRules := make(map[string]struct{})
	totalRules := 0

	for _, listUrl := range e.urls {
		count, err := e.processList(listUrl, newMatcher, seenRules)
		if err != nil {
			fmt.Printf("Error processing list %s: %v\n", listUrl, err)
		} else {
			totalRules += count
			fmt.Printf("Successfully loaded %d unique rules from %s\n", count, listUrl)
		}
	}

	// Hot-swap the matcher (pointer swap is atomic)
	e.matcher = newMatcher
	e.RuleCount = totalRules
	fmt.Printf("Engine swap complete. Total active unique rules: %d\n", e.RuleCount)
}

func (e *Engine) processList(url string, matcher *adblock.RuleMatcher, seen map[string]struct{}) (int, error) {
	// Create a safe filename using SHA256 of the URL to avoid path traversal or invalid characters
	hash := sha256.Sum256([]byte(url))
	fileName := hex.EncodeToString(hash[:]) + ".txt"
	filePath := filepath.Join(e.cacheDir, fileName)

	var reader io.Reader
	var fileInfo os.FileInfo

	fileInfo, err := os.Stat(filePath)
	fileExists := err == nil

	// Check if we have a saved ETag for this file
	etagPath := filePath + ".etag"
	var localEtag string
	if b, err := os.ReadFile(etagPath); err == nil {
		localEtag = strings.TrimSpace(string(b))
	}

	// Check for updates if file exists
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return 0, err
	}

	if fileExists {
		req.Header.Set("If-Modified-Since", fileInfo.ModTime().UTC().Format(http.TimeFormat))
	}
	if localEtag != "" {
		req.Header.Set("If-None-Match", localEtag)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	
	if err == nil {
		defer resp.Body.Close()
		
		if resp.StatusCode == http.StatusOK {
			// New data downloaded! Save it to our fixed file
			fmt.Printf("Downloading fresh data for %s...\n", url)
			out, err := os.Create(filePath)
			if err != nil {
				return 0, fmt.Errorf("failed to create cache file: %v", err)
			}
			_, err = io.Copy(out, resp.Body)
			out.Close()
			if err != nil {
				return 0, fmt.Errorf("failed to save cache file: %v", err)
			}

			// Save the new ETag if the server provided one
			if etag := resp.Header.Get("ETag"); etag != "" {
				os.WriteFile(etagPath, []byte(etag), 0644)
			}
		} else if resp.StatusCode == http.StatusNotModified {
			// File hasn't changed on server, we use our local cache!
			fmt.Printf("List %s is up to date (304 Not Modified), using cache.\n", url)
		} else {
			// Handle errors like 404, fallback to local file if we have it
			fmt.Printf("Server returned %d for %s, falling back to cache if available.\n", resp.StatusCode, url)
		}
	} else if fileExists {
		fmt.Printf("Network error %v, falling back to cached file for %s.\n", err, url)
	} else {
		return 0, fmt.Errorf("network error and no cache available: %v", err)
	}

	// At this point, we either downloaded a new file, or we rely on the existing local file
	f, err := os.Open(filePath)
	if err != nil {
		return 0, fmt.Errorf("failed to open list file: %v", err)
	}
	defer f.Close()
	reader = f

	// Parse and deduplicate
	scanner := bufio.NewScanner(reader)
	// Buffer size might need to be increased for very long URLs in blocklists
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	addedCount := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		
		// Skip empty lines or comments to save CPU
		if line == "" || strings.HasPrefix(line, "!") || strings.HasPrefix(line, "#") {
			continue
		}

		// Deduplication check
		if _, exists := seen[line]; exists {
			continue // Already added this exact rule from another list!
		}
		seen[line] = struct{}{} // Mark as seen

		rule, err := adblock.ParseRule(line)
		if err == nil && rule != nil {
			matcher.AddRule(rule, 0)
			addedCount++
		}
	}

	return addedCount, scanner.Err()
}

func (e *Engine) IsBlocked(requestUrl string, sourceDomain string) bool {
	if e.matcher == nil {
		return false
	}
	
	req := &adblock.Request{
		URL:          requestUrl,
		Domain:       sourceDomain,
		Timeout:      50 * time.Millisecond,
	}

	matched, _, err := e.matcher.Match(req)
	if err != nil {
		return false
	}
	return matched
}
