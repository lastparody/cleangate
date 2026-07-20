package engine

import (
	"strings"
	"sync"
)

// CosmeticEngine stores element hiding rules (CSS selectors)
type CosmeticEngine struct {
	mu              sync.RWMutex
	domainSelectors map[string][]string
	globalSelectors []string
}

func NewCosmeticEngine() *CosmeticEngine {
	return &CosmeticEngine{
		domainSelectors: make(map[string][]string),
		globalSelectors: make([]string, 0),
	}
}

// ParseLine parses a single adblock list line. If it's a cosmetic rule, it stores it.
// Returns true if the line was a cosmetic rule.
func (ce *CosmeticEngine) ParseLine(line string) bool {
	// Simple CSS hiding rule parsing: "domain1,domain2##selector" or "##selector"
	// Advanced rules like #?# or #%# (scriptlets) can be added here later.
	
	if !strings.Contains(line, "##") {
		return false // Not a standard cosmetic rule
	}

	parts := strings.SplitN(line, "##", 2)
	if len(parts) != 2 {
		return false
	}

	domainsStr := strings.TrimSpace(parts[0])
	selector := strings.TrimSpace(parts[1])

	if selector == "" {
		return true
	}

	ce.mu.Lock()
	defer ce.mu.Unlock()

	if domainsStr == "" {
		// Global rule applied everywhere
		ce.globalSelectors = append(ce.globalSelectors, selector)
	} else {
		// Specific domains, format: domain1,~domain2,domain3
		domains := strings.Split(domainsStr, ",")
		for _, d := range domains {
			d = strings.TrimSpace(d)
			// Ignore excluded domains (starting with ~) for simplicity in this basic version
			if d != "" && !strings.HasPrefix(d, "~") {
				ce.domainSelectors[d] = append(ce.domainSelectors[d], selector)
			}
		}
	}

	return true
}

// GetInjectionCSS returns the compiled CSS string to be injected into the HTML of a specific domain
func (ce *CosmeticEngine) GetInjectionCSS(domain string) string {
	ce.mu.RLock()
	defer ce.mu.RUnlock()

	var selectors []string
	
	// Add global selectors
	selectors = append(selectors, ce.globalSelectors...)

	// Add domain specific selectors
	// We check the exact domain, and also higher level domains (e.g. www.youtube.com -> youtube.com)
	parts := strings.Split(domain, ".")
	for i := 0; i < len(parts)-1; i++ {
		subDomain := strings.Join(parts[i:], ".")
		if sel, ok := ce.domainSelectors[subDomain]; ok {
			selectors = append(selectors, sel...)
		}
	}

	if len(selectors) == 0 {
		return ""
	}

	// Join all selectors with comma and add display:none
	// To prevent creating an overly massive single CSS block that breaks browsers, 
	// we could chunk it, but standard modern browsers handle 50k selectors easily.
	css := strings.Join(selectors, ",\n")
	return "<style>\n" + css + " { display: none !important; }\n</style>"
}
