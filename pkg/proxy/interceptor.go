package proxy

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/andybalholm/brotli"
)

// InjectHTML reads the response body, decompresses it if needed, injects the CSS/JS payload, and recompresses it.
func InjectHTML(resp *http.Response, payload string) error {
	if payload == "" || resp.Body == nil {
		return nil
	}

	contentType := resp.Header.Get("Content-Type")
	if !strings.Contains(strings.ToLower(contentType), "text/html") {
		return nil
	}

	// Read body
	var reader io.Reader = resp.Body
	encoding := strings.ToLower(resp.Header.Get("Content-Encoding"))

	if encoding == "gzip" {
		gr, err := gzip.NewReader(reader)
		if err != nil {
			return err
		}
		defer gr.Close()
		reader = gr
	} else if encoding == "br" {
		reader = brotli.NewReader(reader)
	}

	bodyBytes, err := io.ReadAll(reader)
	if err != nil {
		return err
	}
	resp.Body.Close()

	html := string(bodyBytes)
	
	// Injection logic: look for </head>, if not found look for </body>
	lowerHtml := strings.ToLower(html)
	if idx := strings.Index(lowerHtml, "</head>"); idx != -1 {
		html = html[:idx] + payload + "\n" + html[idx:]
	} else if idx := strings.Index(lowerHtml, "</body>"); idx != -1 {
		html = html[:idx] + payload + "\n" + html[idx:]
	} else {
		// Just append if we can't find structural tags
		html += payload
	}

	// Re-compress
	var out bytes.Buffer
	if encoding == "gzip" {
		gw := gzip.NewWriter(&out)
		gw.Write([]byte(html))
		gw.Close()
	} else if encoding == "br" {
		bw := brotli.NewWriter(&out)
		bw.Write([]byte(html))
		bw.Close()
	} else {
		out.WriteString(html)
	}

	// Update response headers
	resp.Body = io.NopCloser(&out)
	resp.ContentLength = int64(out.Len())
	resp.Header.Set("Content-Length", fmt.Sprintf("%d", out.Len()))
	
	// Crucial: Remove chunked transfer encoding since we now have a fixed length
	resp.TransferEncoding = nil
	resp.Header.Del("Transfer-Encoding")

	return nil
}
