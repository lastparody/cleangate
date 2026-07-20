package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"

	"cleangate/pkg/cert"
	"cleangate/pkg/engine"
	"cleangate/pkg/util"
)

type Server struct {
	port        int
	upstream    string // e.g., "127.0.0.1:8080"
	engine      *engine.Engine
	certManager *cert.CertManager
}

func NewServer(port int, upstream string, eng *engine.Engine, cm *cert.CertManager) *Server {
	return &Server{
		port:        port,
		upstream:    upstream,
		engine:      eng,
		certManager: cm,
	}
}

func (s *Server) Start(ctx context.Context) error {
	addr := fmt.Sprintf("127.0.0.1:%d", s.port)
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	util.Debugf("CleanGate Proxy started on %s", addr)
	util.Debugf("Using Upstream Proxy: %s", s.upstream)

	for {
		conn, err := l.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				util.Debugf("Accept error: %v", err)
				continue
			}
		}

		util.Debugf("New connection from %s", conn.RemoteAddr())
		go s.handleConnection(conn)
	}
}

func (s *Server) handleConnection(conn net.Conn) {
	// We read the first line to determine if it's CONNECT or normal HTTP
	clientReader := bufio.NewReader(conn)
	req, err := http.ReadRequest(clientReader)
	if err != nil {
		conn.Close()
		return
	}

	if req.Method == http.MethodConnect {
		s.handleHTTPS(conn, clientReader, req)
	} else {
		s.handleHTTP(conn, clientReader, req)
	}
}

func (s *Server) handleHTTP(conn net.Conn, clientReader *bufio.Reader, req *http.Request) {
	defer conn.Close()

	if s.engine.IsBlocked(req.URL.String(), req.Host) {
		util.Debugf("[BLOCKED HTTP] %s", req.URL.String())
		conn.Write([]byte("HTTP/1.1 403 Forbidden\r\n\r\nBlocked by CleanGate"))
		return
	}

	util.Debugf("[ALLOWED HTTP] %s -> Forwarding to %s", req.URL.String(), s.upstream)

	// Connect to upstream proxy
	upstreamConn, err := net.Dial("tcp", s.upstream)
	if err != nil {
		util.Debugf("Upstream Dial error: %v", err)
		return
	}
	defer upstreamConn.Close()

	// Write the request to upstream
	err = req.Write(upstreamConn)
	if err != nil {
		return
	}

	// Pipe the rest
	go io.Copy(upstreamConn, clientReader)
	io.Copy(conn, upstreamConn)
}

func (s *Server) handleHTTPS(conn net.Conn, clientReader *bufio.Reader, req *http.Request) {
	// Quick domain-level block check before MITM
	if s.engine.IsBlocked("https://"+req.Host, req.Host) {
		util.Debugf("[BLOCKED HTTPS DOMAIN] %s", req.Host)
		conn.Write([]byte("HTTP/1.1 403 Forbidden\r\n\r\nBlocked by CleanGate"))
		conn.Close()
		return
	}

	util.Debugf("Establishing MITM for HTTPS domain: %s", req.Host)

	// 1. Tell the client we are ready for TLS
	_, err := conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	if err != nil {
		conn.Close()
		return
	}

	// 2. Wrap client connection in TLS Server (MITM)
	// Force HTTP/1.1 to simplify interception loop
	tlsConf := s.certManager.TLSConfig().Clone()
	tlsConf.NextProtos = []string{"http/1.1"}

	tlsConn := tls.Server(conn, tlsConf)
	err = tlsConn.Handshake()
	if err != nil {
		util.Debugf("MITM Handshake failed for %s: %v", req.Host, err)
		conn.Close()
		return
	}
	defer tlsConn.Close()

	// 3. Read the actual HTTP request inside the TLS tunnel
	tlsReader := bufio.NewReader(tlsConn)
	innerReq, err := http.ReadRequest(tlsReader)
	if err != nil {
		return
	}

	// Construct full URL for Adblock matching
	scheme := "https://"
	fullURL := scheme + req.Host + innerReq.URL.Path
	if innerReq.URL.RawQuery != "" {
		fullURL += "?" + innerReq.URL.RawQuery
	}

	// 4. Check Adblock rules against the full URL path
	if s.engine.IsBlocked(fullURL, req.Host) {
		util.Debugf("[BLOCKED HTTPS URL] %s", fullURL)
		tlsConn.Write([]byte("HTTP/1.1 403 Forbidden\r\n\r\nBlocked by CleanGate"))
		return
	}

	util.Debugf("[ALLOWED HTTPS] %s -> Forwarding to %s via CONNECT", fullURL, s.upstream)

	// 5. Connect to upstream (OpenGate) via TCP
	upstreamConn, err := net.Dial("tcp", s.upstream)
	if err != nil {
		util.Debugf("HTTPS Upstream Dial error: %v", err)
		return
	}
	defer upstreamConn.Close()

	// 6. Ask Upstream proxy to CONNECT to the target server
	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", req.Host, req.Host)
	upstreamConn.Write([]byte(connectReq))

	// Read upstream's 200 OK response
	upstreamReader := bufio.NewReader(upstreamConn)
	upstreamResp, err := http.ReadResponse(upstreamReader, nil)
	if err != nil || upstreamResp.StatusCode != 200 {
		return
	}

	// 7. Establish TLS with the remote server through the upstream tunnel
	targetTLSConn := tls.Client(upstreamConn, &tls.Config{
		ServerName: strings.Split(req.Host, ":")[0],
	})
	err = targetTLSConn.Handshake()
	if err != nil {
		util.Debugf("Target TLS Handshake failed: %v", err)
		return
	}
	defer targetTLSConn.Close()

	util.Debugf("Starting HTTP interceptor loop for %s", req.Host)
	s.proxyLoop(tlsConn, targetTLSConn, tlsReader, req.Host, innerReq)
}

func (s *Server) proxyLoop(clientConn net.Conn, targetConn net.Conn, clientReader *bufio.Reader, targetHost string, firstReq *http.Request) {
	targetReader := bufio.NewReader(targetConn)
	req := firstReq

	for {
		// 1. Perform Network Block Check (Crucial: do this before writing to target!)
		fullURL := "https://" + targetHost + req.URL.Path
		if req.URL.RawQuery != "" {
			fullURL += "?" + req.URL.RawQuery
		}

		// Extract Source Domain from Referer (Crucial for third-party adblock rules)
		sourceDomain := targetHost
		if ref := req.Header.Get("Referer"); ref != "" {
			if strings.Contains(ref, "://") {
				parts := strings.Split(ref, "/")
				if len(parts) > 2 {
					sourceDomain = strings.Split(parts[2], ":")[0]
				}
			}
		}

		if s.engine.IsBlocked(fullURL, sourceDomain) {
			util.Debugf("[BLOCKED HTTPS URL] %s", fullURL)
			clientConn.Write([]byte("HTTP/1.1 403 Forbidden\r\n\r\nBlocked by CleanGate"))
			return // Connection closed to prevent broken streams
		}

		// 2. Forward request to target
		err := req.Write(targetConn)
		if err != nil {
			return
		}

		// 3. Read response from target
		resp, err := http.ReadResponse(targetReader, req)
		if err != nil {
			return
		}

		// 4. Get Cosmetic CSS for this domain and Inject it
		css := s.engine.GetInjectionCSS(targetHost)
		if css != "" {
			err = InjectHTML(resp, css)
			if err != nil {
				util.Debugf("HTML Injection failed for %s: %v", targetHost, err)
			}
		}

		// 5. Forward response to client
		err = resp.Write(clientConn)
		if err != nil {
			return
		}

		// 6. Read next request on this Keep-Alive connection
		req, err = http.ReadRequest(clientReader)
		if err != nil {
			return // Connection closed or timeout
		}
	}
}
