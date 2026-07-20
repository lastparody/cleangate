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
	fmt.Printf("CleanGate Proxy started on %s\n", addr)
	fmt.Printf("Using Upstream Proxy: %s\n", s.upstream)

	for {
		conn, err := l.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				continue
			}
		}

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
		fmt.Printf("[BLOCKED HTTP] %s\n", req.URL.String())
		conn.Write([]byte("HTTP/1.1 403 Forbidden\r\n\r\nBlocked by CleanGate"))
		return
	}

	// Connect to upstream proxy
	upstreamConn, err := net.Dial("tcp", s.upstream)
	if err != nil {
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
		fmt.Printf("[BLOCKED HTTPS DOMAIN] %s\n", req.Host)
		conn.Write([]byte("HTTP/1.1 403 Forbidden\r\n\r\nBlocked by CleanGate"))
		conn.Close()
		return
	}

	// 1. Tell the client we are ready for TLS
	_, err := conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	if err != nil {
		conn.Close()
		return
	}

	// 2. Wrap client connection in TLS Server (MITM)
	tlsConn := tls.Server(conn, s.certManager.TLSConfig())
	err = tlsConn.Handshake()
	if err != nil {
		fmt.Printf("MITM Handshake failed for %s: %v\n", req.Host, err)
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
		fmt.Printf("[BLOCKED HTTPS URL] %s\n", fullURL)
		tlsConn.Write([]byte("HTTP/1.1 403 Forbidden\r\n\r\nBlocked by CleanGate"))
		return
	}

	// 5. Connect to upstream (OpenGate) via TCP
	upstreamConn, err := net.Dial("tcp", s.upstream)
	if err != nil {
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
		return
	}
	defer targetTLSConn.Close()

	// 8. Forward the intercepted HTTP request to the target TLS connection
	innerReq.Write(targetTLSConn)

	// 9. Transparently pipe the rest of the bidirectional TLS data
	go io.Copy(targetTLSConn, tlsReader)
	io.Copy(tlsConn, targetTLSConn)
}
