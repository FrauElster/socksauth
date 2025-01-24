package socksauth

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

type Proxy struct {
	Username string
	Password string
	NextHost string

	listener     net.Listener
	activeConns  sync.Map
	shutdownChan chan struct{}
	wg           sync.WaitGroup
}

func NewProxy(username, password, nextHost string) (*Proxy, error) {
	if username == "" {
		return nil, errors.New("username cannot be empty")
	}
	if password == "" {
		return nil, errors.New("password cannot be empty")
	}
	if nextHost == "" {
		return nil, errors.New("next host cannot be empty")
	}

	// set default port if non is set
	if _, _, err := net.SplitHostPort(nextHost); err != nil {
		nextHost = fmt.Sprintf("%s:1080", nextHost)
	}
	nextHost = strings.TrimPrefix(nextHost, "socks5://")

	return &Proxy{
		Username:     username,
		Password:     password,
		NextHost:     nextHost,
		shutdownChan: make(chan struct{}),
	}, nil
}

func (p *Proxy) Start(listenPort int) error {
	addr := fmt.Sprintf(":%d", listenPort)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to start listener on %s: %w", addr, err)
	}
	p.listener = listener

	go func() {
		<-p.shutdownChan
		p.listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-p.shutdownChan:
				return nil
			default:
				return fmt.Errorf("failed to accept connection: %w", err)
			}
		}

		tcpConn, ok := conn.(*net.TCPConn)
		if !ok {
			conn.Close()
			continue
		}

		// Set keep-alive for the connection
		if err := tcpConn.SetKeepAlive(true); err != nil {
			tcpConn.Close()
			continue
		}
		if err := tcpConn.SetKeepAlivePeriod(30 * time.Second); err != nil {
			tcpConn.Close()
			continue
		}

		p.wg.Add(1)
		p.activeConns.Store(tcpConn, struct{}{})
		go func() {
			defer p.wg.Done()
			defer p.activeConns.Delete(tcpConn)
			p.handleConnection(tcpConn)
		}()
	}
}

// Shutdown gracefully shuts down the proxy server
func (p *Proxy) Shutdown(ctx context.Context) error {
	// Signal shutdown
	close(p.shutdownChan)

	// Close listener
	if p.listener != nil {
		p.listener.Close()
	}

	// Close all active connections
	p.activeConns.Range(func(key, value interface{}) bool {
		if conn, ok := key.(net.Conn); ok {
			conn.Close()
		}
		return true
	})

	// Wait for all connections to finish with context timeout
	done := make(chan struct{})
	go func() {
		p.wg.Wait()
		close(done)
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-done:
		return nil
	}
}

func (p *Proxy) handleConnection(clientConn net.Conn) {
	// Convert to TCP connection for access to CloseWrite
	tcpConn, ok := clientConn.(*net.TCPConn)
	if !ok {
		fmt.Printf("Client connection is not TCP\n")
		clientConn.Close()
		return
	}
	defer tcpConn.Close()

	// Read the SOCKS5 handshake from client
	if err := p.handleClientHandshake(tcpConn); err != nil {
		fmt.Printf("Client handshake failed: %v\n", err)
		return
	}

	// Connect to next proxy and authenticate
	nextProxy, err := p.connectToNextProxy()
	if err != nil {
		fmt.Printf("Failed to connect to next proxy: %v\n", err)
		return
	}
	defer nextProxy.Close()

	// Forward the client's request to the next proxy
	if err := p.forwardTraffic(tcpConn, nextProxy); err != nil {
		fmt.Printf("Failed to forward traffic: %v\n", err)
		return
	}
}

func (p *Proxy) handleClientHandshake(conn net.Conn) error {
	// Read version and number of methods
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return err
	}

	if header[0] != 5 {
		return errors.New("invalid SOCKS version")
	}

	// Read authentication methods
	methods := make([]byte, header[1])
	if _, err := io.ReadFull(conn, methods); err != nil {
		return err
	}

	// Respond with no authentication required
	response := []byte{5, 0}
	if _, err := conn.Write(response); err != nil {
		return err
	}

	return nil
}

func (p *Proxy) connectToNextProxy() (net.Conn, error) {
	// Connect to the next proxy
	nextProxy, err := net.Dial("tcp", p.NextHost)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to next proxy: %w", err)
	}

	tcpConn, ok := nextProxy.(*net.TCPConn)
	if !ok {
		nextProxy.Close()
		return nil, errors.New("next proxy connection is not TCP")
	}

	// Set timeouts for the handshake process
	if err := tcpConn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("failed to set deadline: %w", err)
	}

	// SOCKS5 handshake with authentication
	// Send version and auth methods (support both no auth and username/password auth)
	if _, err := tcpConn.Write([]byte{5, 2, 0, 2}); err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("failed to send auth methods: %w", err)
	}

	// Read server's response
	response := make([]byte, 2)
	if _, err := io.ReadFull(tcpConn, response); err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("failed to read auth method response: %w", err)
	}

	if response[0] != 5 {
		tcpConn.Close()
		return nil, errors.New("invalid SOCKS version in response")
	}

	// Handle authentication based on server's choice
	switch response[1] {
	case 0: // No authentication required
		// Continue without authentication
	case 2: // Username/password authentication
		// Prepare auth request with correct length allocation
		authLen := 1 + 1 + len(p.Username) + 1 + len(p.Password) // version + userlen + user + passlen + pass
		auth := make([]byte, 0, authLen)
		auth = append(auth, 1) // auth version
		auth = append(auth, byte(len(p.Username)))
		auth = append(auth, []byte(p.Username)...)
		auth = append(auth, byte(len(p.Password)))
		auth = append(auth, []byte(p.Password)...)

		if _, err := tcpConn.Write(auth); err != nil {
			tcpConn.Close()
			return nil, fmt.Errorf("failed to send auth request: %w", err)
		}

		// Read auth response
		// Read auth response
		authResponse := make([]byte, 2)
		if _, err := io.ReadFull(tcpConn, authResponse); err != nil {
			tcpConn.Close()
			return nil, fmt.Errorf("failed to read auth response: %w", err)
		}

		if authResponse[0] != 1 {
			tcpConn.Close()
			return nil, errors.New("invalid auth response version")
		}

		if authResponse[1] != 0 {
			tcpConn.Close()
			return nil, errors.New("authentication failed")
		}
	default:
		tcpConn.Close()
		return nil, fmt.Errorf("unsupported authentication method: %d", response[1])
	}

	// Clear the deadline after handshake is complete
	if err := tcpConn.SetDeadline(time.Time{}); err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("failed to clear deadline: %w", err)
	}

	return tcpConn, nil
}

func (p *Proxy) forwardTraffic(clientConn, nextProxy net.Conn) (err error) {
	var connectionRequest []byte
	connectionRequest, err = readConnectionRequest(clientConn)
	if err != nil {
		return fmt.Errorf("failed to read connection request: %w", err)
	}
	if _, err := nextProxy.Write(connectionRequest); err != nil {
		return fmt.Errorf("failed to forward request: %w", err)
	}

	var response []byte
	response, err = readConnectionResponse(nextProxy)
	if err != nil {
		return fmt.Errorf("failed to read connection response: %w", err)
	}
	if _, err := clientConn.Write(response); err != nil {
		return fmt.Errorf("failed to forward response: %w", err)
	}

	// Start bidirectional forwarding
	done := make(chan error, 2)
	go func() {
		_, err := io.Copy(nextProxy, clientConn)
		if err != nil {
			err = fmt.Errorf("failed to copy from client to proxy: %w", err)
		}
		nextProxy.(*net.TCPConn).CloseWrite()
		done <- err
	}()

	go func() {
		_, err := io.Copy(clientConn, nextProxy)
		if err != nil {
			err = fmt.Errorf("failed to copy from proxy to client: %w", err)
		}
		clientConn.(*net.TCPConn).CloseWrite()
		done <- err
	}()

	// Wait for both copies to complete
	for i := 0; i < 2; i++ {
		err := <-done
		if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
			return fmt.Errorf("copy error: %w", err)
		}
	}

	return nil
}

func readConnectionRequest(clientConn net.Conn) ([]byte, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(clientConn, header); err != nil {
		return nil, fmt.Errorf("failed to read request header: %w", err)
	}

	if header[0] != 5 {
		return nil, errors.New("invalid SOCKS version in request")
	}

	// Read address type and address
	var addrLen int
	var domainLen []byte
	switch header[3] {
	case 1: // IPv4
		addrLen = net.IPv4len
	case 3: // Domain name
		domainLen = make([]byte, 1)
		if _, err := io.ReadFull(clientConn, domainLen); err != nil {
			return nil, fmt.Errorf("failed to read domain length: %w", err)
		}
		addrLen = int(domainLen[0])
	case 4: // IPv6
		addrLen = net.IPv6len
	default:
		return nil, errors.New("unsupported address type")
	}

	// Read address and port
	addr := make([]byte, addrLen+2) // +2 for port
	if _, err := io.ReadFull(clientConn, addr); err != nil {
		return nil, fmt.Errorf("failed to read address and port: %w", err)
	}

	// Construct and forward the request to the next proxy
	if header[3] == 3 {
		// For domain names, include the length byte
		request := make([]byte, 0, 4+1+len(addr))
		request = append(request, header...)
		request = append(request, domainLen[0])
		request = append(request, addr...)
		return request, nil
	}

	request := make([]byte, 0, 4+len(addr))
	request = append(request, header...)
	request = append(request, addr...)
	return request, nil
}

func readConnectionResponse(nextProxy net.Conn) ([]byte, error) {
	response := make([]byte, 4)
	if _, err := io.ReadFull(nextProxy, response); err != nil {
		return nil, fmt.Errorf("failed to read response header: %w", err)
	}

	switch response[1] {
	case 0:
		// Success
	case 1:
		return nil, errors.New("general SOCKS server failure")
	case 2:
		return nil, errors.New("connection not allowed by ruleset")
	case 3:
		return nil, errors.New("network unreachable")
	case 4:
		return nil, errors.New("host unreachable")
	case 5:
		return nil, errors.New("connection refused by destination host")
	case 6:
		return nil, errors.New("TTL expired")
	case 7:
		return nil, errors.New("command not supported / protocol error")
	case 8:
		return nil, errors.New("address type not supported")
	default:
		return nil, fmt.Errorf("unknown error code: %d", response[1])
	}

	addrLen := 0
	switch response[3] { // Address type
	case 1:
		addrLen = net.IPv4len
	case 3:
		domainLen := make([]byte, 1)
		if _, err := io.ReadFull(nextProxy, domainLen); err != nil {
			return nil, fmt.Errorf("error reading domain name length: %w", err)
		}
		addrLen = int(domainLen[0])
		response = append(response, domainLen...)
	case 4:
		addrLen = net.IPv6len
	default:
		return nil, fmt.Errorf("unknown address type: %d", response[3])
	}

	addr := make([]byte, addrLen+2) // +2 for port
	if _, err := io.ReadFull(nextProxy, addr); err != nil {
		return nil, fmt.Errorf("failed to read address and port: %w", err)
	}

	return append(response, addr...), nil
}
