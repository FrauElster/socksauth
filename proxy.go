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

const (
	socksSucceeded           = 0
	socksGeneralFailure      = 1
	socksNotAllowed          = 2
	socksNetworkUnreachable  = 3
	socksHostUnreachable     = 4
	socksConnectionRefused   = 5
	socksTTLExpired          = 6
	socksCommandNotSupported = 7
	socksAddressNotSupported = 8
	socksUnknownError        = 9
	socksNoAcceptableMethods = 0xFF

	socksVersion5   = 5
	socksCmdConnect = 1

	socksAuthNoneRequired = 0
	socksAuthUsernamePass = 2

	socksAddrIPv4 = 1
	socksAddrFQDN = 3
	socksAddrIPv6 = 4
)

var (
	errNoAcceptableAuth       = errors.New("no acceptable authentication methods")
	errUnsupportedCommand     = errors.New("unsupported command")
	errUnsupportedAddressType = errors.New("unsupported address type")

	errGeneralFailure       = errors.New("general SOCKS server failure")
	errConnectionNotAllowed = errors.New("connection not allowed by ruleset")
	errNetworkUnreachable   = errors.New("network unreachable")
	errHostUnreachable      = errors.New("host unreachable")
	errConnectionRefused    = errors.New("connection refused by destination host")
	errTTLExpired           = errors.New("TTL expired")
	errCommandNotSupported  = errors.New("command not supported / protocol error")
	errAddressNotSupported  = errors.New("address type not supported")
	errAuthFailed           = errors.New("authentication failed")
)

type tcpConnHandler struct {
	conn *net.TCPConn
}

func newTCPConnHandler(conn net.Conn) (*tcpConnHandler, error) {
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		conn.Close()
		return nil, errors.New("not a TCP connection")
	}

	// Set keep-alive for the connection
	if err := tcpConn.SetKeepAlive(true); err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("failed to set keep-alive: %w", err)
	}
	if err := tcpConn.SetKeepAlivePeriod(30 * time.Second); err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("failed to set keep-alive period: %w", err)
	}

	return &tcpConnHandler{conn: tcpConn}, nil
}

// Helper function to send SOCKS5 error responses
func sendSocks5Error(conn net.Conn, request []byte, errCode byte) error {
	if len(request) < 4 {
		// If we don't have the original request, fallback to IPv4 format
		response := []byte{
			socksVersion5, // SOCKS version
			errCode,       // Error code
			0,             // Reserved
			1,             // Address type (IPv4)
			0, 0, 0, 0,    // IPv4 address (0.0.0.0)
			0, 0, // Port (0)
		}
		_, err := conn.Write(response)
		return err
	}

	// Create response maintaining the address type and address from request
	response := make([]byte, 0, len(request))
	response = append(response, socksVersion5, errCode, 0) // SOCKS version, error code, reserved
	response = append(response, request[3:]...)            // Address type and address and port

	_, err := conn.Write(response)
	return err
}

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

		handler, err := newTCPConnHandler(conn)
		if err != nil {
			continue
		}

		p.wg.Add(1)
		p.activeConns.Store(handler.conn, struct{}{})
		go func() {
			defer p.wg.Done()
			defer p.activeConns.Delete(handler.conn)
			p.handleConnection(handler.conn)
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

func (p *Proxy) handleConnection(clientConn *net.TCPConn) {
	defer clientConn.Close()

	// Start connecting to the next proxy early in a separate goroutine
	type proxyResult struct {
		conn *net.TCPConn
		err  error
	}
	proxyConnChan := make(chan proxyResult, 1)
	go func() {
		conn, err := p.connectToNextProxy()
		proxyConnChan <- proxyResult{conn, err}
	}()

	// Handle client handshake while proxy connection is being established
	if err := p.handleClientHandshake(clientConn); err != nil {
		if errors.Is(err, errNoAcceptableAuth) {
			response := []byte{socksVersion5, socksNoAcceptableMethods}
			clientConn.Write(response)
		} else {
			sendSocks5Error(clientConn, nil, socksGeneralFailure)
		}
		// Clean up the proxy connection if it succeeded
		if result := <-proxyConnChan; result.conn != nil {
			result.conn.Close()
		}
		return
	}

	// Read the connection request
	request, err := readConnectionRequest(clientConn)
	if err != nil {
		sendSocks5Error(clientConn, nil, socksGeneralFailure)
		// Clean up the proxy connection if it succeeded
		if result := <-proxyConnChan; result.conn != nil {
			result.conn.Close()
		}
		return
	}

	// Wait for proxy connection result
	pResult := <-proxyConnChan
	if pResult.err != nil {
		var errCode byte = socksGeneralFailure
		if errors.Is(pResult.err, errNoAcceptableAuth) {
			errCode = socksConnectionRefused
		} else if strings.Contains(pResult.err.Error(), "no route to host") {
			errCode = socksHostUnreachable
		} else if strings.Contains(pResult.err.Error(), "network is unreachable") {
			errCode = socksNetworkUnreachable
		} else if errors.Is(err, errAuthFailed) {
			errCode = socksConnectionRefused
		}
		sendSocks5Error(clientConn, request, errCode)
		return
	}
	defer pResult.conn.Close()

	if err := p.forwardTraffic(clientConn, pResult.conn, request); err != nil {
		if !isConnectionClosedError(err) {
			sendSocks5Error(clientConn, request, socksGeneralFailure)
		}
		return
	}
}

func (p *Proxy) handleClientHandshake(conn *net.TCPConn) error {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return fmt.Errorf("failed to read handshake header: %w", err)
	}

	if header[0] != socksVersion5 {
		return errors.New("invalid SOCKS version")
	}

	methods := make([]byte, header[1])
	if _, err := io.ReadFull(conn, methods); err != nil {
		return fmt.Errorf("failed to read auth methods: %w", err)
	}

	// Check if the client supports no authentication
	hasNoAuth := false
	for _, method := range methods {
		if method == socksAuthNoneRequired {
			hasNoAuth = true
			break
		}
	}

	if !hasNoAuth {
		return errNoAcceptableAuth
	}

	response := []byte{socksVersion5, 0}
	if _, err := conn.Write(response); err != nil {
		return fmt.Errorf("failed to send auth response: %w", err)
	}

	return nil
}

func (p *Proxy) connectToNextProxy() (*net.TCPConn, error) {
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
	if _, err := tcpConn.Write([]byte{socksVersion5, 2, socksAuthNoneRequired, socksAuthUsernamePass}); err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("failed to send auth methods: %w", err)
	}

	// Read server's response
	response := make([]byte, 2)
	if _, err := io.ReadFull(tcpConn, response); err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("failed to read auth method response: %w", err)
	}

	if response[0] != socksVersion5 {
		tcpConn.Close()
		return nil, errors.New("invalid SOCKS version in response")
	}

	// Handle authentication based on server's choice
	switch response[1] {
	case socksAuthNoneRequired:
		// Continue without authentication
	case socksAuthUsernamePass:
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
			return nil, errAuthFailed
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

func (p *Proxy) forwardTraffic(clientConn, proxyConn *net.TCPConn, request []byte) error {
	if _, err := proxyConn.Write(request); err != nil {
		sendSocks5Error(clientConn, request, socksGeneralFailure)
		return fmt.Errorf("failed to forward request: %w", err)
	}

	response, err := readConnectionResponse(proxyConn)
	if err != nil {
		// Forward the exact error response from the next proxy if we got one
		if len(response) >= 2 {
			clientConn.Write(response)
		} else {
			sendSocks5Error(clientConn, request, socksGeneralFailure)
		}
		return err
	}

	if _, err := clientConn.Write(response); err != nil {
		return fmt.Errorf("failed to forward response: %w", err)
	}

	// Bidirectional copy with proper error handling
	errc := make(chan error, 2)
	go func() {
		_, err := io.Copy(proxyConn, clientConn)
		if err != nil && !isConnectionClosedError(err) {
			errc <- err
		} else {
			errc <- nil
		}
		proxyConn.CloseWrite()
	}()

	go func() {
		_, err := io.Copy(clientConn, proxyConn)
		if err != nil && !isConnectionClosedError(err) {
			errc <- err
		} else {
			errc <- nil
		}
		clientConn.CloseWrite()
	}()

	// Wait for both copies to complete
	for i := 0; i < 2; i++ {
		if err := <-errc; err != nil {
			return err
		}
	}

	return nil
}

func readConnectionRequest(clientConn net.Conn) ([]byte, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(clientConn, header); err != nil {
		return nil, fmt.Errorf("failed to read request header: %w", err)
	}

	if header[0] != socksVersion5 {
		return nil, errors.New("invalid SOCKS version in request")
	}

	if header[1] != socksCmdConnect {
		return nil, errUnsupportedCommand
	}

	// Read address type and address
	var addrLen int
	var domainLen []byte
	switch header[3] {
	case socksAddrIPv4:
		addrLen = net.IPv4len
	case socksAddrFQDN:
		domainLen = make([]byte, 1)
		if _, err := io.ReadFull(clientConn, domainLen); err != nil {
			return nil, fmt.Errorf("failed to read domain length: %w", err)
		}
		addrLen = int(domainLen[0])
	case socksAddrIPv6:
		addrLen = net.IPv6len
	default:
		return nil, errUnsupportedAddressType
	}

	// Read address and port
	addr := make([]byte, addrLen+2) // +2 for port
	if _, err := io.ReadFull(clientConn, addr); err != nil {
		return nil, fmt.Errorf("failed to read address and port: %w", err)
	}

	// Construct and forward the request to the next proxy
	if header[3] == socksAddrFQDN {
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
	case socksSucceeded:
		// Success
	case socksGeneralFailure:
		return nil, errGeneralFailure
	case socksNotAllowed:
		return nil, errConnectionNotAllowed
	case socksNetworkUnreachable:
		return nil, errNetworkUnreachable
	case socksHostUnreachable:
		return nil, errHostUnreachable
	case socksConnectionRefused:
		return nil, errConnectionRefused
	case socksTTLExpired:
		return nil, errTTLExpired
	case socksCommandNotSupported:
		return nil, errUnsupportedCommand
	case socksAddressNotSupported:
		return nil, errAddressNotSupported
	default:
		return nil, fmt.Errorf("unknown error code: %d", response[1])
	}

	addrLen := 0
	switch response[3] { // Address type
	case socksAddrIPv4:
		addrLen = net.IPv4len
	case socksAddrFQDN:
		domainLen := make([]byte, 1)
		if _, err := io.ReadFull(nextProxy, domainLen); err != nil {
			return nil, fmt.Errorf("error reading domain name length: %w", err)
		}
		addrLen = int(domainLen[0])
		response = append(response, domainLen...)
	case socksAddrIPv6:
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

func isConnectionClosedError(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, io.EOF) ||
		errors.Is(err, net.ErrClosed) ||
		strings.Contains(err.Error(), "broken pipe") ||
		strings.Contains(err.Error(), "connection reset by peer") ||
		strings.Contains(err.Error(), "use of closed network connection")
}
