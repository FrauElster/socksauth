package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
)

var remoteHost, remoteUser, remotePass string

func main() {
	var port int
	flag.StringVar(&remoteHost, "remoteHost", "", "Remote host address")
	flag.StringVar(&remoteUser, "remoteUser", "", "Remote username")
	flag.StringVar(&remotePass, "remotePass", "", "Remote password")
	flag.IntVar(&port, "port", 1080, "Port to listen on")
	flag.Parse()

	// Validate the input
	if remoteHost == "" || remoteUser == "" || remotePass == "" {
		log.Fatal("Remote host, user, and password must be provided")
	}

	socks5Server(port)
}

func socks5Server(port int) {
	// Listen on TCP port 1080 on all interfaces.
	l, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		fmt.Println(err)
		return
	}
	defer l.Close()

	fmt.Println("SOCKS5 server is listening on ", l.Addr().String())

	for {
		// Wait for a connection.
		conn, err := l.Accept()
		if err != nil {
			fmt.Println(err)
			continue
		}

		// Handle the connection in a new goroutine.
		// The loop then returns to accepting, so that
		// multiple connections may be served concurrently.
		go handleConnection(conn)
	}
}

func handleConnection(clientConn net.Conn) {
	defer clientConn.Close()

	// Greet the client
	if err := greetClient(clientConn); err != nil {
		fmt.Println("Error greeting client:", err)
		return
	}

	// Connect to the remote SOCKS5 server
	remoteConn, err := net.Dial("tcp", remoteHost)
	if err != nil {
		fmt.Println("Error connecting to remote SOCKS5 server:", err)
		return
	}
	defer remoteConn.Close()

	// Authenticate with the remote SOCKS5 server
	if err := authenticateRemoteSocks(remoteConn, remoteUser, remotePass); err != nil {
		fmt.Println("Authentication failed:", err)
		return
	}

	// Forward the client's request to the remote SOCKS5 server
	if err := sendRemoteRequest(clientConn, remoteConn); err != nil {
		fmt.Println("Failed to send request to remote SOCKS5 server:", err)
		return
	}

	// Relay data between the client and the remote SOCKS5 server
	go func() { io.Copy(remoteConn, clientConn) }()
	io.Copy(clientConn, remoteConn)
}

func greetClient(clientConn net.Conn) error {
	// https://datatracker.ietf.org/doc/html/rfc1928#section-3
	header := make([]byte, 2)
	if _, err := io.ReadFull(clientConn, header); err != nil {
		return fmt.Errorf("error reading header: %w", err)
	}

	socksVersion := header[0]
	if socksVersion != 0x05 {
		return fmt.Errorf("unsupported SOCKS version: %d", socksVersion)
	}

	numMethods := int(header[1])
	methods := make([]byte, numMethods)
	if _, err := io.ReadFull(clientConn, methods); err != nil {
		return fmt.Errorf("error reading methods: %w", err)
	}

	if !Contains(methods, 0x00) { // 0x00: No authentication
		return fmt.Errorf("no supported authentication methods")
	}

	clientConn.Write([]byte{0x05, 0x00}) // SOCKS5, No Authentication
	return nil
}

func authenticateRemoteSocks(conn net.Conn, username, password string) error {
	// Send the authentication methods supported by the client https://datatracker.ietf.org/doc/html/rfc1928#section-3
	// 0x05: SOCKS5
	// 0x01: number of authentication methods supported
	// 0x02: username/password authentication
	_, err := conn.Write([]byte{0x05, 0x01, 0x02})
	if err != nil {
		return fmt.Errorf("error sending authentication methods: %w", err)
	}

	// Read the server's choice of authentication method
	response := make([]byte, 2)
	if _, err := io.ReadFull(conn, response); err != nil {
		return fmt.Errorf("error reading authentication method selection: %w", err)
	}

	// Check if the server selected username/password authentication
	if response[1] != 0x02 {
		return fmt.Errorf("server did not select username/password authentication, selected method: %d", response[1])
	}

	// Then, send the username and password
	ulen, plen := len(username), len(password)
	upauth := make([]byte, 3+ulen+plen)
	upauth[0] = 0x01 // version 1 of the subnegotiation
	upauth[1] = byte(ulen)
	copy(upauth[2:], username)
	upauth[2+ulen] = byte(plen)
	copy(upauth[3+ulen:], password)

	_, err = conn.Write(upauth)
	if err != nil {
		return fmt.Errorf("error sending username/password: %w", err)
	}

	// Read the server's response
	response = make([]byte, 2)
	if _, err := io.ReadFull(conn, response); err != nil {
		return fmt.Errorf("error reading authentication response: %w", err)
	}

	// Check the server's response
	if response[1] != 0x00 {
		return fmt.Errorf("authentication failed")
	}

	return nil
}

func sendRemoteRequest(clientConn, remoteConn net.Conn) error {
	request, err := readSocks5Request(clientConn)
	if err != nil {
		return fmt.Errorf("error reading request from client: %w", err)
	}

	_, err = remoteConn.Write(request)
	if err != nil {
		return fmt.Errorf("error forwarding request to remote server: %w", err)
	}

	response, err := readSocks5Response(remoteConn)
	if err != nil {
		return fmt.Errorf("error reading response from remote server: %w", err)
	}

	_, err = clientConn.Write(response)
	if err != nil {
		return fmt.Errorf("error forwarding response to client: %w", err)
	}

	return nil
}

func readSocks5Request(conn net.Conn) ([]byte, error) {
	// Read the SOCKS request from the client https://datatracker.ietf.org/doc/html/rfc1928#section-5
	// The request is at least 5 bytes: VER, CMD, RSV, ATYP, and the first byte of the DST.ADDR
	requestHeader := make([]byte, 5)
	if _, err := io.ReadFull(conn, requestHeader); err != nil {
		return nil, fmt.Errorf("error reading request header: %w", err)
	}

	// Determine the length of the remaining part of the request based on the address type
	addrLen := 0
	switch requestHeader[3] { // ATYP, the address type
	case 0x01: // IPv4 address
		addrLen = net.IPv4len + 2 // 4 bytes for IPv4 address, 2 for port
	case 0x03: // Domain name
		lengthByte := make([]byte, 1)
		if _, err := io.ReadFull(conn, lengthByte); err != nil {
			return nil, fmt.Errorf("error reading domain name length: %w", err)
		}
		addrLen = int(lengthByte[0]) + 2 // Domain name length + 2 for port
	case 0x04: // IPv6 address
		addrLen = net.IPv6len + 2 // 16 bytes for IPv6 address, 2 for port
	default:
		return nil, fmt.Errorf("unknown address type: %d", requestHeader[3])
	}

	// Read the rest of the request
	requestRest := make([]byte, addrLen-1) // -1 since we already read the first byte to determine the address type
	if _, err := io.ReadFull(conn, requestRest); err != nil {
		return nil, fmt.Errorf("error reading the rest of the request: %w", err)
	}

	// Combine the header and the rest of the request
	fullRequest := append(requestHeader, requestRest...)
	return fullRequest, nil
}

func readSocks5Response(conn net.Conn) ([]byte, error) {
	// Read the SOCKS response from the remote server
	// https://datatracker.ietf.org/doc/html/rfc1928#section-6
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, fmt.Errorf("error reading response header: %w", err)
	}

	reply := header[1]
	switch reply {
	case 0x00: // Succeeded
	case 0x01: // General SOCKS server failure
		return nil, fmt.Errorf("general SOCKS server failure")
	case 0x02: // Connection not allowed by ruleset
		return nil, fmt.Errorf("connection not allowed by ruleset")
	case 0x03: // Network unreachable
		return nil, fmt.Errorf("network unreachable")
	case 0x04: // Host unreachable
		return nil, fmt.Errorf("host unreachable")
	case 0x05: // Connection refused
		return nil, fmt.Errorf("connection refused")
	case 0x06: // TTL expired
		return nil, fmt.Errorf("TTL expired")
	case 0x07: // Command not supported
		return nil, fmt.Errorf("command not supported")
	case 0x08: // Address type not supported
		return nil, fmt.Errorf("address type not supported")
	default:
		return nil, fmt.Errorf("unknown reply: %d", reply)
	}

	addrLen := 0
	switch header[3] { // Address type
	case 0x01: // IPv4
		addrLen = net.IPv4len
	case 0x03: // Domain name
		lengthByte := make([]byte, 1)
		if _, err := io.ReadFull(conn, lengthByte); err != nil {
			return nil, fmt.Errorf("error reading domain name length: %w", err)
		}
		addrLen = int(lengthByte[0])
	case 0x04: // IPv6
		addrLen = net.IPv6len
	default:
		return nil, fmt.Errorf("unknown address type: %d", header[3])
	}

	requestRest := make([]byte, addrLen+2) // +2 for port
	if _, err := io.ReadFull(conn, requestRest); err != nil {
		return nil, fmt.Errorf("error reading the rest of the response: %w", err)
	}

	fullResponse := append(header, requestRest...)
	return fullResponse, nil
}

func Contains[T comparable](slice []T, item T) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
