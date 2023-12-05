package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync/atomic"
	"time"
)

const (
	SOCKS_VERSION         = 0x05
	NO_ACCEPTABLE_METHODS = 0xff

	NO_AUTHENTICATION      = 0x00
	USERNAME_PASSWORD_AUTH = 0x02
	CONNECT                = 0x01

	STATUS_OK                   = 0x00
	GENERAL_SOCKS_FAILURE       = 0x01
	CONN_NOT_ALLOWED_BY_RULESET = 0x02
	NETWORK_UNREACHABLE         = 0x03
	HOST_UNREACHABLE            = 0x04
	CONN_REFUSED                = 0x05
	TTL_EXPIRED                 = 0x06
	COMMAND_NOT_SUPPORTED       = 0x07
	ADDRESS_TYPE_NOT_SUPPORTED  = 0x08

	IP_V4       = 0x01
	DOMAIN_NAME = 0x03
	IP_V6       = 0x04
)

var remoteHost, remoteUser, remotePass string
var debug bool

func main() {
	var port int
	flag.StringVar(&remoteHost, "remoteHost", "", "Remote host address")
	flag.StringVar(&remoteUser, "remoteUser", "", "Remote username")
	flag.StringVar(&remotePass, "remotePass", "", "Remote password")
	flag.IntVar(&port, "port", 1080, "Port to listen on")
	flag.BoolVar(&debug, "debug", false, "Enable debug logging")
	flag.Parse()

	// Validate the input
	if remoteHost == "" || remoteUser == "" || remotePass == "" {
		log.Fatal("Remote host, user, and password must be provided")
	}

	socks5Server(port)
}

var connId atomic.Int64
var openConnCount atomic.Int32

func socks5Server(port int) {
	l, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
		return
	}
	defer l.Close()
	fmt.Println("SOCKS5 server is listening on ", l.Addr().String())

	if debug {
		go func() {
			for {
				fmt.Printf("Open connections: %d\n", openConnCount.Load())
				time.Sleep(1 * time.Second)
			}
		}()
	}

	for {
		// Wait for a connection.
		conn, err := l.Accept()
		if err != nil {
			fmt.Println(err)
			continue
		}

		go handleConnection(conn)
	}
}

func handleConnection(clientConn net.Conn) {
	id := connId.Add(1)
	openConnCount.Add(1)
	defer openConnCount.Add(-1)

	defer clientConn.Close()

	// Greet the client
	if err := greetClient(clientConn); err != nil {
		fmt.Printf("(%d) Error greeting client: %s\n", id, err)
		return
	}

	// Connect to the remote SOCKS5 server
	remoteConn, err := net.Dial("tcp", remoteHost)
	if err != nil {
		fmt.Printf("(%d) Error connecting to remote SOCKS5 server: %s\n", id, err)
		return
	}
	defer remoteConn.Close()

	// Authenticate with the remote SOCKS5 server
	if err := authenticateRemoteSocks(remoteConn, remoteUser, remotePass); err != nil {
		fmt.Printf("(%d) Authentication failed: %s\n", id, err)
		return
	}

	// Forward the client's request to the remote SOCKS5 server
	if err := sendRemoteRequest(clientConn, remoteConn); err != nil {
		fmt.Printf("(%d) Failed to send request to remote SOCKS5 server: %s\n", id, err)
		return
	}

	// Relay data between the client and the remote SOCKS5 server
	if err := syncConns(clientConn, remoteConn, id); err != nil {
		fmt.Println("Error during data relay:", err)
		return
	}
	// go func() { io.Copy(remoteConn, clientConn) }()
	// io.Copy(clientConn, remoteConn)
}

func greetClient(clientConn net.Conn) error {
	// https://datatracker.ietf.org/doc/html/rfc1928#section-3
	header := make([]byte, 2)
	if _, err := io.ReadFull(clientConn, header); err != nil {
		return fmt.Errorf("error reading header: %w", err)
	}

	socksVersion := header[0]
	if socksVersion != SOCKS_VERSION {
		return fmt.Errorf("unsupported SOCKS version: %d", socksVersion)
	}

	numMethods := int(header[1])
	methods := make([]byte, numMethods)
	if _, err := io.ReadFull(clientConn, methods); err != nil {
		return fmt.Errorf("error reading methods: %w", err)
	}

	if !Contains(methods, NO_AUTHENTICATION) {
		clientConn.Write([]byte{SOCKS_VERSION, NO_ACCEPTABLE_METHODS})
		return fmt.Errorf("no supported authentication methods")
	}

	clientConn.Write([]byte{SOCKS_VERSION, NO_AUTHENTICATION})
	return nil
}

func authenticateRemoteSocks(conn net.Conn, username, password string) error {
	// Send the authentication methods supported by the client https://datatracker.ietf.org/doc/html/rfc1928#section-3
	// 0x05: SOCKS5
	// 0x01: number of authentication methods supported
	// 0x02: username/password authentication
	_, err := conn.Write([]byte{SOCKS_VERSION, 0x01, USERNAME_PASSWORD_AUTH})
	if err != nil {
		return fmt.Errorf("error sending authentication methods: %w", err)
	}

	// Read the server's choice of authentication method
	response := make([]byte, 2)
	if _, err := io.ReadFull(conn, response); err != nil {
		return fmt.Errorf("error reading authentication method selection: %w", err)
	}

	// Check if the server selected username/password authentication
	if response[1] != USERNAME_PASSWORD_AUTH {
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
	response[1] = 0xff // Set the response to an invalid value
	if _, err := io.ReadFull(conn, response); err != nil {
		return fmt.Errorf("error reading authentication response: %w", err)
	}

	// Check the server's response
	if response[1] != STATUS_OK {
		return fmt.Errorf("authentication failed")
	}

	return nil
}

func syncConns(clientConn, remoteConn net.Conn, connId int64) error {
	done := make(chan error, 1)

	// Relay data from client to remote
	go func() {
		count, err := io.Copy(remoteConn, clientConn)
		if err != nil {
			done <- fmt.Errorf("(%d) error copying data from client to remote: %w", connId, err)
			return
		}

		if debug {
			fmt.Printf("(%d) client -> remote closed (copied %d bytes)\n", connId, count)
		}
		done <- nil
	}()

	// Relay data from remote to client
	go func() {
		count, err := io.Copy(clientConn, remoteConn)
		if err != nil {
			done <- fmt.Errorf("(%d) error copying data from remote to client: %w", connId, err)
			return
		}

		if debug {
			fmt.Printf("(%d) remote -> client closed (copied %d bytes)\n", connId, count)
		}
		done <- nil
	}()

	// Wait for either goroutine to finish
	err := <-done
	clientConn.Close()
	remoteConn.Close()

	return err
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
	// Read the SOCKS request from the client https://datatracker.ietf.org/doc/html/rfc1928#section-4
	// Read the first 4 Bytes of the request, the fourth byte determines the length of the rest of the request
	requestHeader := make([]byte, 4)
	if _, err := io.ReadFull(conn, requestHeader); err != nil {
		return nil, fmt.Errorf("error reading request header: %w", err)
	}

	version := requestHeader[0]
	if version != SOCKS_VERSION {
		return nil, fmt.Errorf("unsupported SOCKS version: %d", version)
	}

	cmd := requestHeader[1]
	if cmd != CONNECT {
		conn.Write([]byte{SOCKS_VERSION, COMMAND_NOT_SUPPORTED})
		return nil, fmt.Errorf("unsupported command: %d", cmd)
	}

	// Determine the length of the remaining part of the request based on the address type
	addrLen := 0
	switch requestHeader[3] { // ATYP, the address type
	case IP_V4:
		addrLen = net.IPv4len
	case DOMAIN_NAME:
		lengthByte := make([]byte, 1)
		if _, err := io.ReadFull(conn, lengthByte); err != nil {
			return nil, fmt.Errorf("error reading domain name length: %w", err)
		}
		requestHeader = append(requestHeader, lengthByte...)
		addrLen = int(lengthByte[0])
	case IP_V6:
		addrLen = net.IPv6len
	default:
		conn.Write([]byte{SOCKS_VERSION, ADDRESS_TYPE_NOT_SUPPORTED})
		return nil, fmt.Errorf("unknown address type: %d", requestHeader[3])
	}

	// Read the rest of the request
	requestRest := make([]byte, addrLen+2) // +2 for port number
	if _, err := io.ReadFull(conn, requestRest); err != nil {
		conn.Write([]byte{SOCKS_VERSION, GENERAL_SOCKS_FAILURE})
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
		conn.Write([]byte{SOCKS_VERSION, GENERAL_SOCKS_FAILURE})
		return nil, fmt.Errorf("error reading response header: %w", err)
	}

	version := header[0]
	if version != SOCKS_VERSION {
		conn.Write([]byte{SOCKS_VERSION, GENERAL_SOCKS_FAILURE})
		return nil, fmt.Errorf("unsupported SOCKS version: %d", version)
	}

	reply := header[1]
	switch reply {
	case STATUS_OK:
	case GENERAL_SOCKS_FAILURE:
		conn.Write([]byte{SOCKS_VERSION, header[1]})
		return nil, fmt.Errorf("general SOCKS server failure")
	case CONN_NOT_ALLOWED_BY_RULESET:
		conn.Write([]byte{SOCKS_VERSION, header[1]})
		return nil, fmt.Errorf("connection not allowed by ruleset")
	case NETWORK_UNREACHABLE:
		conn.Write([]byte{SOCKS_VERSION, header[1]})
		return nil, fmt.Errorf("network unreachable")
	case HOST_UNREACHABLE:
		conn.Write([]byte{SOCKS_VERSION, header[1]})
		return nil, fmt.Errorf("host unreachable")
	case CONN_REFUSED:
		conn.Write([]byte{SOCKS_VERSION, header[1]})
		return nil, fmt.Errorf("connection refused")
	case TTL_EXPIRED:
		conn.Write([]byte{SOCKS_VERSION, header[1]})
		return nil, fmt.Errorf("TTL expired")
	case COMMAND_NOT_SUPPORTED:
		conn.Write([]byte{SOCKS_VERSION, header[1]})
		return nil, fmt.Errorf("command not supported")
	case ADDRESS_TYPE_NOT_SUPPORTED:
		conn.Write([]byte{SOCKS_VERSION, header[1]})
		return nil, fmt.Errorf("address type not supported")
	default:
		conn.Write([]byte{SOCKS_VERSION, GENERAL_SOCKS_FAILURE})
		return nil, fmt.Errorf("unknown reply: %d", reply)
	}

	addrLen := 0
	switch header[3] { // Address type
	case IP_V4:
		addrLen = net.IPv4len
	case DOMAIN_NAME:
		lengthByte := make([]byte, 1)
		if _, err := io.ReadFull(conn, lengthByte); err != nil {
			return nil, fmt.Errorf("error reading domain name length: %w", err)
		}
		addrLen = int(lengthByte[0])
	case IP_V6:
		addrLen = net.IPv6len
	default:
		conn.Write([]byte{SOCKS_VERSION, ADDRESS_TYPE_NOT_SUPPORTED})
		return nil, fmt.Errorf("unknown address type: %d", header[3])
	}

	requestRest := make([]byte, addrLen+2) // +2 for port
	if _, err := io.ReadFull(conn, requestRest); err != nil {
		conn.Write([]byte{SOCKS_VERSION, GENERAL_SOCKS_FAILURE})
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
