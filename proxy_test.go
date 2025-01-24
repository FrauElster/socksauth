package socksauth

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/joho/godotenv"
)

func mustStartProxy(t *testing.T) (*Proxy, int) {
	t.Helper()

	if err := godotenv.Load(); err != nil {
		t.Fatalf("Failed to load .env file: %v", err)
	}

	proxy, err := NewProxy(
		os.Getenv("SOCKS_USER"),
		os.Getenv("SOCKS_PASSWORD"),
		os.Getenv("SOCKS_HOST"),
	)
	proxy.UseOld = true
	if err != nil {
		t.Fatalf("Failed to create proxy: %v", err)
	}

	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	proxyPort := listener.Addr().(*net.TCPAddr).Port
	listener.Close()

	go func() {
		if err := proxy.Start(proxyPort); err != nil {
			t.Errorf("Proxy failed: %v", err)
		}
	}()

	time.Sleep(time.Second)
	return proxy, proxyPort
}

func TestProxy(t *testing.T) {
	t.Run("Basic Connectivity", func(t *testing.T) {
		_, proxyPort := mustStartProxy(t)

		t.Run("HTTPS Connection", func(t *testing.T) {
			testProxyConnection(t, proxyPort, "google.com", 443, false)
		})

		t.Run("HTTP Connection", func(t *testing.T) {
			testProxyConnection(t, proxyPort, "google.com", 80, false)
		})

		t.Run("Invalid Port", func(t *testing.T) {
			testProxyConnection(t, proxyPort, "google.com", 12345, true)
		})
	})

	t.Run("Concurrent Connections", func(t *testing.T) {
		testConcurrentConnections(t)
	})
}

// testProxyConnection handles a single proxy connection test
func testProxyConnection(t *testing.T, proxyPort int, targetHost string, targetPort int, expectError bool) {
	conn, err := net.Dial("tcp", fmt.Sprintf("localhost:%d", proxyPort))
	if err != nil {
		t.Fatalf("Failed to connect to proxy: %v", err)
	}
	defer conn.Close()

	if err := socks5Handshake(t, conn); err != nil {
		t.Fatalf("Handshake failed: %v", err)
	}

	if err := sendConnectRequest(t, conn, targetHost, targetPort); err != nil {
		if !expectError {
			t.Fatalf("Connect request failed: %v", err)
		}
		return
	}

	if err := readConnectResponse(t, conn); err != nil {
		if !expectError {
			t.Fatalf("Connect response failed: %v", err)
		}
		return
	}

	if expectError {
		t.Fatal("Expected error but got success")
	}

	if targetPort == 80 || targetPort == 443 {
		if err := testHTTPRequest(t, proxyPort, targetHost, targetPort); err != nil {
			t.Fatalf("HTTP request failed: %v", err)
		}
	}
}

func testConcurrentConnections(t *testing.T) {
	t.Helper()
	_, proxyPort := mustStartProxy(t)

	t.Run("10 Simultaneous Connections", func(t *testing.T) {
		errCh := make(chan error, 10)
		var wg sync.WaitGroup
		wg.Add(10)
		for i := 0; i < 10; i++ {
			go func() {
				errCh <- testHTTPRequest(t, proxyPort, "google.com", 443)
				wg.Done()
			}()
		}
		wg.Wait()
		close(errCh)
		for i := 0; i < 10; i++ {
			if err := <-errCh; err != nil {
				t.Errorf("Connection %d failed: %v", i, err)
			}
		}
	})
}

// Helper functions

func socks5Handshake(t *testing.T, conn net.Conn) error {
	t.Helper()

	// Send version and auth method
	if _, err := conn.Write([]byte{5, 1, 0}); err != nil {
		return err
	}

	// Read response
	response := make([]byte, 2)
	if _, err := io.ReadFull(conn, response); err != nil {
		return err
	}

	if response[0] != 5 || response[1] != 0 {
		return fmt.Errorf("unexpected handshake response: %v", response)
	}

	return nil
}

func sendConnectRequest(t *testing.T, conn net.Conn, host string, port int) error {
	t.Helper()

	// Build connect request
	request := []byte{5, 1, 0, 3, byte(len(host))}
	request = append(request, []byte(host)...)
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(port))
	request = append(request, portBytes...)

	_, err := conn.Write(request)
	return err
}

func readConnectResponse(t *testing.T, conn net.Conn) error {
	t.Helper()

	response := make([]byte, 4)
	if _, err := io.ReadFull(conn, response); err != nil {
		return err
	}

	if response[1] != 0 {
		return fmt.Errorf("connect failed with code: %d", response[1])
	}

	// Read bound address and port (we don't use these)
	switch response[3] {
	case 1: // IPv4
		addr := make([]byte, 6) // 4 for IPv4 + 2 for port
		if _, err := io.ReadFull(conn, addr); err != nil {
			return err
		}
		return nil
	case 3: // Domain
		lenByte := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenByte); err != nil {
			return err
		}
		addr := make([]byte, int(lenByte[0])+2) // domain length + 2 for port
		if _, err := io.ReadFull(conn, addr); err != nil {
			return err
		}
		return nil
	case 4: // IPv6
		addr := make([]byte, 18) // 16 for IPv6 + 2 for port
		if _, err := io.ReadFull(conn, addr); err != nil {
			return err
		}
		return nil
	default:
		return fmt.Errorf("unknown address type: %d", response[3])
	}
}

func testHTTPRequest(t *testing.T, proxyPort int, targetHost string, targetPort int) error {
	t.Helper()

	// Create HTTP client with SOCKS5 proxy
	proxyURL, err := url.Parse(fmt.Sprintf("socks5://localhost:%d", proxyPort))
	if err != nil {
		return fmt.Errorf("failed to parse proxy URL: %v", err)
	}

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
	}

	// Make HTTP request
	scheme := "https"
	if targetPort == 80 {
		scheme = "http"
	}
	resp, err := client.Get(fmt.Sprintf("%s://%s", scheme, targetHost))
	if err != nil {
		return fmt.Errorf("HTTP request failed: %v", err)
	}
	defer resp.Body.Close()

	// Read response body
	_, err = io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %v", err)
	}

	return nil
}
