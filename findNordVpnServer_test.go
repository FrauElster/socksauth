package socksauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/chromedp/chromedp"
	"github.com/joho/godotenv"
)

type Config struct {
	User string
	Pass string
}

func loadConfig(t *testing.T) Config {
	godotenv.Load()
	user := os.Getenv("SOCKS_USER")
	if user == "" {
		t.Fatal("SOCKS_USER not set")
	}
	pass := os.Getenv("SOCKS_PASS")
	if pass == "" {
		t.Fatal("SOCKS_PASS not set")
	}
	return Config{User: user, Pass: pass}
}

func TestFindNordVpnServers(t *testing.T) {
	servers, err := findNordVpnServers(context.Background())
	if err != nil {
		t.Error(err)
	}
	if len(servers) == 0 {
		t.Error("No servers found")
	}
}

func startProxy(ctx context.Context, user, password string, opts ...ServerOption) string {
	server := NewServer("", user, password, opts...)
	go server.Start(ctx)

	time.Sleep(500 * time.Millisecond) // wait for server to start and set addr
	return server.Addr
}

func request(url, proxy string) error {
	executorOpts := chromedp.DefaultExecAllocatorOptions[:]
	executorOpts = append(
		executorOpts,
		chromedp.Flag("headless", "new"),
		chromedp.DisableGPU,
		chromedp.NoSandbox,
		chromedp.Flag("incognito", true),
		chromedp.Flag("ignore-certificate-errors", true),
		chromedp.ProxyServer(proxy),
		chromedp.UserAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36"),
	)

	ctx, _ := chromedp.NewExecAllocator(context.Background(), executorOpts...)
	ctx, cancel := chromedp.NewContext(ctx)
	defer cancel()

	return chromedp.Run(ctx, chromedp.Tasks{chromedp.Navigate(url)})
}

func TestOfficialServers(t *testing.T) {
	servers := []string{
		"amsterdam.nl.socks.nordhold.net",
		"atlanta.us.socks.nordhold.net",
		"dallas.us.socks.nordhold.net",
		"dublin.ie.socks.nordhold.net",
		"ie.socks.nordhold.net",
		"los-angeles.us.socks.nordhold.net",
		"nl.socks.nordhold.net",
		"se.socks.nordhold.net",
		"stockholm.se.socks.nordhold.net",
		"us.socks.nordhold.net",
	}

	goodServers := make([]string, 0)
	badServers := make([]string, 0)

	config := loadConfig(t)
	serverIdx := 0
	ctx, stop := context.WithCancel(context.Background())
	proxyAddr := startProxy(ctx, config.User, config.Pass,
		WithServerFinder(func(ctx context.Context) (string, error) {
			if serverIdx >= len(servers) {
				return "", fmt.Errorf("no more servers")
			}
			server := servers[serverIdx]
			serverIdx++
			return server, nil
		}),
		WithOnError(func(id int64, conn net.Conn, err SocksError) {
			if serverIdx-1 >= len(servers) {
				return
			}
			if !contains(badServers, err.ProxyServer().Host) {
				badServers = append(badServers, err.ProxyServer().Host)
			}
		}),
	)

	for idx := range servers {
		err := request("https://akf-shop.de/", proxyAddr)
		if err == nil {
			fmt.Printf("Server %s is good\n", servers[idx])
			goodServers = append(goodServers, servers[idx])
		} else {
			fmt.Printf("Server %s is bad: %s\n", servers[idx], err)
		}
	}

	stop()
	println("Good servers: ", strings.Join(goodServers, ", "))
	println("Bad servers: ", strings.Join(badServers, ", "))
	if len(badServers) > 0 {
		t.Fail() // so the prints will appear
	}
}

func TestFilterNordVpnServers(t *testing.T) {
	servers, err := findNordVpnServers(context.Background())
	if err != nil {
		t.Error(err)
	}
	if len(servers) == 0 {
		t.Error("No servers found")
	}

	config := loadConfig(t)

	ctx, stopProxy := context.WithCancel(context.Background())
	serverIdx := 0
	proxyAddr := startProxy(ctx, config.User, config.Pass,
		WithServerFinder(func(ctx context.Context) (string, error) {
			if serverIdx >= len(servers) {
				return "", fmt.Errorf("no more servers")
			}
			server := servers[serverIdx]
			serverIdx++
			return server.Hostname, nil
		}),
		WithOnError(func(id int64, conn net.Conn, err SocksError) {
			if serverIdx-1 < len(servers) {
				fmt.Printf("%s: %s\n", servers[serverIdx-1].Hostname, err)
			}
		}),
	)

	badServers := make([]nordServer, 0)
	goodServers := make([]nordServer, 0)
	for idx := range servers {
		err := request("https://google.com/", proxyAddr)
		if err == nil {
			goodServers = append(goodServers, servers[idx])
		} else {
			badServers = append(badServers, servers[idx])
		}
	}
	stopProxy()

	fmt.Printf("Found %d good servers\n", len(goodServers))
	goodData, err := json.MarshalIndent(goodServers, "", "  ")
	if err != nil {
		t.Error(err)
	}
	err = os.WriteFile("good_servers.json", goodData, 0644)
	if err != nil {
		t.Error(err)
	}

	fmt.Printf("Found %d bad servers\n", len(badServers))
	badData, err := json.MarshalIndent(badServers, "", "  ")
	if err != nil {
		t.Error(err)
	}
	err = os.WriteFile("bad_servers.json", badData, 0644)
	if err != nil {
		t.Error(err)
	}

	if len(badServers) > 0 {
		hostnames := make([]string, 0)
		for _, server := range badServers {
			hostnames = append(hostnames, server.Hostname)
		}
		println("Bad servers: ", strings.Join(hostnames, ", "))
		t.Fail() // so the prints will appear
	}
}
