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

func TestFilterNordVpnServers(t *testing.T) {
	servers, err := findNordVpnServers(context.Background())
	if err != nil {
		t.Error(err)
	}
	if len(servers) == 0 {
		t.Error("No servers found")
	}

	config := loadConfig(t)
	startProxy := func(ctx context.Context, opts ...ServerOption) string {
		server := NewServer("", config.User, config.Pass, opts...)
		go func(t *testing.T) {
			err := server.Start(ctx)
			if err != nil {
				t.Fatalf("Error starting proxy: %v", err)
			}
		}(t)

		time.Sleep(50 * time.Millisecond) // wait for server to start and set addr
		return server.Addr
	}

	request := func(url, proxy string) error {
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

	ctx, stopProxy := context.WithCancel(context.Background())
	serverIdx := 0
	proxyAddr := startProxy(ctx,
		WithServerFinder(func(ctx context.Context) (string, error) {
			if serverIdx >= len(servers) {
				return "", fmt.Errorf("no more servers")
			}
			server := servers[serverIdx]
			serverIdx++
			return server.Hostname, nil
		}),
		WithOnError(func(id int64, conn net.Conn, err error) {
			if serverIdx < len(servers) {
				fmt.Printf("%s: %s\n", servers[serverIdx].Hostname, err)
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
