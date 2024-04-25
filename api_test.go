package socksauth_test

import (
	"context"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	_ "net/http/pprof"

	"github.com/FrauElster/socksauth"
	"github.com/chromedp/chromedp"
	"github.com/joho/godotenv"
)

type Config struct {
	User string
	Pass string
	Host string
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
	host := os.Getenv("SOCKS_HOST")

	return Config{User: user, Pass: pass, Host: host}
}

func startProxy(t *testing.T, ctx context.Context, config Config, opts ...socksauth.ServerOption) *socksauth.Server {
	onError := func(connId int64, conn net.Conn, err error) {
		t.Errorf("Error on connection %d: %v", connId, err)
	}

	if opts == nil {
		opts = make([]socksauth.ServerOption, 0)
	}
	opts = append(opts, socksauth.WithOnError(onError))

	server := socksauth.NewServer(config.Host, config.User, config.Pass, opts...)
	go func(t *testing.T) {
		err := server.Start(ctx)
		if err != nil {
			t.Fatalf("Error starting proxy: %v", err)
		}
	}(t)

	time.Sleep(50 * time.Millisecond) // wait for server to start and set addr
	return server
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

func TestWithHost(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	proxy := startProxy(t, ctx, loadConfig(t))
	proxyAddr := proxy.Addr

	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			err := request("https://google.com/", proxyAddr)
			if err != nil {
				t.Errorf("Error navigating to URL: %v", err)
			}
			wg.Done()
		}()
	}

	wg.Wait()
}

func TestWithNoHost(t *testing.T) {
	t.Skip("It seems like normal SOCKS5 servers wont authenticate")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	config := loadConfig(t)
	config.Host = ""
	proxy := startProxy(t, ctx, config)
	proxyAddr := proxy.Addr

	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			err := request("https://google.com/", proxyAddr)
			if err != nil {
				t.Errorf("Error navigating to URL: %v", err)
			}
			wg.Done()
		}()
	}

	wg.Wait()
}
