package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/FrauElster/socksauth/v2"
)

func main() {
	// Command line flags
	remoteUser := flag.String("remoteUser", "", "Username for remote SOCKS server")
	remotePass := flag.String("remotePass", "", "Password for remote SOCKS server")
	remoteHost := flag.String("remoteHost", "", "Remote SOCKS server address (host:port)")
	localPort := flag.Int("port", 1080, "Local port to listen on")

	// Parse flags
	flag.Parse()

	// Validate required flags
	if *remoteUser == "" || *remotePass == "" || *remoteHost == "" {
		fmt.Println("Usage: socksauth -remoteUser <username> -remotePass <password> -remoteHost <host:port> [-port <localport>]")
		flag.PrintDefaults()
		os.Exit(1)
	}

	// Create proxy instance
	proxy, err := socksauth.NewProxy(*remoteUser, *remotePass, *remoteHost)
	if err != nil {
		log.Fatalf("Failed to create proxy: %v", err)
	}

	// Set up signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Start proxy in a goroutine
	go func() {
		log.Printf("Starting SOCKS proxy on port %d", *localPort)
		if err := proxy.Start(*localPort); err != nil {
			if err.Error() != "use of closed network connection" {
				log.Printf("Proxy error: %v", err)
			}
		}
	}()

	// Wait for interrupt signal
	<-sigChan
	log.Println("Shutting down proxy...")

	// Graceful shutdown with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := proxy.Shutdown(ctx); err != nil {
		log.Printf("Shutdown error: %v", err)
		os.Exit(1)
	}

	log.Println("Proxy shutdown complete")
}
