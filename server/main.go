package main

import (
	"FrauElster/SocksAuth/socksauth"
	"context"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"net"
	"os"
	"os/signal"
)

func main() {
	var remoteHost, remoteUser, remotePass string
	var port int
	flag.StringVar(&remoteHost, "remoteHost", "", "Remote host address")
	flag.StringVar(&remoteUser, "remoteUser", "", "Remote username")
	flag.StringVar(&remotePass, "remotePass", "", "Remote password")
	flag.IntVar(&port, "port", 1080, "Port to listen on")
	flag.Parse()

	// Validate the input
	if remoteUser == "" || remotePass == "" {
		log.Fatal("user and password must be provided")
	}

	// build the server
	onError := func(connId int64, conn net.Conn, err error) { slog.Error("Error", "connId", connId, "err", err) }
	onConnect := func(connId int64, conn net.Conn) {
		slog.Debug("Connected", "connId", connId, "addr", conn.RemoteAddr())
	}
	onDisconnect := func(connId int64, conn net.Conn) {
		slog.Debug("Disconnected", "connId", connId, "addr", conn.RemoteAddr())
	}
	server := socksauth.NewServer(remoteHost, remoteUser, remotePass,
		socksauth.WithAddr(fmt.Sprintf(":%d", port)), socksauth.WithOnConnect(onConnect), socksauth.WithOnDisconnect(onDisconnect), socksauth.WithOnError(onError))

	// Start the server
	runCtx, cancel := context.WithCancel(context.Background())
	err := server.Start(runCtx)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("SOCKS5 server is listening on ", server.Addr)

	// wait for ctrl+c
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt)
	<-sigChan
	fmt.Println("Shutting down...")
	cancel()
}
