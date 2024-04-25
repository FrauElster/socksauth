# SocksAuth

This project forwards your TCP connection through a SOCKS5 proxy, especially it can be used to forward it through a SOCKS5 proxy with authentication.

I tried to keep it minimal. It has 0 depencencies, 

### _Why?_ 

Because I needed a way to use a propietery SOCKS5 server with an automated browser, which does not allow to pass authentification to proxies.

### _As executable_

You can install it as executable

```sh
git clone https://https://github.com/FrauElster/SocksAuth.git && cd ./SocksAuth
cd src && go build -o ../socksauth ./server && cd .. && rm 
```

And run it with 

`./socksauth -remoteUser <username> -remotePass <password> [-remoteHost <host:port>] [-port <localport>]`

If the `remoteHost` is omitted a NordVPN will be used (because that was my usecase).

If the `port` is omitted, `1080` will be used.


### _As module_

This is pretty much just the `main.go` of the server

```go
package main

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"net"
	"os"
	"os/signal"

	"github.com/FrauElster/socksauth"
)

func main() {
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
```

or more minimal

```go
server := socksauth.NewServer(remoteHost, remoteUser, remotePass)
err := server.Start(context.Background())
if err != nil {
	log.Fatal(err)
}

```
