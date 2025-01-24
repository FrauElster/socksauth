# SocksAuth

This project forwards your TCP connection through a SOCKS5 proxy, especially it can be used to forward it through a SOCKS5 proxy with authentication.

I tried to keep it minimal. It has 0 depencencies,

### _Why?_

Because I needed a way to use a propietery SOCKS5 server with an automated browser, which does not allow to pass authentification to proxies.

### _As executable_

You can install it as executable

```sh
git clone https://https://github.com/FrauElster/SocksAuth.git && cd ./SocksAuth
go build -o socksauth ./cmd/socksauth
```

And run it with

`./socksauth -remoteUser <username> -remotePass <password> -remoteHost <host:port> [-port <localport>]`

If the `port` is omitted, `1080` will be used.


### _As module_

This is pretty much just the `main.go` of the server

```go
package main

import (
	"log"

	"github.com/FrauElster/socksauth/v2"
)

func main() {
	proxy, err := NewProxy(
		os.Getenv("SOCKS_USER"),
		os.Getenv("SOCKS_PASSWORD"),
		os.Getenv("SOCKS_HOST"),
	)
	if err != nil {
		log.Fatalf("Failed to create proxy: %v", err)
	}

	// Start proxy in a goroutine
	socksPort := 1080
	go func() {
		log.Printf("Starting SOCKS proxy on port %d", socksPort)
		if err := proxy.Start(*localPort); err != nil {
			if err.Error() != "use of closed network connection" {
				log.Printf("Proxy error: %v", err)
			}
		}
	}()

	// runs now on localhost:1080
}
```
