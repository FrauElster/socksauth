# SocksAuth

This project turns an authenticated SOCKS5 connection to an authenticated one.

It is kept very minimal, so there is just ~400 LoC in one single file. No tests, no assets, no github workflows, no dependabot, no issue templates, etc. Just the code and this Readme I guess.

### _Why?_ 

Because I needed a way to use a propietery SOCKS5 server with an automated browser, which does not allow to pass authentification to proxies.

### _How to install?_ 

Currently it is just available as an executable. Maybe I will package it as a go module at some point.

```sh
git clone https://https://github.com/FrauElster/SocksAuth.git && cd ./SocksAuth
cd src && go build -o ../socksauth . && cd ..
```

### _How to use?_

`./socksauth -remoteHost <host:port> -remoteUser <username> -remotePass <password> [-port <localport>] [-debug]`

Everything should be straight forward.

`localport`  defaults to 1080
`debug` prints some additional information