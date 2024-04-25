package socksauth

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
)

type SocksError interface {
	error
	Is(target error) bool
	Unwrap() error

	ProxyServer() struct {
		Host string
		Name string
	}
	DestinationServer() string
	ConnectionId() int64

	withError(err error) SocksError
	withMessage(message string) SocksError
	fromConnection(socksConnection) SocksError
}

var _ SocksError = (*socksError)(nil)

type socksError struct {
	code      string
	err       error
	Message   string
	ErrOrigin string

	destinationServer string
	proxyServer       struct {
		Name string
		Host string
	}
	connectionId int64
}

func newError(code, defaultMessage string) socksError {
	_, file, line, _ := runtime.Caller(1)

	return socksError{
		code:      code,
		Message:   defaultMessage,
		ErrOrigin: fmt.Sprintf("%s:%d", file, line),
	}
}

func (e socksError) Error() string {
	connInfos := make([]string, 0)
	if e.connectionId != 0 {
		connInfos = append(connInfos, fmt.Sprintf("connection %d", e.connectionId))
	}
	if e.proxyServer.Name != "" && e.proxyServer.Host != "" {
		connInfos = append(connInfos, fmt.Sprintf("proxy %s (%s)", e.proxyServer.Name, e.proxyServer.Host))
	} else if e.proxyServer.Host != "" {
		connInfos = append(connInfos, fmt.Sprintf("proxy %s", e.proxyServer.Host))
	}
	if e.destinationServer != "" {
		connInfos = append(connInfos, fmt.Sprintf("destination %s", e.destinationServer))
	}
	asString := fmt.Sprintf("%s - [%s] %s", e.code, strings.Join(connInfos, " | "), e.Message)

	if e.err != nil {
		asString += ": " + e.err.Error()
	}
	if e.ErrOrigin != "" {
		asString += " at " + e.ErrOrigin
	}
	return asString
}

func (e socksError) Is(target error) bool {
	t, ok := target.(socksError)
	if !ok {
		return false
	}
	return e.code == t.code
}

func (e socksError) Unwrap() error {
	return e.err
}

func (e socksError) ProxyServer() struct {
	Host string
	Name string
} {
	return struct {
		Host string
		Name string
	}{Host: e.proxyServer.Host, Name: e.proxyServer.Name}
}

func (e socksError) DestinationServer() string {
	return e.destinationServer
}

func (e socksError) ConnectionId() int64 {
	return e.connectionId
}

func (e socksError) withError(err error) SocksError {
	e.err = errors.Join(e.err, err)
	return e
}

func (e socksError) withMessage(message string) SocksError {
	e.Message = message
	return e
}

func (e socksError) fromConnection(conn socksConnection) SocksError {
	e.connectionId = conn.connId
	e.proxyServer.Name = conn.proxyName
	e.proxyServer.Host = conn.proxyHost
	e.destinationServer = conn.destination

	_, file, line, ok := runtime.Caller(1)
	if !ok {
		return e
	}
	e.ErrOrigin = fmt.Sprintf("%s:%d", file, line)
	return e
}
