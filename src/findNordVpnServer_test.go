package main

import (
	"context"
	"testing"
)

func TestFindNordVpnServers(t *testing.T) {
	servers, err := findSocksServer(context.Background())
	if err != nil {
		t.Error(err)
	}
	if len(servers) == 0 {
		t.Error("No servers found")
	}
}
