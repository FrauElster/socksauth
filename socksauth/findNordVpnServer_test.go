package socksauth

import (
	"context"
	"testing"
)

func TestFindNordVpnServers(t *testing.T) {
	servers, err := FindNordVpnServer(context.Background())
	if err != nil {
		t.Error(err)
	}
	if len(servers) == 0 {
		t.Error("No servers found")
	}
}
