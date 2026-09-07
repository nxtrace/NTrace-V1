package internal

import (
	"context"
	"testing"
)

func TestBackendCancellationDoesNotOpenResources(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	for _, proto := range []string{"icmp", "tcp", "udp"} {
		checks := CheckProbeBackend(ctx, BackendOptions{Protocol: proto, IPVersion: 4, ICMPMode: 1})
		if len(checks) == 0 {
			t.Fatal("no check results")
		}
		for _, c := range checks {
			if !c.Skipped {
				t.Fatalf("%s initialized after cancellation: %+v", proto, c)
			}
		}
	}
	c := backendStep(ctx, "test", func() error { t.Fatal("opened after cancellation"); return nil })
	if !c.Skipped {
		t.Fatal("expected skipped")
	}
}
