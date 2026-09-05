package ipgeo

import (
	"context"
	"net/http"
	"testing"
	"time"
)

func TestNewGeoRequestAppliesTimeoutToContext(t *testing.T) {
	const timeout = 5 * time.Second
	started := time.Now()
	req, cancel, err := newGeoRequest(http.MethodGet, "https://example.com/geo", timeout)
	if err != nil {
		t.Fatalf("newGeoRequest() error = %v", err)
	}
	defer cancel()

	deadline, ok := req.Context().Deadline()
	if !ok {
		t.Fatal("request context has no deadline")
	}
	if remaining := deadline.Sub(started); remaining < timeout-time.Second || remaining > timeout+time.Second {
		t.Fatalf("request deadline remaining = %v, want approximately %v", remaining, timeout)
	}

	cancel()
	select {
	case <-req.Context().Done():
		if req.Context().Err() != context.Canceled {
			t.Fatalf("request context error = %v, want context.Canceled", req.Context().Err())
		}
	case <-time.After(time.Second):
		t.Fatal("request context was not canceled")
	}
}

func TestNewGeoRequestWithoutPositiveTimeoutHasNoDeadline(t *testing.T) {
	for _, timeout := range []time.Duration{0, -time.Second} {
		req, cancel, err := newGeoRequest(http.MethodGet, "https://example.com/geo", timeout)
		if err != nil {
			t.Fatalf("newGeoRequest(%v) error = %v", timeout, err)
		}
		cancel()
		if _, ok := req.Context().Deadline(); ok {
			t.Fatalf("newGeoRequest(%v) unexpectedly set a deadline", timeout)
		}
	}
}
