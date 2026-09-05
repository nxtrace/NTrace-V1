package server

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"

	"github.com/nxtrace/NTrace-core/trace"
)

func TestTraceWebsocketInitMessageSizeBoundary(t *testing.T) {
	gin.SetMode(gin.TestMode)

	oldLookup := traceDomainLookupFn
	oldTraceroute := traceTracerouteFn
	oldEnsure := ensureNextTraceAPIV3ConnectionFn
	defer func() {
		traceDomainLookupFn = oldLookup
		traceTracerouteFn = oldTraceroute
		ensureNextTraceAPIV3ConnectionFn = oldEnsure
	}()

	traceDomainLookupFn = func(context.Context, string, string, string, bool) (net.IP, error) {
		return net.ParseIP("192.0.2.1"), nil
	}
	var tracerCalls atomic.Int32
	traceTracerouteFn = func(trace.Method, trace.Config) (*trace.Result, error) {
		tracerCalls.Add(1)
		return &trace.Result{}, nil
	}
	ensureNextTraceAPIV3ConnectionFn = func() {}

	router := gin.New()
	router.GET("/ws", traceWebsocketHandler)
	server := httptest.NewServer(router)
	defer server.Close()
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/ws"

	t.Run("accepts exactly 65536 bytes", func(t *testing.T) {
		conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
		if err != nil {
			t.Fatalf("websocket dial: %v", err)
		}
		defer func() { _ = conn.Close() }()

		payload := paddedWSInitPayload(t, maxWSInitMessageBytes)
		if err := conn.WriteMessage(websocket.TextMessage, payload); err != nil {
			t.Fatalf("write init message: %v", err)
		}

		for _, wantType := range []string{"start", "complete"} {
			var envelope wsEnvelope
			if err := conn.ReadJSON(&envelope); err != nil {
				t.Fatalf("read %s envelope: %v", wantType, err)
			}
			if envelope.Type != wantType {
				t.Fatalf("envelope type = %q, want %q", envelope.Type, wantType)
			}
		}
		if got := tracerCalls.Load(); got != 1 {
			t.Fatalf("tracer calls = %d, want 1", got)
		}
	})

	t.Run("rejects 65537 bytes", func(t *testing.T) {
		callsBefore := tracerCalls.Load()
		conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
		if err != nil {
			t.Fatalf("websocket dial: %v", err)
		}
		defer func() { _ = conn.Close() }()

		payload := paddedWSInitPayload(t, maxWSInitMessageBytes+1)
		if err := conn.WriteMessage(websocket.TextMessage, payload); err != nil {
			t.Fatalf("write oversized init message: %v", err)
		}

		_, _, err = conn.ReadMessage()
		var closeErr *websocket.CloseError
		if !errors.As(err, &closeErr) || closeErr.Code != websocket.CloseMessageTooBig {
			t.Fatalf("read oversized response error = %v, want close code %d", err, websocket.CloseMessageTooBig)
		}
		if got := tracerCalls.Load(); got != callsBefore {
			t.Fatalf("oversized message invoked tracer: calls %d -> %d", callsBefore, got)
		}
	})
}

func paddedWSInitPayload(t *testing.T, size int) []byte {
	t.Helper()
	base := []byte(`{"target":"192.0.2.1","data_provider":"disable-geoip","disable_maptrace":true}`)
	if len(base) > size {
		t.Fatalf("base init payload size = %d, exceeds target %d", len(base), size)
	}
	payload := make([]byte, size)
	copy(payload, base)
	for i := len(base); i < len(payload); i++ {
		payload[i] = ' '
	}
	if !json.Valid(payload) {
		t.Fatal("padded init payload is not valid JSON")
	}
	return payload
}
