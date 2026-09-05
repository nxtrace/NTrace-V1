package server

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/nxtrace/NTrace-core/internal/service"
	"github.com/nxtrace/NTrace-core/util"
)

func TestDeployProbeLimitsBeforeLookup(t *testing.T) {
	oldLookup := traceDomainLookupFn
	t.Cleanup(func() { traceDomainLookupFn = oldLookup })
	for _, tc := range []struct {
		name  string
		req   traceRequest
		field string
	}{
		{"hops", traceRequest{MaxHops: 256}, "max_hops"},
		{"begin", traceRequest{BeginHop: 31}, "begin_hop"},
		{"queries", traceRequest{Queries: 64}, "queries"},
		{"parallel", traceRequest{ParallelRequests: 257}, "parallel_requests"},
		{"attempts", traceRequest{MaxAttempts: 64}, "max_attempts"},
		{"rest_mtr_alias", traceRequest{Mode: "mtr", Queries: 64}, "queries"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			traceDomainLookupFn = func(context.Context, string, string, string, bool) (net.IP, error) {
				called = true
				return nil, errors.New("unexpected lookup")
			}
			tc.req.Target = "example.invalid"
			tc.req.DataProvider = "disable-geoip"
			_, status, err := prepareTrace(context.Background(), tc.req)
			if called || status != 400 || err == nil || !strings.Contains(err.Error(), tc.field) {
				t.Fatalf("lookup=%v status=%d err=%v; want pre-lookup %s rejection", called, status, err, tc.field)
			}
		})
	}
}

func TestDeployProbeLimitsHTTPAndWebsocket(t *testing.T) {
	oldLookup := traceDomainLookupFn
	t.Cleanup(func() { traceDomainLookupFn = oldLookup })
	traceDomainLookupFn = func(context.Context, string, string, string, bool) (net.IP, error) {
		t.Error("invalid request reached DNS")
		return nil, errors.New("unexpected lookup")
	}
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/api/trace", traceHandler)
	router.GET("/ws/trace", traceWebsocketHandler)
	server := httptest.NewServer(router)
	defer server.Close()
	for _, payload := range []string{
		`{"target":"example.invalid","max_hops":256}`,
		`{"target":"example.invalid","parallel_requests":2147483647}`,
		`{"target":"example.invalid","mode":"mtr","queries":64}`,
		`{"target":"example.invalid","mode":"continuous","max_attempts":64}`,
	} {
		resp := httptest.NewRecorder()
		router.ServeHTTP(resp, httptest.NewRequestWithContext(context.Background(), "POST", "/api/trace", strings.NewReader(payload)))
		if resp.Code != 400 {
			t.Fatalf("REST status=%d body=%s", resp.Code, resp.Body.String())
		}
	}
	for _, payload := range []traceRequest{
		{MaxHops: 256}, {Queries: 64}, {MaxAttempts: 64},
		{Mode: "mtr", ParallelRequests: 257}, {Mode: "continuous", BeginHop: 31},
	} {
		conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http")+"/ws/trace", nil)
		if err != nil {
			t.Fatal(err)
		}
		payload.Target = "example.invalid"
		if err := conn.WriteJSON(payload); err != nil {
			t.Fatal(err)
		}
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		var envelope wsEnvelope
		err = conn.ReadJSON(&envelope)
		_ = conn.Close()
		if err != nil || envelope.Type != "error" || envelope.Status != http.StatusBadRequest {
			t.Fatalf("WS envelope=%+v err=%v", envelope, err)
		}
	}
}

func TestDeployProbeLimitsMCPHTTP(t *testing.T) {
	session, cleanup := newTestMCPSession(t, service.New())
	defer cleanup()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, tc := range []struct {
		tool, field string
		value       int
	}{
		{"nexttrace_traceroute", "queries", 64},
		{"nexttrace_traceroute", "max_attempts", 64},
		{"nexttrace_mtr_report", "parallel_requests", 257},
		{"nexttrace_mtr_raw", "max_hops", 256},
		{"nexttrace_mtu_trace", "queries", 64},
		{"nexttrace_mtu_trace", "begin_hop", 31},
	} {
		result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: tc.tool, Arguments: map[string]any{
			"target": "example.invalid", "data_provider": "disable-geoip", tc.field: tc.value,
		}})
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := json.Marshal(result)
		if err != nil {
			t.Fatal(err)
		}
		if !result.IsError || !strings.Contains(string(encoded), tc.field+" must be within range 1-") {
			t.Fatalf("MCP result=%s", encoded)
		}
	}
}

func TestDeployProbeLimitsEffectiveMTRAndDefaults(t *testing.T) {
	oldLookup, oldEnv := traceDomainLookupFn, util.EnvMaxAttempts
	t.Cleanup(func() { traceDomainLookupFn, util.EnvMaxAttempts = oldLookup, oldEnv })
	traceDomainLookupFn = func(context.Context, string, string, string, bool) (net.IP, error) {
		return net.ParseIP("192.0.2.1"), nil
	}
	util.EnvMaxAttempts = 64
	for _, mode := range []string{"mtr", " CONTINUOUS "} {
		setup, _, err := prepareWebsocketTrace(context.Background(), traceRequest{Target: "example.invalid", DataProvider: "disable-geoip", Mode: mode, Queries: 1000000, MaxAttempts: 1000000})
		if err != nil {
			t.Fatal(err)
		}
		if setup.Config.NumMeasurements != 1 || setup.Config.MaxAttempts != 1 || setup.Req.MaxRounds != 0 {
			t.Fatal("MTR ignored fields or unlimited default changed")
		}
	}
	_, status, err := prepareTrace(context.Background(), traceRequest{Target: "example.invalid", DataProvider: "disable-geoip", MaxAttempts: -1})
	if status != 400 || err == nil || !strings.Contains(err.Error(), "max_attempts") {
		t.Fatalf("env limit: status=%d err=%v", status, err)
	}
	util.EnvMaxAttempts = 0
	setup, _, err := prepareTrace(context.Background(), traceRequest{Target: "example.invalid", DataProvider: "disable-geoip", MaxHops: -1, BeginHop: -1, Queries: -1, ParallelRequests: -1})
	if err != nil {
		t.Fatal(err)
	}
	if setup.Config.MaxHops != 30 || setup.Config.BeginHop != 1 || setup.Config.NumMeasurements != 3 || setup.Config.ParallelRequests != 18 {
		t.Fatal("non-positive defaults changed")
	}
}
