package server

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/nxtrace/NTrace-core/internal/service"
	"github.com/nxtrace/NTrace-core/trace"
)

func TestHTTPServerTimeoutConfiguration(t *testing.T) {
	srv := newHTTPServer("127.0.0.1:0", http.NotFoundHandler())
	if srv.ReadHeaderTimeout != 5*time.Second || srv.ReadTimeout != 30*time.Second || srv.IdleTimeout != 60*time.Second || srv.WriteTimeout != 0 {
		t.Fatalf("unexpected deadlines: header=%s read=%s idle=%s write=%s", srv.ReadHeaderTimeout, srv.ReadTimeout, srv.IdleTimeout, srv.WriteTimeout)
	}
}

func newShortTimeoutTestServer(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(handler)
	srv.Config = newHTTPServer("", handler)
	srv.Config.ReadHeaderTimeout = 250 * time.Millisecond
	srv.Config.ReadTimeout = 500 * time.Millisecond
	srv.Config.IdleTimeout = 250 * time.Millisecond
	srv.Start()
	t.Cleanup(srv.Close)
	return srv
}

func dialTimeoutTestServer(t *testing.T, srv *httptest.Server) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", srv.Listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	return conn
}

func TestHTTPReadDeadlines(t *testing.T) {
	t.Run("incomplete_header", func(t *testing.T) {
		var calls atomic.Int32
		srv := newShortTimeoutTestServer(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
		conn := dialTimeoutTestServer(t, srv)
		if _, err := io.WriteString(conn, "GET / HTTP/1.1\r\nHost: localhost\r\n"); err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadAll(conn); err != nil {
			t.Fatalf("server did not close incomplete headers before client deadline: %v", err)
		}
		if calls.Load() != 0 {
			t.Fatal("incomplete headers entered handler")
		}
	})
	t.Run("incomplete_body", func(t *testing.T) {
		readErr := make(chan error, 1)
		srv := newShortTimeoutTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, err := io.Copy(io.Discard, r.Body)
			readErr <- err
			w.WriteHeader(http.StatusBadRequest)
		}))
		conn := dialTimeoutTestServer(t, srv)
		if _, err := io.WriteString(conn, "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 100\r\n\r\nx"); err != nil {
			t.Fatal(err)
		}
		select {
		case err := <-readErr:
			var timeout net.Error
			if !errors.As(err, &timeout) || !timeout.Timeout() {
				t.Fatalf("body read error=%v, want timeout", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("slow body was not interrupted")
		}
	})
	t.Run("idle_keepalive", func(t *testing.T) {
		srv := newShortTimeoutTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") }))
		conn := dialTimeoutTestServer(t, srv)
		if _, err := io.WriteString(conn, "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"); err != nil {
			t.Fatal(err)
		}
		reader := bufio.NewReader(conn)
		resp, err := http.ReadResponse(reader, nil)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if resp.Close {
			t.Fatal("control response unexpectedly disabled keepalive")
		}
		if _, err := reader.ReadByte(); !errors.Is(err, io.EOF) {
			t.Fatalf("idle connection close=%v, want EOF", err)
		}
	})
}

type delayedMCPService struct{ *recordingMCPService }

func (s *delayedMCPService) MTRReport(ctx context.Context, req service.MTRReportRequest) (service.MTRReportResponse, error) {
	select {
	case <-time.After(time.Second):
		return s.recordingMCPService.MTRReport(ctx, req)
	case <-ctx.Done():
		return service.MTRReportResponse{}, ctx.Err()
	}
}

func TestHTTPReadTimeoutPreservesLongMCPJob(t *testing.T) {
	srv := newShortTimeoutTestServer(t, newMCPHTTPHandlerWithService(&delayedMCPService{newRecordingMCPService()}))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client := mcp.NewClient(&mcp.Implementation{Name: "deadline-test", Version: "1"}, nil)
	session, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: srv.URL, HTTPClient: srv.Client(), DisableStandaloneSSE: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = session.Close() }()
	result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "nexttrace_mtr_report", Arguments: map[string]any{"target": "example.invalid"}})
	if err != nil {
		t.Fatal(err)
	}
	if result.IsError {
		t.Fatalf("long MCP job failed: %+v", result)
	}
}

func TestHTTPReadTimeoutPreservesContinuousWebsocketMTR(t *testing.T) {
	oldLookup, oldRun := traceDomainLookupFn, traceRunMTRRawFn
	t.Cleanup(func() { traceDomainLookupFn, traceRunMTRRawFn = oldLookup, oldRun })
	traceDomainLookupFn = func(context.Context, string, string, string, bool) (net.IP, error) {
		return net.ParseIP("192.0.2.1"), nil
	}
	done := make(chan struct{})
	traceRunMTRRawFn = func(ctx context.Context, _ trace.Method, _ trace.Config, opts trace.MTRRawOptions, emit trace.MTRRawOnRecord) error {
		defer close(done)
		if opts.MaxPerHop != 0 {
			t.Error("continuous MTR no longer unlimited")
		}
		emit(trace.MTRRawRecord{Iteration: 1, TTL: 1, IP: "192.0.2.1", Success: true})
		select {
		case <-time.After(time.Second):
			emit(trace.MTRRawRecord{Iteration: 2, TTL: 1, IP: "192.0.2.1", Success: true})
		case <-ctx.Done():
			return ctx.Err()
		}
		<-ctx.Done()
		return ctx.Err()
	}
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/ws/trace", traceWebsocketHandler)
	srv := newShortTimeoutTestServer(t, router)
	conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http")+"/ws/trace", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if err := conn.WriteJSON(traceRequest{Target: "example.invalid", DataProvider: "disable-geoip", Mode: "mtr"}); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	for records := 0; records < 2; {
		var envelope wsEnvelope
		if err := conn.ReadJSON(&envelope); err != nil {
			t.Fatal(err)
		}
		if envelope.Type == "error" {
			t.Fatalf("MTR error: %+v", envelope)
		}
		if envelope.Type == "mtr_raw" {
			records++
		}
	}
	_ = conn.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("client close did not cancel MTR")
	}
}
