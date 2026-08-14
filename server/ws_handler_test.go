package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"

	"github.com/nxtrace/NTrace-core/ipgeo"
	"github.com/nxtrace/NTrace-core/trace"
)

type fakeWSConn struct {
	mu            sync.Mutex
	writes        []wsEnvelope
	writeStarted  chan struct{}
	writeBlock    chan struct{}
	closeOnce     sync.Once
	closeCount    int
	controlCount  int
	deadlineCount int
}

func newFakeWSConn(blockWrites bool) *fakeWSConn {
	conn := &fakeWSConn{}
	if blockWrites {
		conn.writeStarted = make(chan struct{})
		conn.writeBlock = make(chan struct{})
	}
	return conn
}

func (f *fakeWSConn) WriteJSON(v interface{}) error {
	if f.writeStarted != nil {
		select {
		case <-f.writeStarted:
		default:
			close(f.writeStarted)
		}
	}
	if f.writeBlock != nil {
		<-f.writeBlock
	}

	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	var msg wsEnvelope
	if err := json.Unmarshal(data, &msg); err != nil {
		return err
	}

	f.mu.Lock()
	f.writes = append(f.writes, msg)
	f.mu.Unlock()
	return nil
}

func (f *fakeWSConn) SetWriteDeadline(time.Time) error {
	f.mu.Lock()
	f.deadlineCount++
	f.mu.Unlock()
	return nil
}

func (f *fakeWSConn) WriteControl(messageType int, data []byte, deadline time.Time) error {
	f.mu.Lock()
	f.controlCount++
	f.mu.Unlock()
	return nil
}

func (f *fakeWSConn) Close() error {
	f.closeOnce.Do(func() {
		f.mu.Lock()
		f.closeCount++
		f.mu.Unlock()
		if f.writeBlock != nil {
			close(f.writeBlock)
		}
	})
	return nil
}

func (f *fakeWSConn) NextReader() (messageType int, r io.Reader, err error) {
	return 0, nil, io.EOF
}

type fakeWSInitConn struct {
	deadlines    []time.Time
	readLimit    int64
	message      []byte
	err          error
	deadlineErrs []error
}

func (f *fakeWSInitConn) SetReadDeadline(t time.Time) error {
	f.deadlines = append(f.deadlines, t)
	if len(f.deadlineErrs) > 0 {
		err := f.deadlineErrs[0]
		f.deadlineErrs = f.deadlineErrs[1:]
		return err
	}
	return nil
}

func (f *fakeWSInitConn) SetReadLimit(limit int64) {
	f.readLimit = limit
}

func (f *fakeWSInitConn) ReadMessage() (messageType int, p []byte, err error) {
	if f.err != nil {
		return 0, nil, f.err
	}
	return websocket.TextMessage, f.message, nil
}

func TestReadWSInitMessage_ClearsDeadlineAfterSuccessfulRead(t *testing.T) {
	conn := &fakeWSInitConn{message: []byte(`{"target":"example.com"}`)}

	msg, err := readWSInitMessage(conn)
	if err != nil {
		t.Fatalf("readWSInitMessage returned error: %v", err)
	}
	if string(msg) != `{"target":"example.com"}` {
		t.Fatalf("readWSInitMessage()=%q, want payload unchanged", string(msg))
	}
	if conn.readLimit != maxWSInitMessageBytes {
		t.Fatalf("SetReadLimit=%d, want %d", conn.readLimit, maxWSInitMessageBytes)
	}
	if len(conn.deadlines) != 2 {
		t.Fatalf("SetReadDeadline called %d times, want 2", len(conn.deadlines))
	}
	if conn.deadlines[0].IsZero() {
		t.Fatal("initial read deadline should be set")
	}
	if !conn.deadlines[1].IsZero() {
		t.Fatalf("final read deadline=%v, want zero time", conn.deadlines[1])
	}
}

func TestReadWSInitMessage_ReturnsInitialDeadlineError(t *testing.T) {
	conn := &fakeWSInitConn{
		message:      []byte(`{"target":"example.com"}`),
		deadlineErrs: []error{errors.New("set deadline failed")},
	}

	if _, err := readWSInitMessage(conn); err == nil || err.Error() != "set deadline failed" {
		t.Fatalf("readWSInitMessage error = %v, want initial deadline error", err)
	}
}

func TestReadWSInitMessage_ReturnsClearDeadlineError(t *testing.T) {
	conn := &fakeWSInitConn{
		message:      []byte(`{"target":"example.com"}`),
		deadlineErrs: []error{nil, errors.New("clear deadline failed")},
	}

	if _, err := readWSInitMessage(conn); err == nil || err.Error() != "clear deadline failed" {
		t.Fatalf("readWSInitMessage error = %v, want clear deadline error", err)
	}
}

func TestTraceWebsocketCanonicalizesLegacyProviderInStartAndComplete(t *testing.T) {
	gin.SetMode(gin.TestMode)
	oldLookup := traceDomainLookupFn
	oldTraceroute := traceTracerouteFn
	oldEnsure := ensureNextTraceAPIV3ConnectionFn
	t.Cleanup(func() {
		traceDomainLookupFn = oldLookup
		traceTracerouteFn = oldTraceroute
		ensureNextTraceAPIV3ConnectionFn = oldEnsure
	})
	traceDomainLookupFn = func(context.Context, string, string, string, bool) (net.IP, error) {
		return net.ParseIP("192.0.2.1"), nil
	}
	traceTracerouteFn = func(trace.Method, trace.Config) (*trace.Result, error) {
		return &trace.Result{}, nil
	}
	ensureNextTraceAPIV3ConnectionFn = func() {}

	router := gin.New()
	router.GET("/ws", traceWebsocketHandler)
	server := httptest.NewServer(router)
	t.Cleanup(server.Close)

	conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http")+"/ws", nil)
	if err != nil {
		t.Fatalf("websocket dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := conn.WriteJSON(map[string]any{
		"target":           "example.test",
		"data_provider":    "LeOmOe",
		"disable_maptrace": true,
	}); err != nil {
		t.Fatalf("write init request: %v", err)
	}

	for _, wantType := range []string{"start", "complete"} {
		var envelope wsEnvelope
		if err := conn.ReadJSON(&envelope); err != nil {
			t.Fatalf("read %s envelope: %v", wantType, err)
		}
		if envelope.Type != wantType {
			t.Fatalf("envelope type = %q, want %q", envelope.Type, wantType)
		}
		data, ok := envelope.Data.(map[string]any)
		if !ok {
			t.Fatalf("%s data = %T, want object", wantType, envelope.Data)
		}
		if got := data["data_provider"]; got != ipgeo.NextTraceAPIProvider {
			t.Fatalf("%s data_provider = %v, want %q", wantType, got, ipgeo.NextTraceAPIProvider)
		}
	}
}

func TestNewWSSessionContextInheritsParentCancellation(t *testing.T) {
	parent, cancelParent := context.WithCancel(context.Background())
	ctx, cancel := newWSSessionContext(parent)
	defer cancel()

	cancelParent()

	select {
	case <-ctx.Done():
		if !errors.Is(ctx.Err(), context.Canceled) {
			t.Fatalf("ctx.Err() = %v, want context.Canceled", ctx.Err())
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("session context did not inherit parent cancellation")
	}
}

func TestWSTraceSessionSend_QueueOverflowReturnsErrSlowConsumer(t *testing.T) {
	conn := newFakeWSConn(true)
	session := newWSTraceSession(conn, "cn", 1)
	defer session.finish()

	if err := session.send(wsEnvelope{Type: "first"}); err != nil {
		t.Fatalf("first send returned error: %v", err)
	}
	<-conn.writeStarted

	if err := session.send(wsEnvelope{Type: "second"}); err != nil {
		t.Fatalf("second send returned error: %v", err)
	}

	err := session.send(wsEnvelope{Type: "third"})
	if !errors.Is(err, errWSSlowConsumer) {
		t.Fatalf("expected errWSSlowConsumer, got %v", err)
	}
	if !session.closed.Load() {
		t.Fatal("session should be marked closed after queue overflow")
	}
}

func TestWSTraceSessionWriter_PreservesEnvelopeOrder(t *testing.T) {
	conn := newFakeWSConn(false)
	session := newWSTraceSession(conn, "cn", 4)

	if err := session.send(wsEnvelope{Type: "start"}); err != nil {
		t.Fatalf("first send returned error: %v", err)
	}
	if err := session.send(wsEnvelope{Type: "mtr_raw", Data: map[string]int{"ttl": 1}}); err != nil {
		t.Fatalf("second send returned error: %v", err)
	}

	session.finish()

	conn.mu.Lock()
	defer conn.mu.Unlock()
	if len(conn.writes) != 2 {
		t.Fatalf("writer sent %d envelopes, want 2", len(conn.writes))
	}
	if conn.writes[0].Type != "start" || conn.writes[1].Type != "mtr_raw" {
		t.Fatalf("unexpected write order: %+v", conn.writes)
	}
}

func TestWSTraceSessionClose_IsIdempotent(t *testing.T) {
	conn := newFakeWSConn(false)
	session := newWSTraceSession(conn, "cn", 4)

	session.closeWithCode(websocket.CloseTryAgainLater, "slow consumer")
	session.closeWithCode(websocket.CloseTryAgainLater, "slow consumer")
	session.finish()
	session.finish()

	conn.mu.Lock()
	defer conn.mu.Unlock()
	if conn.closeCount != 1 {
		t.Fatalf("Close called %d times, want 1", conn.closeCount)
	}
	if conn.controlCount != 1 {
		t.Fatalf("WriteControl called %d times, want 1", conn.controlCount)
	}
	if conn.deadlineCount != 0 {
		t.Fatalf("SetWriteDeadline called %d times during close path, want 0", conn.deadlineCount)
	}
}

func TestRunMTRTraceStreamsPathEndAndCompleteState(t *testing.T) {
	oldRun := traceRunMTRRawFn
	defer func() { traceRunMTRRawFn = oldRun }()
	traceRunMTRRawFn = func(_ context.Context, _ trace.Method, _ trace.Config, opts trace.MTRRawOptions, onRecord trace.MTRRawOnRecord) error {
		opts.OnPathEnd(&trace.StopReason{Hop: 3, Reason: trace.StopReasonUnreachable, Markers: []string{"!H"}})
		onRecord(trace.MTRRawRecord{Iteration: 1, TTL: 3, Success: true, IP: "192.0.2.3", Response: &trace.MTRProbeResponse{Kind: trace.MTRResponseUnreachable, Marker: "!H"}})
		opts.OnPathEnd(nil)
		return nil
	}

	conn := newFakeWSConn(false)
	session := newWSTraceSession(conn, "en", 8)
	runMTRTrace(context.Background(), session, &traceExecution{
		Method: trace.ICMPTrace,
		Config: trace.Config{MaxHops: 5},
		Req:    traceRequest{HopIntervalMs: 1, MaxRounds: 1},
	})
	session.finish()

	conn.mu.Lock()
	defer conn.mu.Unlock()
	var types []string
	for _, write := range conn.writes {
		types = append(types, write.Type)
	}
	want := []string{"path_end", "mtr_raw", "path_end", "complete"}
	if len(types) != len(want) {
		t.Fatalf("envelopes = %v, want %v", types, want)
	}
	for i := range want {
		if types[i] != want[i] {
			t.Fatalf("envelopes = %v, want %v", types, want)
		}
	}
	reopenData, err := json.Marshal(conn.writes[2].Data)
	if err != nil {
		t.Fatal(err)
	}
	if string(reopenData) != "null" {
		t.Fatalf("reopen path_end data = %s, want null", reopenData)
	}
	data, err := json.Marshal(conn.writes[len(conn.writes)-1].Data)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != `{"iteration":1,"path_end":null}` {
		t.Fatalf("complete data = %s", data)
	}
}

func TestRunMTRTraceCancellationDoesNotInventPathEnd(t *testing.T) {
	oldRun := traceRunMTRRawFn
	defer func() { traceRunMTRRawFn = oldRun }()
	traceRunMTRRawFn = func(_ context.Context, _ trace.Method, _ trace.Config, _ trace.MTRRawOptions, _ trace.MTRRawOnRecord) error {
		return context.Canceled
	}

	conn := newFakeWSConn(false)
	session := newWSTraceSession(conn, "en", 8)
	runMTRTrace(context.Background(), session, &traceExecution{
		Method: trace.ICMPTrace,
		Config: trace.Config{MaxHops: 5},
		Req:    traceRequest{HopIntervalMs: 1, MaxRounds: 3},
	})
	session.finish()

	conn.mu.Lock()
	defer conn.mu.Unlock()
	if len(conn.writes) != 1 || conn.writes[0].Type != "complete" {
		t.Fatalf("cancel envelopes = %#v, want only complete", conn.writes)
	}
	data, err := json.Marshal(conn.writes[0].Data)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != `{"iteration":0,"path_end":null}` {
		t.Fatalf("cancel complete data = %s", data)
	}
}

func TestRunSingleTraceCompleteUsesSnakeCaseStopReason(t *testing.T) {
	oldTraceroute := traceTracerouteFn
	t.Cleanup(func() { traceTracerouteFn = oldTraceroute })
	traceTracerouteFn = func(trace.Method, trace.Config) (*trace.Result, error) {
		return &trace.Result{
			StopReason: &trace.StopReason{
				Hop:       4,
				Reason:    trace.StopReasonUnreachable,
				Responses: []string{"ICMP Host Unreachable"},
				Markers:   []string{"!H"},
			},
		}, nil
	}

	conn := newFakeWSConn(false)
	session := newWSTraceSession(conn, "en", 4)
	runSingleTrace(context.Background(), session, &traceExecution{
		Target:       "example.test",
		Protocol:     "ICMP",
		DataProvider: "disable-geoip",
		Method:       trace.ICMPTrace,
		IP:           net.ParseIP("192.0.2.1"),
		Config:       trace.Config{Lang: "en"},
	})
	session.finish()

	conn.mu.Lock()
	defer conn.mu.Unlock()
	if len(conn.writes) != 1 || conn.writes[0].Type != "complete" {
		t.Fatalf("envelopes = %#v, want one complete", conn.writes)
	}
	data, err := json.Marshal(conn.writes[0].Data)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatalf("complete data decode: %v", err)
	}
	if _, ok := fields["stop_reason"]; !ok {
		t.Fatalf("complete data missing stop_reason: %s", data)
	}
	if _, ok := fields["StopReason"]; ok {
		t.Fatalf("complete data leaked core StopReason key: %s", data)
	}
}

func TestSanitizeLogParam(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"normal text", "normal text"},
		{"hello\nworld", "hello\\nworld"},
		{"hello\r\nworld", "hello\\n\\nworld"},
		{"line1\nline2\nline3", "line1\\nline2\\nline3"},
		{"tab\there", "tab\there"},
		{"null\x00byte", "null\uFFFDbyte"},
		{"esc\x1b[31m", "esc\uFFFD[31m"},
		{"", ""},
		{"safe-host.example.com", "safe-host.example.com"},
		{"evil\n[deploy] fake log entry", "evil\\n[deploy] fake log entry"},
	}
	for _, tt := range tests {
		got := sanitizeLogParam(tt.input)
		if got != tt.want {
			t.Errorf("sanitizeLogParam(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
