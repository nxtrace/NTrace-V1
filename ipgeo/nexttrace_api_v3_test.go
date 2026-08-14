package ipgeo

import (
	"context"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nxtrace/NTrace-core/wshandle"
)

func TestNextTraceAPIV3GeoIPWaitsForConnectionBeforeSending(t *testing.T) {
	oldGet := getNextTraceAPIV3WSConn
	oldPools := IPPools.pool
	oldRunning, oldRestart := nextTraceAPIV3ReceiveState()
	var conn *wshandle.WsConn
	nextTraceAPIV3ReceiveStarted := make(chan struct{})
	var getConnCalls int32
	var closeStarted sync.Once
	defer func() {
		if conn != nil && conn.MsgReceiveCh != nil {
			close(conn.MsgReceiveCh)
		}
		waitForNextTraceAPIV3ReceiveStart(t, nextTraceAPIV3ReceiveStarted)
		waitForNextTraceAPIV3ReceiveStop(t)
		getNextTraceAPIV3WSConn = oldGet
		IPPools.pool = oldPools
		setNextTraceAPIV3ReceiveState(oldRunning, oldRestart)
	}()

	IPPools.pool = make(map[string]chan IPGeoData)
	setNextTraceAPIV3ReceiveState(false, false)

	conn = &wshandle.WsConn{
		MsgSendCh:    make(chan string, 1),
		MsgReceiveCh: make(chan string, 1),
		Interrupt:    make(chan os.Signal, 1),
	}
	getNextTraceAPIV3WSConn = func() *wshandle.WsConn {
		if atomic.AddInt32(&getConnCalls, 1) >= 3 {
			closeStarted.Do(func() { close(nextTraceAPIV3ReceiveStarted) })
		}
		return conn
	}

	sent := make(chan string, 1)
	go func() {
		msg := <-conn.MsgSendCh
		sent <- msg
		conn.MsgReceiveCh <- `{"ip":"1.1.1.1","asnumber":"13335"}`
	}()

	var (
		gotGeo *IPGeoData
		gotErr error
	)
	done := make(chan struct{})
	go func() {
		gotGeo, gotErr = NextTraceAPIV3GeoIP("1.1.1.1", 300*time.Millisecond, "en", false)
		close(done)
	}()

	select {
	case <-sent:
		t.Fatal("NextTraceAPIV3GeoIP sent request before websocket became connected")
	case <-time.After(60 * time.Millisecond):
	}

	conn.SetConnected(true)

	select {
	case msg := <-sent:
		if msg != "1.1.1.1" {
			t.Fatalf("sent request = %q, want 1.1.1.1", msg)
		}
	case <-time.After(time.Second):
		t.Fatal("NextTraceAPIV3GeoIP did not send request after websocket became connected")
	}

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("NextTraceAPIV3GeoIP did not complete")
	}

	if gotErr != nil {
		t.Fatalf("NextTraceAPIV3GeoIP error = %v, want nil", gotErr)
	}
	if gotGeo == nil || gotGeo.Asnumber != "13335" {
		t.Fatalf("NextTraceAPIV3GeoIP geo = %+v, want ASN 13335", gotGeo)
	}
}

func TestNextTraceAPIV3GeoIPUsesSingleTimeoutBudget(t *testing.T) {
	oldGet := getNextTraceAPIV3WSConn
	oldPools := IPPools.pool
	oldRunning, oldRestart := nextTraceAPIV3ReceiveState()
	var conn *wshandle.WsConn
	nextTraceAPIV3ReceiveStarted := make(chan struct{})
	var getConnCalls int32
	var closeStarted sync.Once
	defer func() {
		if conn != nil && conn.MsgReceiveCh != nil {
			close(conn.MsgReceiveCh)
		}
		waitForNextTraceAPIV3ReceiveStart(t, nextTraceAPIV3ReceiveStarted)
		waitForNextTraceAPIV3ReceiveStop(t)
		getNextTraceAPIV3WSConn = oldGet
		IPPools.pool = oldPools
		setNextTraceAPIV3ReceiveState(oldRunning, oldRestart)
	}()

	IPPools.pool = make(map[string]chan IPGeoData)
	setNextTraceAPIV3ReceiveState(false, false)

	conn = &wshandle.WsConn{
		MsgSendCh:    make(chan string, 1),
		MsgReceiveCh: make(chan string),
		Interrupt:    make(chan os.Signal, 1),
	}
	getNextTraceAPIV3WSConn = func() *wshandle.WsConn {
		if atomic.AddInt32(&getConnCalls, 1) >= 3 {
			closeStarted.Do(func() { close(nextTraceAPIV3ReceiveStarted) })
		}
		return conn
	}

	start := time.Now()
	done := make(chan error, 1)
	go func() {
		_, err := NextTraceAPIV3GeoIP("1.1.1.1", 2*time.Second, "en", false)
		done <- err
	}()

	time.Sleep(1500 * time.Millisecond)
	conn.SetConnected(true)

	select {
	case err := <-done:
		if err == nil || err.Error() != "TimeOut" {
			t.Fatalf("NextTraceAPIV3GeoIP error = %v, want TimeOut", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("NextTraceAPIV3GeoIP exceeded expected shared timeout budget")
	}

	if elapsed := time.Since(start); elapsed > 2800*time.Millisecond {
		t.Fatalf("NextTraceAPIV3GeoIP elapsed = %s, want <= 2.8s", elapsed)
	}
}

func TestNextTraceAPIV3ReceiveReturnsWhenWebsocketMissing(t *testing.T) {
	oldGet := getNextTraceAPIV3WSConn
	defer func() { getNextTraceAPIV3WSConn = oldGet }()

	getNextTraceAPIV3WSConn = func() *wshandle.WsConn { return nil }

	done := make(chan struct{})
	go func() {
		receiveNextTraceAPIV3Responses()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("receiveNextTraceAPIV3Responses should return when websocket is nil")
	}
}

func TestNextTraceAPIV3ReceiveContinuesAfterWebsocketReplacement(t *testing.T) {
	oldGet := getNextTraceAPIV3WSConn
	oldPools := IPPools.pool
	defer func() {
		getNextTraceAPIV3WSConn = oldGet
		IPPools.pool = oldPools
	}()

	oldConn := &wshandle.WsConn{
		MsgReceiveCh: make(chan string),
		Interrupt:    make(chan os.Signal, 1),
	}
	newConn := &wshandle.WsConn{
		MsgReceiveCh: make(chan string),
		Interrupt:    make(chan os.Signal, 1),
	}
	current := oldConn
	getNextTraceAPIV3WSConn = func() *wshandle.WsConn {
		return current
	}

	oldResult := make(chan IPGeoData, 1)
	newResult := make(chan IPGeoData, 1)
	IPPools.pool = map[string]chan IPGeoData{
		"1.1.1.1": oldResult,
		"2.2.2.2": newResult,
	}

	done := make(chan struct{})
	go func() {
		receiveNextTraceAPIV3Responses()
		close(done)
	}()

	select {
	case oldConn.MsgReceiveCh <- `{"ip":"1.1.1.1","asnumber":"13335"}`:
	case <-time.After(time.Second):
		t.Fatal("receiveNextTraceAPIV3Responses did not consume from the original websocket")
	}
	select {
	case geo := <-oldResult:
		if geo.Asnumber != "13335" {
			t.Fatalf("old websocket geo ASN = %q, want 13335", geo.Asnumber)
		}
	case <-time.After(time.Second):
		t.Fatal("receiveNextTraceAPIV3Responses did not dispatch original websocket data")
	}

	current = newConn
	close(oldConn.MsgReceiveCh)

	select {
	case newConn.MsgReceiveCh <- `{"ip":"2.2.2.2","asnumber":"64512"}`:
	case <-time.After(time.Second):
		t.Fatal("receiveNextTraceAPIV3Responses did not switch to replacement websocket")
	}
	select {
	case geo := <-newResult:
		if geo.Asnumber != "64512" {
			t.Fatalf("new websocket geo ASN = %q, want 64512", geo.Asnumber)
		}
	case <-time.After(time.Second):
		t.Fatal("receiveNextTraceAPIV3Responses did not dispatch replacement websocket data")
	}

	close(newConn.MsgReceiveCh)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("receiveNextTraceAPIV3Responses did not exit after replacement websocket closed")
	}
}

func TestStartNextTraceAPIV3ReceiverRestartsAfterQueuedStart(t *testing.T) {
	oldGet := getNextTraceAPIV3WSConn
	oldPools := IPPools.pool
	oldRunning, oldRestart := nextTraceAPIV3ReceiveState()
	var closeOld, closeNew sync.Once
	var oldConn, newConn *wshandle.WsConn
	defer func() {
		if oldConn != nil {
			closeOld.Do(func() { close(oldConn.MsgReceiveCh) })
		}
		if newConn != nil {
			closeNew.Do(func() { close(newConn.MsgReceiveCh) })
		}
		waitForNextTraceAPIV3ReceiveStop(t)
		getNextTraceAPIV3WSConn = oldGet
		IPPools.pool = oldPools
		setNextTraceAPIV3ReceiveState(oldRunning, oldRestart)
	}()

	oldConn = &wshandle.WsConn{
		MsgReceiveCh: make(chan string),
		Interrupt:    make(chan os.Signal, 1),
	}
	newConn = &wshandle.WsConn{
		MsgReceiveCh: make(chan string),
		Interrupt:    make(chan os.Signal, 1),
	}
	afterOldClose := atomic.Bool{}
	afterOldCloseCalls := atomic.Int32{}
	getNextTraceAPIV3WSConn = func() *wshandle.WsConn {
		if afterOldClose.Load() {
			if afterOldCloseCalls.Add(1) == 1 {
				return oldConn
			}
			return newConn
		}
		return oldConn
	}

	oldResult := make(chan IPGeoData, 1)
	newResult := make(chan IPGeoData, 1)
	IPPools.pool = map[string]chan IPGeoData{
		"1.1.1.1": oldResult,
		"2.2.2.2": newResult,
	}
	setNextTraceAPIV3ReceiveState(false, false)

	startNextTraceAPIV3Receiver()
	select {
	case oldConn.MsgReceiveCh <- `{"ip":"1.1.1.1","asnumber":"13335"}`:
	case <-time.After(time.Second):
		t.Fatal("receiveNextTraceAPIV3Responses did not consume from the original websocket")
	}
	select {
	case geo := <-oldResult:
		if geo.Asnumber != "13335" {
			t.Fatalf("old websocket geo ASN = %q, want 13335", geo.Asnumber)
		}
	case <-time.After(time.Second):
		t.Fatal("receiveNextTraceAPIV3Responses did not dispatch original websocket data")
	}

	startNextTraceAPIV3Receiver()
	afterOldClose.Store(true)
	closeOld.Do(func() { close(oldConn.MsgReceiveCh) })

	select {
	case newConn.MsgReceiveCh <- `{"ip":"2.2.2.2","asnumber":"64512"}`:
	case <-time.After(time.Second):
		t.Fatal("receiveNextTraceAPIV3Responses did not restart for a queued start")
	}
	select {
	case geo := <-newResult:
		if geo.Asnumber != "64512" {
			t.Fatalf("new websocket geo ASN = %q, want 64512", geo.Asnumber)
		}
	case <-time.After(time.Second):
		t.Fatal("receiveNextTraceAPIV3Responses did not dispatch restarted websocket data")
	}

	closeNew.Do(func() { close(newConn.MsgReceiveCh) })
}

func TestSendNextTraceAPIV3IPRequestHonorsContextWhenQueueIsFull(t *testing.T) {
	oldGet := getNextTraceAPIV3WSConn
	defer func() { getNextTraceAPIV3WSConn = oldGet }()

	conn := &wshandle.WsConn{
		MsgSendCh: make(chan string, 1),
		Interrupt: make(chan os.Signal, 1),
	}
	conn.MsgSendCh <- "blocked"
	getNextTraceAPIV3WSConn = func() *wshandle.WsConn {
		return conn
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if sendNextTraceAPIV3IPRequest(ctx, conn, "1.1.1.1") {
		t.Fatal("sendNextTraceAPIV3IPRequest() = true, want false when context expires")
	}
}

func TestSendNextTraceAPIV3IPRequestUsesProvidedConnection(t *testing.T) {
	oldGet := getNextTraceAPIV3WSConn
	defer func() { getNextTraceAPIV3WSConn = oldGet }()

	conn := &wshandle.WsConn{
		MsgSendCh: make(chan string, 1),
		Interrupt: make(chan os.Signal, 1),
	}
	getNextTraceAPIV3WSConn = func() *wshandle.WsConn { return nil }

	if !sendNextTraceAPIV3IPRequest(context.Background(), conn, "1.1.1.1") {
		t.Fatal("sendNextTraceAPIV3IPRequest() = false, want true")
	}
	select {
	case got := <-conn.MsgSendCh:
		if got != "1.1.1.1" {
			t.Fatalf("sent IP = %q, want 1.1.1.1", got)
		}
	default:
		t.Fatal("provided connection did not receive request")
	}
}

func TestDispatchNextTraceAPIV3MessageReplacesStaleBufferedResponse(t *testing.T) {
	oldPools := IPPools.pool
	defer func() { IPPools.pool = oldPools }()

	ch := make(chan IPGeoData, 1)
	ch <- IPGeoData{Asnumber: "STALE"}
	IPPools.pool = map[string]chan IPGeoData{"1.1.1.1": ch}

	dispatchNextTraceAPIV3Message(`{"ip":"1.1.1.1","asnumber":"13335"}`)

	select {
	case geo := <-ch:
		if geo.Asnumber != "13335" {
			t.Fatalf("buffered geo ASN = %q, want latest response", geo.Asnumber)
		}
	default:
		t.Fatal("expected latest response to be buffered")
	}
}

func waitForNextTraceAPIV3ReceiveStart(t *testing.T, started <-chan struct{}) {
	t.Helper()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("waitForNextTraceAPIV3ReceiveStart: receiveNextTraceAPIV3Responses did not start")
	}
}

func waitForNextTraceAPIV3ReceiveStop(t *testing.T) {
	t.Helper()
	deadline := time.After(time.Second)
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		running, _ := nextTraceAPIV3ReceiveState()
		if !running {
			return
		}
		select {
		case <-deadline:
			t.Fatal("waitForNextTraceAPIV3ReceiveStop: receiveNextTraceAPIV3Responses did not stop")
		case <-ticker.C:
		}
	}
}

func nextTraceAPIV3ReceiveState() (bool, bool) {
	nextTraceAPIV3ReceiveMu.Lock()
	defer nextTraceAPIV3ReceiveMu.Unlock()
	return nextTraceAPIV3ReceiveRunning, nextTraceAPIV3ReceiveRestart
}

func setNextTraceAPIV3ReceiveState(running, restart bool) {
	nextTraceAPIV3ReceiveMu.Lock()
	defer nextTraceAPIV3ReceiveMu.Unlock()
	nextTraceAPIV3ReceiveRunning = running
	nextTraceAPIV3ReceiveRestart = restart
}
