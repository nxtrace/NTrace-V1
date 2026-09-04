package ipgeo

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/nxtrace/NTrace-core/wshandle"
)

func TestNextTraceAPIV3ReceiverOwnerConcurrentEnsureUsesOneConsumer(t *testing.T) {
	owner := newNextTraceAPIV3ReceiverOwner()
	receiveCh := make(chan string)
	conn := &wshandle.WsConn{MsgReceiveCh: receiveCh}

	const callers = 64
	receivers := make([]*nextTraceAPIV3Receiver, callers)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range receivers {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			<-start
			receivers[index] = owner.ensure(conn)
		}(i)
	}
	close(start)
	wg.Wait()

	first := receivers[0]
	if first == nil {
		t.Fatal("ensure() receiver = nil")
	}
	for i, receiver := range receivers[1:] {
		if receiver != first {
			t.Fatalf("ensure() receiver[%d] = %p, want %p", i+1, receiver, first)
		}
	}
	if got := nextTraceAPIV3ReceiverCount(owner); got != 1 {
		t.Fatalf("receiver count = %d, want 1", got)
	}

	close(receiveCh)
	waitForNextTraceAPIV3ReceiverDone(t, first)
	if got := nextTraceAPIV3ReceiverCount(owner); got != 0 {
		t.Fatalf("receiver count after close = %d, want 0", got)
	}
}

func TestNextTraceAPIV3ReceiverOwnerDeduplicatesSharedChannelWrappers(t *testing.T) {
	owner := newNextTraceAPIV3ReceiverOwner()
	receiveCh := make(chan string)
	firstConn := &wshandle.WsConn{MsgReceiveCh: receiveCh}
	secondConn := &wshandle.WsConn{MsgReceiveCh: receiveCh}

	first := owner.ensure(firstConn)
	second := owner.ensure(secondConn)
	if first == nil || second != first {
		t.Fatalf("shared channel receivers = (%p, %p), want one receiver", first, second)
	}
	if got := nextTraceAPIV3ReceiverCount(owner); got != 1 {
		t.Fatalf("receiver count = %d, want 1", got)
	}

	close(receiveCh)
	waitForNextTraceAPIV3ReceiverDone(t, first)
}

func TestNextTraceAPIV3ReceiverOwnerKeepsOldAndNewChannelsDuringHandoff(t *testing.T) {
	owner := newNextTraceAPIV3ReceiverOwner()
	oldReceiveCh := make(chan string, 1)
	newReceiveCh := make(chan string, 1)
	oldConn := &wshandle.WsConn{MsgReceiveCh: oldReceiveCh}
	newConn := &wshandle.WsConn{MsgReceiveCh: newReceiveCh}
	oldReceiver := owner.ensure(oldConn)
	newReceiver := owner.ensure(newConn)
	if oldReceiver == nil || newReceiver == nil || oldReceiver == newReceiver {
		t.Fatalf("handoff receivers = (%p, %p), want distinct receivers", oldReceiver, newReceiver)
	}
	if got := nextTraceAPIV3ReceiverCount(owner); got != 2 {
		t.Fatalf("receiver count during handoff = %d, want 2", got)
	}

	oldResult := make(chan IPGeoData, 1)
	newResult := make(chan IPGeoData, 1)
	restorePool := replaceNextTraceAPIV3Pool(map[string]chan IPGeoData{
		"1.1.1.1": oldResult,
		"2.2.2.2": newResult,
	})
	defer restorePool()

	oldReceiveCh <- `{"ip":"1.1.1.1","asnumber":"13335"}`
	assertNextTraceAPIV3ASN(t, oldResult, "13335")
	if !oldConn.ConnMux.TryLock() {
		t.Fatal("receiver holds compatibility ConnMux while waiting for messages")
	}
	oldConn.ConnMux.Unlock()

	close(oldReceiveCh)
	waitForNextTraceAPIV3ReceiverDone(t, oldReceiver)
	if got := nextTraceAPIV3ReceiverCount(owner); got != 1 {
		t.Fatalf("receiver count after old close = %d, want 1", got)
	}

	newReceiveCh <- `{"ip":"2.2.2.2","asnumber":"64512"}`
	assertNextTraceAPIV3ASN(t, newResult, "64512")
	close(newReceiveCh)
	waitForNextTraceAPIV3ReceiverDone(t, newReceiver)
}

func TestNextTraceAPIV3GeoIPBindsReceiverAndSendToSelectedConnection(t *testing.T) {
	owner := newNextTraceAPIV3ReceiverOwner()
	oldConn := &wshandle.WsConn{
		MsgSendCh:    make(chan string, 1),
		MsgReceiveCh: make(chan string, 1),
	}
	newConn := &wshandle.WsConn{
		MsgSendCh:    make(chan string, 1),
		MsgReceiveCh: make(chan string, 1),
	}
	oldConn.SetConnected(true)
	newConn.SetConnected(true)

	var getCalls atomic.Int32
	restoreGlobals := replaceNextTraceAPIV3Globals(owner, func() *wshandle.WsConn {
		if getCalls.Add(1) == 1 {
			return oldConn
		}
		return newConn
	}, make(map[string]chan IPGeoData))
	defer func() {
		oldReceiver := nextTraceAPIV3ReceiverFor(owner, oldConn.MsgReceiveCh)
		close(oldConn.MsgReceiveCh)
		if oldReceiver != nil {
			waitForNextTraceAPIV3ReceiverDone(t, oldReceiver)
		}
		close(newConn.MsgReceiveCh)
		restoreGlobals()
	}()

	type result struct {
		geo *IPGeoData
		err error
	}
	done := make(chan result, 1)
	go func() {
		geo, err := NextTraceAPIV3GeoIP("1.1.1.1", 2*time.Second, "en", false)
		done <- result{geo: geo, err: err}
	}()

	select {
	case ip := <-oldConn.MsgSendCh:
		if ip != "1.1.1.1" {
			t.Fatalf("old connection request = %q, want 1.1.1.1", ip)
		}
		if nextTraceAPIV3ReceiverFor(owner, oldConn.MsgReceiveCh) == nil {
			t.Fatal("request was sent before its selected receive channel was ensured")
		}
	case <-time.After(time.Second):
		t.Fatal("selected old connection did not receive request")
	}
	select {
	case ip := <-newConn.MsgSendCh:
		t.Fatalf("replacement connection unexpectedly received request %q", ip)
	default:
	}

	oldConn.MsgReceiveCh <- `{"ip":"1.1.1.1","asnumber":"13335"}`
	select {
	case got := <-done:
		if got.err != nil {
			t.Fatalf("NextTraceAPIV3GeoIP() error = %v", got.err)
		}
		if got.geo == nil || got.geo.Asnumber != "13335" {
			t.Fatalf("NextTraceAPIV3GeoIP() geo = %+v, want ASN 13335", got.geo)
		}
	case <-time.After(time.Second):
		t.Fatal("NextTraceAPIV3GeoIP() did not receive response from selected connection")
	}
	if got := getCalls.Load(); got != 1 {
		t.Fatalf("GetWsConn calls = %d, want 1", got)
	}
	if nextTraceAPIV3ReceiverFor(owner, newConn.MsgReceiveCh) != nil {
		t.Fatal("replacement connection unexpectedly gained a receiver")
	}
}

func TestNextTraceAPIV3GeoIPIgnoresOldConnectionResponseAfterBoundSubmit(t *testing.T) {
	owner := newNextTraceAPIV3ReceiverOwner()
	oldConn := &wshandle.WsConn{MsgReceiveCh: make(chan string, 1)}
	newConn := &wshandle.WsConn{MsgReceiveCh: make(chan string, 1)}
	newConn.SetConnected(true)
	responseCh := make(chan IPGeoData, 1)
	restoreGlobals := replaceNextTraceAPIV3Globals(
		owner,
		func() *wshandle.WsConn { return newConn },
		map[string]chan IPGeoData{"1.1.1.1": responseCh},
	)
	oldReceiver := owner.ensure(oldConn)
	if oldReceiver == nil {
		t.Fatal("old connection receiver = nil")
	}

	oldRequestFn := requestNextTraceAPIV3IPFn
	oldSendFn := sendNextTraceAPIV3IPRequestFn
	var fallbackSendCalled atomic.Bool
	submitted := make(chan struct{})
	boundResponse := make(chan string, 1)
	requestNextTraceAPIV3IPFn = func(ctx context.Context, conn *wshandle.WsConn, ip string) (string, error) {
		if conn != newConn || ip != "1.1.1.1" {
			t.Errorf("bound request = (%p, %q), want (%p, 1.1.1.1)", conn, ip, newConn)
		}
		close(submitted)
		select {
		case response := <-boundResponse:
			return response, nil
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
	sendNextTraceAPIV3IPRequestFn = func(context.Context, *wshandle.WsConn, string) bool {
		fallbackSendCalled.Store(true)
		return false
	}
	defer func() {
		requestNextTraceAPIV3IPFn = oldRequestFn
		sendNextTraceAPIV3IPRequestFn = oldSendFn
		close(oldConn.MsgReceiveCh)
		waitForNextTraceAPIV3ReceiverDone(t, oldReceiver)
		newReceiver := nextTraceAPIV3ReceiverFor(owner, newConn.MsgReceiveCh)
		close(newConn.MsgReceiveCh)
		if newReceiver != nil {
			waitForNextTraceAPIV3ReceiverDone(t, newReceiver)
		}
		restoreGlobals()
	}()

	type result struct {
		geo *IPGeoData
		err error
	}
	done := make(chan result, 1)
	go func() {
		geo, err := NextTraceAPIV3GeoIP("1.1.1.1", 2*time.Second, "en", false)
		done <- result{geo: geo, err: err}
	}()

	select {
	case <-submitted:
	case <-time.After(time.Second):
		t.Fatal("new connection request was not submitted")
	}

	oldConn.MsgReceiveCh <- `{"ip":"1.1.1.1","asnumber":"OLD"}`
	var oldGeo IPGeoData
	select {
	case oldGeo = <-responseCh:
		if oldGeo.Asnumber != "OLD" {
			t.Fatalf("old response ASN = %q, want OLD", oldGeo.Asnumber)
		}
	case <-time.After(time.Second):
		t.Fatal("old connection response did not reach the compatibility pool")
	}
	responseCh <- oldGeo
	select {
	case got := <-done:
		t.Fatalf("old connection response completed bound request: %+v", got)
	default:
	}

	boundResponse <- `{"ip":"1.1.1.1","asnumber":"NEW"}`
	select {
	case got := <-done:
		if got.err != nil {
			t.Fatalf("NextTraceAPIV3GeoIP() error = %v", got.err)
		}
		if got.geo == nil || got.geo.Asnumber != "NEW" {
			t.Fatalf("NextTraceAPIV3GeoIP() geo = %+v, want ASN NEW", got.geo)
		}
	case <-time.After(time.Second):
		t.Fatal("bound response did not complete the new connection request")
	}
	if fallbackSendCalled.Load() {
		t.Fatal("managed request fell back to the generationless send path")
	}
}

func TestNextTraceAPIV3GeoIPRejectsSelectedConnectionClosedBeforeSubmit(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		owner := newNextTraceAPIV3ReceiverOwner()
		oldConn := &wshandle.WsConn{
			MsgSendCh:    make(chan string, 1),
			MsgReceiveCh: make(chan string, 1),
		}
		newConn := &wshandle.WsConn{
			MsgSendCh:    make(chan string, 1),
			MsgReceiveCh: make(chan string, 1),
		}
		oldConn.SetConnected(true)
		newConn.SetConnected(true)

		var current atomic.Pointer[wshandle.WsConn]
		current.Store(oldConn)
		restoreGlobals := replaceNextTraceAPIV3Globals(
			owner,
			func() *wshandle.WsConn { return current.Load() },
			make(map[string]chan IPGeoData),
		)
		oldSendFn := sendNextTraceAPIV3IPRequestFn
		reachedSubmit := make(chan struct{})
		releaseSubmit := make(chan struct{})
		sendNextTraceAPIV3IPRequestFn = func(ctx context.Context, conn *wshandle.WsConn, ip string) bool {
			close(reachedSubmit)
			<-releaseSubmit
			return sendNextTraceAPIV3IPRequest(ctx, conn, ip)
		}
		defer func() {
			sendNextTraceAPIV3IPRequestFn = oldSendFn
			newConn.Close()
			restoreGlobals()
		}()

		type result struct {
			geo *IPGeoData
			err error
		}
		startedAt := time.Now()
		done := make(chan result, 1)
		go func() {
			geo, err := NextTraceAPIV3GeoIP("1.1.1.1", time.Millisecond, "en", false)
			done <- result{geo: geo, err: err}
		}()

		<-reachedSubmit
		receiver := nextTraceAPIV3ReceiverFor(owner, oldConn.MsgReceiveCh)
		if receiver == nil {
			t.Fatal("selected connection receiver was not ensured before submit")
		}
		current.Store(newConn)
		oldConn.Close()
		close(releaseSubmit)
		synctest.Wait()

		got := <-done
		if got.err == nil || got.err.Error() != "TimeOut" {
			t.Fatalf("NextTraceAPIV3GeoIP() error = %v, want TimeOut", got.err)
		}
		if got.geo == nil || got.geo.Asnumber != "" || got.geo.IP != "" {
			t.Fatalf("NextTraceAPIV3GeoIP() geo = %+v, want empty result", got.geo)
		}
		if elapsed := time.Since(startedAt); elapsed != 0 {
			t.Fatalf("closed selected connection consumed timeout budget: %s", elapsed)
		}
		select {
		case msg := <-oldConn.MsgSendCh:
			t.Fatalf("closed old connection accepted request %q", msg)
		default:
		}
		select {
		case msg := <-newConn.MsgSendCh:
			t.Fatalf("replacement connection unexpectedly accepted request %q", msg)
		default:
		}
		<-receiver.done
	})
}

func TestNextTraceAPIV3GeoIPWaitsForConnectionBeforeSending(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		owner := newNextTraceAPIV3ReceiverOwner()
		conn := &wshandle.WsConn{
			MsgSendCh:    make(chan string, 1),
			MsgReceiveCh: make(chan string, 1),
		}
		restoreGlobals := replaceNextTraceAPIV3Globals(
			owner,
			func() *wshandle.WsConn { return conn },
			make(map[string]chan IPGeoData),
		)
		defer func() {
			receiver := nextTraceAPIV3ReceiverFor(owner, conn.MsgReceiveCh)
			close(conn.MsgReceiveCh)
			if receiver != nil {
				<-receiver.done
			}
			restoreGlobals()
		}()

		type result struct {
			geo *IPGeoData
			err error
		}
		done := make(chan result, 1)
		go func() {
			geo, err := NextTraceAPIV3GeoIP("1.1.1.1", time.Millisecond, "en", false)
			done <- result{geo: geo, err: err}
		}()
		synctest.Wait()

		select {
		case ip := <-conn.MsgSendCh:
			t.Fatalf("request %q sent before connection became ready", ip)
		default:
		}
		time.Sleep(time.Second)
		synctest.Wait()
		select {
		case ip := <-conn.MsgSendCh:
			t.Fatalf("request %q sent before connection became ready", ip)
		default:
		}

		conn.SetConnected(true)
		synctest.Wait()
		select {
		case ip := <-conn.MsgSendCh:
			if ip != "1.1.1.1" {
				t.Fatalf("request = %q, want 1.1.1.1", ip)
			}
		default:
			t.Fatal("request not sent after connection became ready")
		}
		conn.MsgReceiveCh <- `{"ip":"1.1.1.1","asnumber":"13335"}`
		synctest.Wait()
		got := <-done
		if got.err != nil {
			t.Fatalf("NextTraceAPIV3GeoIP() error = %v", got.err)
		}
		if got.geo == nil || got.geo.Asnumber != "13335" {
			t.Fatalf("NextTraceAPIV3GeoIP() geo = %+v, want ASN 13335", got.geo)
		}
	})
}

func TestNextTraceAPIV3GeoIPUsesSingleMinimumTimeoutBudget(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		owner := newNextTraceAPIV3ReceiverOwner()
		conn := &wshandle.WsConn{
			MsgSendCh:    make(chan string, 1),
			MsgReceiveCh: make(chan string),
		}
		restoreGlobals := replaceNextTraceAPIV3Globals(
			owner,
			func() *wshandle.WsConn { return conn },
			make(map[string]chan IPGeoData),
		)
		defer func() {
			receiver := nextTraceAPIV3ReceiverFor(owner, conn.MsgReceiveCh)
			close(conn.MsgReceiveCh)
			if receiver != nil {
				<-receiver.done
			}
			restoreGlobals()
		}()

		started := time.Now()
		done := make(chan error, 1)
		go func() {
			_, err := NextTraceAPIV3GeoIP("1.1.1.1", time.Millisecond, "en", false)
			done <- err
		}()
		synctest.Wait()

		time.Sleep(1500 * time.Millisecond)
		conn.SetConnected(true)
		synctest.Wait()
		select {
		case ip := <-conn.MsgSendCh:
			if ip != "1.1.1.1" {
				t.Fatalf("request = %q, want 1.1.1.1", ip)
			}
		default:
			t.Fatal("request not sent after connection became ready")
		}

		time.Sleep(500 * time.Millisecond)
		synctest.Wait()
		if err := <-done; err == nil || err.Error() != "TimeOut" {
			t.Fatalf("NextTraceAPIV3GeoIP() error = %v, want TimeOut", err)
		}
		if elapsed := time.Since(started); elapsed != 2*time.Second {
			t.Fatalf("NextTraceAPIV3GeoIP() elapsed = %s, want 2s", elapsed)
		}
	})
}

func TestNextTraceAPIV3GeoIPReturnsTimeOutWhenWebsocketMissing(t *testing.T) {
	owner := newNextTraceAPIV3ReceiverOwner()
	restoreGlobals := replaceNextTraceAPIV3Globals(
		owner,
		func() *wshandle.WsConn { return nil },
		make(map[string]chan IPGeoData),
	)
	defer restoreGlobals()

	_, err := NextTraceAPIV3GeoIP("1.1.1.1", time.Millisecond, "en", false)
	if err == nil || err.Error() != "TimeOut" {
		t.Fatalf("NextTraceAPIV3GeoIP() error = %v, want TimeOut", err)
	}
	if got := nextTraceAPIV3ReceiverCount(owner); got != 0 {
		t.Fatalf("receiver count = %d, want 0", got)
	}
}

func TestNextTraceAPIV3APIErrorDeliveredOnce(t *testing.T) {
	owner := newNextTraceAPIV3ReceiverOwner()
	conn := &wshandle.WsConn{
		MsgSendCh:    make(chan string, 1),
		MsgReceiveCh: make(chan string, 1),
	}
	conn.SetConnected(true)
	restoreGlobals := replaceNextTraceAPIV3Globals(
		owner,
		func() *wshandle.WsConn { return conn },
		make(map[string]chan IPGeoData),
	)
	defer func() {
		receiver := nextTraceAPIV3ReceiverFor(owner, conn.MsgReceiveCh)
		close(conn.MsgReceiveCh)
		if receiver != nil {
			waitForNextTraceAPIV3ReceiverDone(t, receiver)
		}
		restoreGlobals()
	}()

	done := make(chan struct {
		geo *IPGeoData
		err error
	}, 1)
	go func() {
		geo, err := NextTraceAPIV3GeoIP("1.1.1.1", 2*time.Second, "en", false)
		done <- struct {
			geo *IPGeoData
			err error
		}{geo: geo, err: err}
	}()

	select {
	case <-conn.MsgSendCh:
	case <-time.After(time.Second):
		t.Fatal("request was not sent")
	}
	conn.MsgReceiveCh <- `{"ip":"1.1.1.1","asnumber":"API Server Error"}`
	got := <-done
	if got.err != nil {
		t.Fatalf("NextTraceAPIV3GeoIP() error = %v", got.err)
	}
	if got.geo == nil || got.geo.Asnumber != "API Server Error" {
		t.Fatalf("NextTraceAPIV3GeoIP() geo = %+v, want API Server Error", got.geo)
	}

	IPPools.poolMux.RLock()
	responseCh := IPPools.pool["1.1.1.1"]
	IPPools.poolMux.RUnlock()
	select {
	case duplicate := <-responseCh:
		t.Fatalf("duplicate API error delivery = %+v", duplicate)
	default:
	}
}

func TestSendNextTraceAPIV3IPRequestHonorsContextWhenQueueIsFull(t *testing.T) {
	conn := &wshandle.WsConn{MsgSendCh: make(chan string, 1)}
	conn.MsgSendCh <- "blocked"
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if sendNextTraceAPIV3IPRequest(ctx, conn, "1.1.1.1") {
		t.Fatal("sendNextTraceAPIV3IPRequest() = true, want false when context expires")
	}
}

func TestSendNextTraceAPIV3IPRequestUsesProvidedConnection(t *testing.T) {
	conn := &wshandle.WsConn{MsgSendCh: make(chan string, 1)}
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
	ch := make(chan IPGeoData, 1)
	ch <- IPGeoData{Asnumber: "STALE"}
	restorePool := replaceNextTraceAPIV3Pool(map[string]chan IPGeoData{"1.1.1.1": ch})
	defer restorePool()

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

func replaceNextTraceAPIV3Globals(
	owner *nextTraceAPIV3ReceiverOwner,
	getConn func() *wshandle.WsConn,
	pool map[string]chan IPGeoData,
) func() {
	oldOwner := nextTraceAPIV3Receivers
	oldGetConn := getNextTraceAPIV3WSConn
	nextTraceAPIV3Receivers = owner
	getNextTraceAPIV3WSConn = getConn
	restorePool := replaceNextTraceAPIV3Pool(pool)
	return func() {
		restorePool()
		getNextTraceAPIV3WSConn = oldGetConn
		nextTraceAPIV3Receivers = oldOwner
	}
}

func replaceNextTraceAPIV3Pool(pool map[string]chan IPGeoData) func() {
	IPPools.poolMux.Lock()
	oldPool := IPPools.pool
	IPPools.pool = pool
	IPPools.poolMux.Unlock()
	return func() {
		IPPools.poolMux.Lock()
		IPPools.pool = oldPool
		IPPools.poolMux.Unlock()
	}
}

func nextTraceAPIV3ReceiverFor(owner *nextTraceAPIV3ReceiverOwner, ch <-chan string) *nextTraceAPIV3Receiver {
	owner.mu.Lock()
	defer owner.mu.Unlock()
	return owner.receivers[ch]
}

func nextTraceAPIV3ReceiverCount(owner *nextTraceAPIV3ReceiverOwner) int {
	owner.mu.Lock()
	defer owner.mu.Unlock()
	return len(owner.receivers)
}

func waitForNextTraceAPIV3ReceiverDone(t *testing.T, receiver *nextTraceAPIV3Receiver) {
	t.Helper()
	select {
	case <-receiver.done:
	case <-time.After(time.Second):
		t.Fatal("NextTrace API v3 receiver did not stop")
	}
}

func assertNextTraceAPIV3ASN(t *testing.T, ch <-chan IPGeoData, want string) {
	t.Helper()
	select {
	case geo := <-ch:
		if geo.Asnumber != want {
			t.Fatalf("geo ASN = %q, want %q", geo.Asnumber, want)
		}
	case <-time.After(time.Second):
		t.Fatalf("timed out waiting for ASN %q", want)
	}
}
