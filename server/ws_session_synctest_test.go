package server

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/gorilla/websocket"
)

type wsSessionWritePlan struct {
	entered chan struct{}
	release <-chan struct{}
	err     error
}

type wsSessionCloseFrame struct {
	code   int
	reason string
}

type wsSessionTestConn struct {
	mu sync.Mutex

	writePlans chan wsSessionWritePlan
	readError  chan error
	closed     chan struct{}

	closeSignalOnce sync.Once
	readerStartOnce sync.Once
	readerExitOnce  sync.Once
	readerStarted   chan struct{}
	readerExited    chan struct{}

	writes               []wsEnvelope
	closeFrames          []wsSessionCloseFrame
	closeCalls           int
	activeWriters        int
	maxConcurrentWriters int
}

func newWSSessionTestConn() *wsSessionTestConn {
	return &wsSessionTestConn{
		writePlans:    make(chan wsSessionWritePlan, 8),
		readError:     make(chan error, 1),
		closed:        make(chan struct{}),
		readerStarted: make(chan struct{}),
		readerExited:  make(chan struct{}),
	}
}

func (c *wsSessionTestConn) planWrite(plan wsSessionWritePlan) {
	c.writePlans <- plan
}

func (c *wsSessionTestConn) failRead(err error) {
	c.readError <- err
}

func (c *wsSessionTestConn) beginWrite() {
	c.mu.Lock()
	c.activeWriters++
	if c.activeWriters > c.maxConcurrentWriters {
		c.maxConcurrentWriters = c.activeWriters
	}
	c.mu.Unlock()
}

func (c *wsSessionTestConn) endWrite() {
	c.mu.Lock()
	c.activeWriters--
	c.mu.Unlock()
}

func (c *wsSessionTestConn) WriteJSON(value interface{}) error {
	c.beginWrite()
	defer c.endWrite()

	var plan wsSessionWritePlan
	select {
	case plan = <-c.writePlans:
	default:
	}
	if plan.entered != nil {
		close(plan.entered)
	}
	if plan.release != nil {
		select {
		case <-plan.release:
		case <-c.closed:
			return io.ErrClosedPipe
		}
	}
	if plan.err != nil {
		return plan.err
	}

	payload, err := json.Marshal(value)
	if err != nil {
		return err
	}
	var envelope wsEnvelope
	if err := json.Unmarshal(payload, &envelope); err != nil {
		return err
	}

	c.mu.Lock()
	c.writes = append(c.writes, envelope)
	c.mu.Unlock()
	return nil
}

func (c *wsSessionTestConn) SetWriteDeadline(time.Time) error {
	c.beginWrite()
	defer c.endWrite()
	return nil
}

func (c *wsSessionTestConn) WriteControl(messageType int, data []byte, _ time.Time) error {
	c.beginWrite()
	defer c.endWrite()

	if messageType != websocket.CloseMessage {
		return nil
	}
	frame := wsSessionCloseFrame{}
	if len(data) >= 2 {
		frame.code = int(binary.BigEndian.Uint16(data[:2]))
		frame.reason = string(data[2:])
	}
	c.mu.Lock()
	c.closeFrames = append(c.closeFrames, frame)
	c.mu.Unlock()
	return nil
}

func (c *wsSessionTestConn) Close() error {
	c.mu.Lock()
	c.closeCalls++
	c.mu.Unlock()
	c.closeSignalOnce.Do(func() { close(c.closed) })
	return nil
}

func (c *wsSessionTestConn) NextReader() (messageType int, r io.Reader, err error) {
	c.readerStartOnce.Do(func() { close(c.readerStarted) })
	defer c.readerExitOnce.Do(func() { close(c.readerExited) })

	select {
	case err := <-c.readError:
		return 0, nil, err
	case <-c.closed:
		return 0, nil, io.EOF
	}
}

func (c *wsSessionTestConn) snapshot() ([]wsEnvelope, []wsSessionCloseFrame, int, int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]wsEnvelope(nil), c.writes...),
		append([]wsSessionCloseFrame(nil), c.closeFrames...),
		c.closeCalls,
		c.maxConcurrentWriters
}

func startBlockingWSTrace(session *wsTraceSession, release <-chan struct{}) (<-chan context.Context, <-chan struct{}) {
	started := make(chan context.Context, 1)
	exited := make(chan struct{})
	go func() {
		session.runTrace(func(ctx context.Context) {
			started <- ctx
			<-ctx.Done()
			if release != nil {
				<-release
			}
		})
		close(exited)
	}()
	return started, exited
}

func finishWSSessionAsync(session *wsTraceSession) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		session.finish()
		close(done)
	}()
	return done
}

func requireWSTestChannelOpen(t *testing.T, ch <-chan struct{}, name string) {
	t.Helper()
	select {
	case <-ch:
		t.Fatalf("%s closed too early", name)
	default:
	}
}

func requireWSTestChannelClosed(t *testing.T, ch <-chan struct{}, name string) {
	t.Helper()
	select {
	case <-ch:
	default:
		t.Fatalf("%s is still open", name)
	}
}

func requireWSTestEnvelopeTypes(t *testing.T, writes []wsEnvelope, want ...string) {
	t.Helper()
	if len(writes) != len(want) {
		t.Fatalf("writes = %#v, want envelope types %v", writes, want)
	}
	for i := range want {
		if writes[i].Type != want[i] {
			t.Fatalf("write %d type = %q, want %q (all writes: %#v)", i, writes[i].Type, want[i], writes)
		}
	}
}

func TestWSTraceSessionNormalFinishDrainsAndJoins(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		conn := newWSSessionTestConn()
		writeEntered := make(chan struct{})
		writeRelease := make(chan struct{})
		conn.planWrite(wsSessionWritePlan{entered: writeEntered, release: writeRelease})

		session := newWSTraceSession(t.Context(), conn, "en", 4)
		traceRelease := make(chan struct{})
		traceStarted, traceExited := startBlockingWSTrace(session, traceRelease)
		traceCtx := <-traceStarted
		<-conn.readerStarted

		for _, messageType := range []string{"start", "hop", "complete"} {
			if err := session.send(wsEnvelope{Type: messageType}); err != nil {
				t.Fatalf("send %q: %v", messageType, err)
			}
		}
		<-writeEntered

		finished := finishWSSessionAsync(session)
		synctest.Wait()
		requireWSTestChannelOpen(t, finished, "finish result")
		requireWSTestChannelOpen(t, traceExited, "trace worker")
		if err := traceCtx.Err(); err != nil {
			t.Fatalf("trace context canceled before normal drain completed: %v", err)
		}

		close(writeRelease)
		synctest.Wait()
		requireWSTestChannelOpen(t, finished, "finish result before trace joins")
		if !errors.Is(traceCtx.Err(), context.Canceled) {
			t.Fatalf("trace context error after drain = %v, want context.Canceled", traceCtx.Err())
		}
		close(traceRelease)
		<-finished
		synctest.Wait()

		requireWSTestChannelClosed(t, traceExited, "trace worker")
		requireWSTestChannelClosed(t, conn.readerExited, "reader")
		writes, frames, closeCalls, maxWriters := conn.snapshot()
		requireWSTestEnvelopeTypes(t, writes, "start", "hop", "complete")
		if len(frames) != 0 {
			t.Fatalf("normal finish wrote close frames: %#v", frames)
		}
		if closeCalls != 1 {
			t.Fatalf("Close calls = %d, want 1", closeCalls)
		}
		if maxWriters != 1 {
			t.Fatalf("maximum concurrent writers = %d, want 1", maxWriters)
		}
	})
}

func TestWSTraceSessionAbnormalTerminationDiscardsQueuedMessages(t *testing.T) {
	tests := []struct {
		name       string
		trigger    string
		wantCode   int
		wantReason string
	}{
		{name: "slow consumer", trigger: "slow", wantCode: websocket.CloseTryAgainLater, wantReason: "client too slow for mtr stream"},
		{name: "reader error", trigger: "reader", wantCode: websocket.CloseNormalClosure, wantReason: "client disconnected"},
		{name: "writer error", trigger: "writer", wantCode: websocket.CloseInternalServerErr, wantReason: "write failed"},
		{name: "parent cancellation", trigger: "parent"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				parent, cancelParent := context.WithCancel(t.Context())
				defer cancelParent()
				conn := newWSSessionTestConn()
				writeEntered := make(chan struct{})
				writeRelease := make(chan struct{})
				releaseWrite := sync.OnceFunc(func() { close(writeRelease) })
				defer releaseWrite()
				writeErr := error(nil)
				if test.trigger == "writer" {
					writeErr = errors.New("scripted write failure")
				}
				conn.planWrite(wsSessionWritePlan{entered: writeEntered, release: writeRelease, err: writeErr})

				session := newWSTraceSession(parent, conn, "en", 1)
				traceStarted, traceExited := startBlockingWSTrace(session, nil)
				traceCtx := <-traceStarted
				<-conn.readerStarted

				if err := session.send(wsEnvelope{Type: "in_flight"}); err != nil {
					t.Fatalf("send in-flight message: %v", err)
				}
				<-writeEntered
				if err := session.send(wsEnvelope{Type: "queued"}); err != nil {
					t.Fatalf("send queued message: %v", err)
				}

				switch test.trigger {
				case "slow":
					err := session.send(wsEnvelope{Type: "overflow"})
					if !errors.Is(err, errWSSlowConsumer) {
						t.Fatalf("overflow error = %v, want errWSSlowConsumer", err)
					}
				case "reader":
					conn.failRead(errors.New("scripted read failure"))
				case "writer":
					releaseWrite()
				case "parent":
					cancelParent()
				default:
					t.Fatalf("unknown trigger %q", test.trigger)
				}

				synctest.Wait()
				if !errors.Is(traceCtx.Err(), context.Canceled) {
					t.Fatalf("trace context error = %v, want context.Canceled", traceCtx.Err())
				}
				requireWSTestChannelClosed(t, traceExited, "trace worker")

				finished := finishWSSessionAsync(session)
				if test.trigger != "writer" {
					synctest.Wait()
					requireWSTestChannelOpen(t, finished, "finish result before in-flight write exits")
					releaseWrite()
				}
				<-finished
				synctest.Wait()

				if err := session.send(wsEnvelope{Type: "after_close"}); !errors.Is(err, errWSSessionClosed) {
					t.Fatalf("send after termination = %v, want errWSSessionClosed", err)
				}
				requireWSTestChannelClosed(t, conn.readerExited, "reader")
				writes, frames, closeCalls, maxWriters := conn.snapshot()
				if test.trigger == "writer" {
					requireWSTestEnvelopeTypes(t, writes)
				} else {
					requireWSTestEnvelopeTypes(t, writes, "in_flight")
				}
				if test.wantCode == 0 {
					if len(frames) != 0 {
						t.Fatalf("parent cancellation wrote close frames: %#v", frames)
					}
				} else if len(frames) != 1 || frames[0].code != test.wantCode || frames[0].reason != test.wantReason {
					t.Fatalf("close frames = %#v, want one code=%d reason=%q", frames, test.wantCode, test.wantReason)
				}
				if closeCalls != 1 {
					t.Fatalf("Close calls = %d, want 1", closeCalls)
				}
				if maxWriters != 1 {
					t.Fatalf("maximum concurrent writers = %d, want 1", maxWriters)
				}
			})
		})
	}
}

func TestWSTraceSessionSerializesDataAndCloseWrites(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		conn := newWSSessionTestConn()
		writeEntered := make(chan struct{})
		writeRelease := make(chan struct{})
		conn.planWrite(wsSessionWritePlan{entered: writeEntered, release: writeRelease})

		session := newWSTraceSession(t.Context(), conn, "en", 2)
		if err := session.send(wsEnvelope{Type: "in_flight"}); err != nil {
			t.Fatalf("send: %v", err)
		}
		<-writeEntered

		session.closeWithCode(websocket.CloseInternalServerErr, "forced close")
		synctest.Wait()
		_, frames, _, maxWriters := conn.snapshot()
		if len(frames) != 0 {
			t.Fatalf("close control overtook blocked data write: %#v", frames)
		}
		if maxWriters != 1 {
			t.Fatalf("maximum concurrent writers while blocked = %d, want 1", maxWriters)
		}

		finished := finishWSSessionAsync(session)
		close(writeRelease)
		<-finished
		synctest.Wait()

		writes, frames, closeCalls, maxWriters := conn.snapshot()
		requireWSTestEnvelopeTypes(t, writes, "in_flight")
		if len(frames) != 1 || frames[0].code != websocket.CloseInternalServerErr || frames[0].reason != "forced close" {
			t.Fatalf("close frames = %#v, want one serialized forced-close frame", frames)
		}
		if closeCalls != 1 {
			t.Fatalf("Close calls = %d, want 1", closeCalls)
		}
		if maxWriters != 1 {
			t.Fatalf("maximum concurrent writers = %d, want 1", maxWriters)
		}
	})
}

func TestWSTraceSessionConcurrentFinishAndCloseIsIdempotent(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		conn := newWSSessionTestConn()
		writeEntered := make(chan struct{})
		writeRelease := make(chan struct{})
		conn.planWrite(wsSessionWritePlan{entered: writeEntered, release: writeRelease})

		session := newWSTraceSession(t.Context(), conn, "en", 2)
		if err := session.send(wsEnvelope{Type: "in_flight"}); err != nil {
			t.Fatalf("send in-flight: %v", err)
		}
		<-writeEntered
		if err := session.send(wsEnvelope{Type: "queued"}); err != nil {
			t.Fatalf("send queued: %v", err)
		}

		start := make(chan struct{})
		var callers sync.WaitGroup
		for range 4 {
			callers.Go(func() {
				<-start
				session.finish()
			})
			callers.Go(func() {
				<-start
				session.closeWithCode(websocket.CloseTryAgainLater, "forced race")
			})
		}
		close(start)
		synctest.Wait()
		close(writeRelease)
		callers.Wait()
		synctest.Wait()

		writes, frames, closeCalls, maxWriters := conn.snapshot()
		if len(frames) == 0 {
			requireWSTestEnvelopeTypes(t, writes, "in_flight", "queued")
		} else {
			if len(frames) != 1 || frames[0].code != websocket.CloseTryAgainLater || frames[0].reason != "forced race" {
				t.Fatalf("close frames = %#v, want one forced-race frame", frames)
			}
			requireWSTestEnvelopeTypes(t, writes, "in_flight")
		}
		if closeCalls != 1 {
			t.Fatalf("Close calls = %d, want 1", closeCalls)
		}
		if maxWriters != 1 {
			t.Fatalf("maximum concurrent writers = %d, want 1", maxWriters)
		}

		session.finish()
		session.closeWithCode(websocket.CloseInternalServerErr, "late close")
		_, framesAfter, closeCallsAfter, _ := conn.snapshot()
		if len(framesAfter) != len(frames) || closeCallsAfter != closeCalls {
			t.Fatalf("late termination changed close calls/frames: before=(%d,%d) after=(%d,%d)", closeCalls, len(frames), closeCallsAfter, len(framesAfter))
		}
	})
}
