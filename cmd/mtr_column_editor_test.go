package cmd

import (
	"context"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nxtrace/NTrace-core/printer"
	"github.com/nxtrace/NTrace-core/trace"
)

func feedMTRKeys(u *mtrUI, k *mtrKeyInput, text string) {
	for _, b := range []byte(text) {
		k.feed(u, b, time.Now())
	}
}

func TestMTRColumnEditorApplyCancelAndIsolation(t *testing.T) {
	u := newMTRUI(nil, 0)
	u.paused.Store(true)
	u.historyMode.Store(true)
	var k mtrKeyInput
	feedMTRKeys(u, &k, "O")
	_, e := u.columnSnapshot()
	if !e.Active || e.Draft != "LSNABWV" {
		t.Fatal(e)
	}
	feedMTRKeys(u, &k, "\x15qprynedgo ")
	if !u.IsPaused() || u.ConsumeRestartRequest() || u.CurrentDisplayMode() != 0 || u.CurrentNameMode() != 0 || !u.IsHistoryMode() || u.IsMPLSDisabled() {
		t.Fatal("shortcut leaked")
	}
	feedMTRKeys(u, &k, "\r")
	_, e = u.columnSnapshot()
	if !e.Active || e.Error == "" {
		t.Fatal("invalid input applied")
	}
	feedMTRKeys(u, &k, "\x15rL\x7f n\r")
	c, e := u.columnSnapshot()
	if e.Active || printer.MTRColumnCodes(c) != "RN" || u.IsHistoryMode() || !u.IsPaused() {
		t.Fatalf("%v %+v", c, e)
	}
	// Invalid/duplicate/empty drafts stay open, cancellation preserves applied columns and view.
	u.historyMode.Store(true)
	for _, draft := range []string{"", "ll", "?"} {
		feedMTRKeys(u, &k, "o\x15"+draft+"\r")
		_, e = u.columnSnapshot()
		if !e.Active || e.Error == "" {
			t.Fatal(e)
		}
		feedMTRKeys(u, &k, "\x1b")
		k.expireEscape(u, time.Now().Add(mtrEscapeDelay))
		c, e = u.columnSnapshot()
		if e.Active || printer.MTRColumnCodes(c) != "RN" || !u.IsHistoryMode() {
			t.Fatal("cancel changed state")
		}
	}
	// Returned selection is isolated from callers.
	c[0] = printer.MTRColumnLoss
	c, _ = u.columnSnapshot()
	if printer.MTRColumnCodes(c) != "RN" {
		t.Fatal("snapshot aliases state")
	}
}

func TestMTRColumnEditorEscapePasteAndLimit(t *testing.T) {
	u := newMTRUI(nil, 0)
	var k mtrKeyInput
	feedMTRKeys(u, &k, "o\x15")
	now := time.Now()
	k.feed(u, 27, now)
	k.expireEscape(u, now.Add(49*time.Millisecond))
	k.feed(u, '[', now.Add(49*time.Millisecond))
	k.feed(u, 'A', now.Add(60*time.Millisecond))
	_, e := u.columnSnapshot()
	if !e.Active || e.Draft != "" {
		t.Fatal("arrow cancelled editor")
	}
	// Arbitrarily split paste wrappers; embedded newline never submits.
	for _, part := range []string{"\x1b[2", "00~", "r\n", " n\r\nl", "\x1b[20", "1~"} {
		feedMTRKeys(u, &k, part)
	}
	_, e = u.columnSnapshot()
	if !e.Active || e.Draft != "r  n  l" {
		t.Fatal(e)
	}
	feedMTRKeys(u, &k, "\r")
	c, e := u.columnSnapshot()
	if e.Active || printer.MTRColumnCodes(c) != "RNL" {
		t.Fatal(c, e)
	}
	feedMTRKeys(u, &k, "o\x15"+strings.Repeat("a", 300))
	_, e = u.columnSnapshot()
	if len(e.Draft) != 256 || e.Error == "" {
		t.Fatal(e)
	}
	feedMTRKeys(u, &k, "\x08")
	_, e = u.columnSnapshot()
	if len(e.Draft) != 255 {
		t.Fatal(e)
	}
	var cancelled bool
	u.cancel = func() { cancelled = true }
	feedMTRKeys(u, &k, "\x1b[200~\x03")
	if !cancelled {
		t.Fatal("paste swallowed Ctrl-C")
	}
}

func TestMTRKeyLoopCancelWhileReadBlocked(t *testing.T) {
	r, w := io.Pipe()
	defer func() { _ = r.Close() }()
	defer func() { _ = w.Close() }()
	ctx, cancel := context.WithCancel(context.Background())
	u := newMTRUI(cancel, 0)
	done := make(chan struct{})
	go func() { u.readKeysLoop(ctx, r); close(done) }()
	_, _ = w.Write([]byte("o\x1b"))
	time.Sleep(75 * time.Millisecond)
	_, e := u.columnSnapshot()
	if e.Active {
		t.Fatal("bare Esc did not cancel without another read")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("key loop did not stop")
	}
}

func TestMTRRedrawInitialPausedResizeAndCleanup(t *testing.T) {
	u := newMTRUI(nil, 0)
	u.paused.Store(true)
	var width atomic.Int32
	width.Store(80)
	var renders atomic.Int32
	frames := make(chan string, 100)
	snapshot, stop := startMTRRedraw(u.redraw, func() (int, int) { return int(width.Load()), 24 }, func(_ int, stats []trace.MTRHopStat) {
		_, e := u.columnSnapshot()
		renders.Add(1)
		select {
		case frames <- e.Draft:
		default:
		}
	})
	wait := func(want string) {
		t.Helper()
		select {
		case got := <-frames:
			if got != want {
				t.Fatalf("frame %q want %q", got, want)
			}
		case <-time.After(time.Second):
			t.Fatal("missing frame")
		}
	}
	wait("") // Visible before the first probe.
	var k mtrKeyInput
	feedMTRKeys(u, &k, "o")
	wait("LSNABWV")
	width.Store(120)
	wait("LSNABWV")
	var wg sync.WaitGroup
	for range 3 {
		wg.Go(func() {
			for i := range 100 {
				snapshot(i, []trace.MTRHopStat{{TTL: 1, IP: "192.0.2.1", Snt: i}})
				u.requestRedraw()
			}
		})
	}
	wg.Wait()
	stop()
	stop()
	count := renders.Load()
	snapshot(101, nil)
	u.requestRedraw()
	time.Sleep(120 * time.Millisecond)
	if renders.Load() != count {
		t.Fatal("wrote after cleanup")
	}
}
