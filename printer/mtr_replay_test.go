package printer

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nxtrace/NTrace-core/trace"
)

func TestMTRReplayExplicitClockInAllHeaders(t *testing.T) {
	clock := time.Date(2000, 2, 3, 4, 5, 6, 0, time.UTC)
	for _, columns := range [][]MTRColumn{nil, {MTRColumnAvg}} {
		header := MTRTUIHeader{Target: "192.0.2.1", Version: "test", Now: clock, Columns: columns, Replay: &MTRReplayStatus{Cursor: 5 * time.Second, Duration: time.Minute, Complete: true}, Status: MTRTUIPaused}
		frame := mtrTUIRenderStringWithWidth(header, nil, 160)
		for _, want := range []string{"Replay", "2000-02-03T04:05:06+0000", "Paused 00:00:05.000/00:01:00.000", "J:time"} {
			if !strings.Contains(frame, want) {
				t.Fatalf("missing %q in %q", want, frame)
			}
		}
	}
}

func TestMTRReplayHistoryUsesRecordingClock(t *testing.T) {
	for _, year := range []int{2000, 2100} {
		clock := time.Date(year, 1, 1, 0, 0, 0, 0, time.UTC)
		store := NewMTRHistoryStore(MTRHistoryWindow)
		store.AddProbeEventAt(trace.MTRProbeEvent{TTL: 1, Success: true, Timestamp: clock.Add(-time.Second), RTT: time.Millisecond}, clock)
		store.AddProbeEventAt(trace.MTRProbeEvent{TTL: 1, Success: false, Timestamp: clock.Add(-4 * time.Minute)}, clock)
		history := store.Snapshot(clock)
		if len(history) != 1 || len(history[0].Samples) != 1 || !history[0].Samples[0].At.Equal(clock.Add(-time.Second)) {
			t.Fatalf("year=%d history=%+v", year, history)
		}
	}
}

type replayFailedWriter struct{}

func (replayFailedWriter) Write([]byte) (int, error) { return 0, errors.New("closed") }

func TestMTRReplayReportPlainSink(t *testing.T) {
	var b bytes.Buffer
	stats := []trace.MTRHopStat{{TTL: 1, IP: "192.0.2.1", Snt: 2, Received: 1, Loss: 50, Avg: 1.25}}
	opts := MTRReportOptions{Columns: []MTRColumn{MTRColumnReceived, MTRColumnAvg}, Wide: true, SrcHost: "recorded-host"}
	if err := WriteMTRReplayReport(&b, stats, opts); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(b.String(), "\x1b") || !strings.Contains(b.String(), "Rcv") || !strings.Contains(b.String(), "Avg") || strings.Contains(b.String(), "Loss%") {
		t.Fatalf("report=%s", b.String())
	}
	if err := WriteMTRReplayReport(replayFailedWriter{}, stats, opts); err == nil {
		t.Fatal("ignored write error")
	}
}

func TestMTRReplayReportLongSourceAlignment(t *testing.T) {
	stats := []trace.MTRHopStat{{TTL: 1, IP: "192.0.2.1", Snt: 2, Received: 1, Loss: 50}}
	for _, wide := range []bool{false, true} {
		var b bytes.Buffer
		opts := MTRReportOptions{Columns: []MTRColumn{MTRColumnSnt}, Wide: wide, SrcHost: strings.Repeat("源host", 12)}
		if err := WriteMTRReplayReport(&b, stats, opts); err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(b.String(), "\n")
		// HOST: has one more prefix cell than the live report's TTL prefix.
		if reportDisplayWidth(lines[1]) != reportDisplayWidth(lines[2])+1 {
			t.Fatalf("misaligned: %s", b.String())
		}
		if wide && !strings.Contains(lines[1], opts.SrcHost) {
			t.Fatal("wide source truncated")
		}
	}
}
