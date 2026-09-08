package cmd

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nxtrace/NTrace-core/internal/mtrsession"
	"github.com/nxtrace/NTrace-core/ipgeo"
	"github.com/nxtrace/NTrace-core/trace"
)

func replayFixture(t *testing.T, start time.Time, complete bool) string {
	t.Helper()
	session := &mtrsession.Session{Version: "test", Target: "offline.invalid", ResolvedIP: "192.0.2.1", Protocol: "icmp", StartedAt: start, SourceHost: "recorded-host", SourceIP: "192.0.2.10", EffectiveParameters: &mtrsession.Parameters{MaxHops: 3, BeginHop: 1, MaxPerHop: 3, HopIntervalMs: 1000, TimeoutMs: 1000, ParallelRequests: 2}, Display: mtrsession.DisplayParameters{ShowMPLS: true}}
	probe := func(gen uint64, at time.Duration, host string) trace.MTRSessionEvent {
		return trace.MTRSessionEvent{Type: trace.MTRSessionProbeEvent, Generation: gen, Iteration: 1, Probe: &trace.MTRSessionProbe{TTL: 1, IP: "192.0.2.1", Host: host, Success: true, RTT: 1234567, CompletedAt: start.Add(at)}}
	}
	records := []mtrsession.Record{
		{MTRSessionEvent: trace.MTRSessionEvent{Type: mtrsession.StartEvent}, Session: session},
		{ElapsedNS: int64(time.Second), MTRSessionEvent: probe(0, time.Second, "before.invalid")},
		{ElapsedNS: int64(2 * time.Second), MTRSessionEvent: trace.MTRSessionEvent{Type: trace.MTRSessionPauseEvent}},
		{ElapsedNS: int64(3 * time.Second), MTRSessionEvent: trace.MTRSessionEvent{Type: trace.MTRSessionResetEvent, Generation: 1}},
		{ElapsedNS: int64(4 * time.Second), MTRSessionEvent: probe(1, 4*time.Second, "")},
		{ElapsedNS: int64(5 * time.Second), MTRSessionEvent: trace.MTRSessionEvent{Type: trace.MTRSessionMetadataEvent, Generation: 1, Metadata: &trace.MTRSessionMetadata{IP: "192.0.2.1", Host: "patched.invalid", Geo: &ipgeo.IPGeoData{Country: "测试"}}}},
		{ElapsedNS: int64(6 * time.Second), MTRSessionEvent: trace.MTRSessionEvent{Type: trace.MTRSessionResumeEvent, Generation: 1}},
	}
	if complete {
		records = append(records, mtrsession.Record{ElapsedNS: int64(7 * time.Second), MTRSessionEvent: trace.MTRSessionEvent{Type: mtrsession.EndEvent, Generation: 1}, End: &mtrsession.End{EndedAt: start.Add(7 * time.Second), EndReason: "completed"}})
	}
	var b bytes.Buffer
	for i := range records {
		r := &records[i]
		r.Format = mtrsession.FormatName
		r.SchemaVersion = mtrsession.SchemaVersion
		r.Seq = uint64(i + 1)
		r.Timestamp = start.Add(time.Duration(r.ElapsedNS))
		if err := json.NewEncoder(&b).Encode(r); err != nil {
			t.Fatal(err)
		}
	}
	if !complete {
		b.WriteString(`{"type":"end"`)
	}
	path := filepath.Join(t.TempDir(), "recording.ndjson")
	if err := os.WriteFile(path, b.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestMTRReplayEmptyStatsArray(t *testing.T) {
	for _, mode := range []string{"empty", "initialize-failed", "reset", "incomplete"} {
		t.Run(mode, func(t *testing.T) {
			start := time.Now()
			path := filepath.Join(t.TempDir(), "empty.jsonl")
			w, err := mtrsession.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = w.Close() }()
			session := mtrsession.Session{Version: "test", StartedAt: start}
			if err := w.Start(session); err != nil {
				t.Fatal(err)
			}
			if mode == "reset" {
				if err := w.Event(trace.MTRSessionEvent{Type: trace.MTRSessionResetEvent, Generation: 1, At: start.Add(time.Second)}); err != nil {
					t.Fatal(err)
				}
			}
			end := mtrsession.End{EndedAt: start.Add(2 * time.Second), EndReason: "completed"}
			if mode == "initialize-failed" {
				end.EndReason, end.Error = "error", &mtrsession.Error{Stage: "initialize", Message: "test failure"}
			}
			if mode != "incomplete" {
				if err := w.Finish(end); err != nil {
					t.Fatal(err)
				}
			} else if err := w.Close(); err != nil {
				t.Fatal(err)
			}
			var output, diagnostic bytes.Buffer
			_, code := maybeRunMTRReplayMode([]string{"--mtr-replay", path, "--json"}, &output, &diagnostic)
			var report map[string]json.RawMessage
			if err := json.Unmarshal(output.Bytes(), &report); err != nil {
				t.Fatalf("invalid replay JSON: %v: %s", err, diagnostic.String())
			}
			expectedCode := 0
			if mode == "incomplete" {
				expectedCode = 1
			}
			if code != expectedCode || string(report["stats"]) != "[]" {
				t.Fatalf("code=%d stats=%s", code, report["stats"])
			}
		})
	}
}

func TestMTRReplaySeekRebuildAndVirtualHistory(t *testing.T) {
	for _, year := range []int{2000, 2100} {
		t.Run(time.Date(year, 1, 1, 0, 0, 0, 0, time.UTC).Format("2006"), func(t *testing.T) {
			start := time.Date(year, 1, 1, 0, 0, 0, 0, time.UTC)
			r, err := mtrsession.OpenReader(replayFixture(t, start, true))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = r.Close() }()
			final, err := readMTRReplay(t.Context(), r, time.Duration(1<<63-1))
			if err != nil {
				t.Fatal(err)
			}
			stats := final.state.Snapshot().Stats
			if r.Incomplete() || final.cursor != 7*time.Second || len(stats) != 1 || stats[0].Snt != 1 || stats[0].Host != "patched.invalid" || stats[0].Geo.Country != "测试" || final.state.Generation() != 1 || final.state.Paused() {
				t.Fatalf("final=%+v stats=%+v", final, stats)
			}
			history := final.history.Snapshot(start.Add(final.cursor))
			if len(history) != 1 || len(history[0].Samples) != 1 || !history[0].Samples[0].At.Equal(start.Add(4*time.Second)) {
				t.Fatalf("history=%+v", history)
			}
			before, err := readMTRReplay(t.Context(), r, 2500*time.Millisecond)
			if err != nil {
				t.Fatal(err)
			}
			if before.cursor != 2500*time.Millisecond || !before.state.Paused() || before.state.Generation() != 0 || before.state.Snapshot().Stats[0].Host != "before.invalid" {
				t.Fatalf("seek=%+v", before)
			}
			if err := before.advance(t.Context(), r, 7*time.Second); err != nil {
				t.Fatal(err)
			}
			if got := before.state.Snapshot().Stats; len(got) != 1 || got[0].Snt != 1 || got[0].Host != "patched.invalid" {
				t.Fatalf("forward=%+v", got)
			}
			atReset, err := readMTRReplay(t.Context(), r, 3*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			if len(atReset.state.Snapshot().Stats) != 0 || len(atReset.history.Snapshot(start.Add(3*time.Second))) != 0 {
				t.Fatal("reset retained data")
			}
		})
	}
}

func TestMTRReplayOfflineCLIAndPartialResult(t *testing.T) {
	oldLookup, oldReport, oldRaw := domainLookupFn, runMTRReportFn, runMTRJSONRawFn
	t.Cleanup(func() { domainLookupFn, runMTRReportFn, runMTRJSONRawFn = oldLookup, oldReport, oldRaw })
	domainLookupFn = func(context.Context, string, string, string, bool) (net.IP, error) {
		t.Fatal("offline replay called DNS")
		return nil, nil
	}
	runMTRReportFn = func(context.Context, trace.Method, trace.Config, trace.MTROptions, trace.MTROnSnapshot) error {
		t.Fatal("offline replay called MTR")
		return nil
	}
	runMTRJSONRawFn = func(context.Context, trace.Method, trace.Config, trace.MTRRawOptions, trace.MTRRawOnRecord) error {
		t.Fatal("offline replay called RAW")
		return nil
	}
	for _, complete := range []bool{false, true} {
		wantCode := 0
		if !complete {
			wantCode = 1
		}
		path := replayFixture(t, time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC), complete)
		var out, diag bytes.Buffer
		handled, code := maybeRunMTRReplayMode([]string{"--mtr-replay", path, "--json"}, &out, &diag)
		if !handled || code != wantCode {
			t.Fatalf("handled=%v code=%d diag=%s", handled, code, diag.String())
		}
		var result struct {
			Complete bool               `json:"complete"`
			Cursor   int64              `json:"cursor_ns"`
			Stats    []trace.MTRHopStat `json:"stats"`
			Type     string             `json:"type"`
		}
		if err := json.Unmarshal(out.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		if result.Complete != complete || result.Type != "mtr_replay" || len(result.Stats) != 1 || result.Stats[0].Snt != 1 || result.Cursor <= 0 {
			t.Fatalf("result=%s", out.String())
		}
		if strings.Contains(diag.String(), "Incomplete") == complete {
			t.Fatalf("diag=%s", diag.String())
		}
		canonicalJSON := append([]byte(nil), out.Bytes()...)
		out.Reset()
		diag.Reset()
		_, code = maybeRunMTRReplayMode([]string{"--mtr-replay", path, "-j"}, &out, &diag)
		if code != wantCode || !bytes.Equal(canonicalJSON, out.Bytes()) {
			t.Fatalf("JSON alias differs: code=%d out=%s diag=%s", code, out.String(), diag.String())
		}
		out.Reset()
		diag.Reset()
		_, code = maybeRunMTRReplayMode([]string{"--mtr-replay", path, "-w", "--mtr-columns", "received,avg"}, &out, &diag)
		if code != wantCode || strings.Contains(out.String(), "\x1b") || !strings.Contains(out.String(), "Rcv") || !strings.Contains(out.String(), "patched.invalid") {
			t.Fatalf("report code=%d out=%s diag=%s", code, out.String(), diag.String())
		}
	}
}

func TestMTRReplayArgumentsAndCancellation(t *testing.T) {
	for _, args := range [][]string{{"--", "--mtr-replay"}, {"--mtr-record", "--mtr-replay"}, {"--file", "--mtr-replay"}, {"--source=--mtr-replay"}} {
		if containsMTRReplayFlag(args) {
			t.Fatalf("stole argument %v", args)
		}
	}
	for _, args := range [][]string{{"--mtr-replay=x", "--tcp"}, {"--mtr-replay=x", "--doctor"}, {"--mtr-replay=x", "--no-rdns"}, {"--mtr-replay=x", "--disable-mpls"}, {"--mtr-replay=x", "target"}, {"--mtr-replay=x", "--ipinfo=9"}, {"--mtr-replay=x", "--json", "--mtr-columns=avg"}} {
		var out, diag bytes.Buffer
		handled, code := maybeRunMTRReplayMode(args, &out, &diag)
		if !handled || code != 2 || out.Len() != 0 {
			t.Fatalf("args=%v handled=%v code=%d out=%s", args, handled, code, out.String())
		}
	}
	r, err := mtrsession.OpenReader(replayFixture(t, time.Now(), true))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := readMTRReplay(ctx, r, time.Second); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel err=%v", err)
	}
}

type replayDelayedWriteFailure struct{ calls int }

func (w *replayDelayedWriteFailure) Write(data []byte) (int, error) {
	w.calls++
	if w.calls == 1 {
		return len(data), nil
	}
	return 0, io.ErrClosedPipe
}

func TestMTRReplayHelpVersionWriteFailures(t *testing.T) {
	for _, flag := range []string{"--help", "--version"} {
		for _, short := range []bool{false, true} {
			var diag bytes.Buffer
			writer := &failingMTRWriter{short: short}
			handled, code := maybeRunMTRReplayMode([]string{"--mtr-replay", "unused", flag}, writer, &diag)
			if !handled || code != 1 || writer.calls != 1 || diag.Len() == 0 {
				t.Fatalf("flag=%s short=%v handled=%v code=%d writes=%d diag=%s", flag, short, handled, code, writer.calls, diag.String())
			}
		}
	}
	var diag bytes.Buffer
	writer := &replayDelayedWriteFailure{}
	_, code := maybeRunMTRReplayMode([]string{"--mtr-replay", "unused", "--help"}, writer, &diag)
	if code != 1 || writer.calls != 2 || diag.Len() == 0 {
		t.Fatalf("PrintDefaults error lost: code=%d writes=%d diag=%s", code, writer.calls, diag.String())
	}
}

func TestMTRReplayTimeEditor(t *testing.T) {
	for value, want := range map[string]time.Duration{"00:00:00": 0, "00:01:02.3": 62300 * time.Millisecond, "100:59:59.999": 100*time.Hour + 59*time.Minute + 59999*time.Millisecond} {
		got, err := parseMTRReplayTime(value)
		if err != nil || got != want {
			t.Fatalf("%q: %s %v", value, got, err)
		}
	}
	for _, value := range []string{"1:02:03", "00:60:00", "00:00:60", "00:01:00.", "00:00:00.0000", "-01:00:00", "99999999999999:00:00", "00:00:0x"} {
		if _, err := parseMTRReplayTime(value); err == nil {
			t.Fatalf("accepted %q", value)
		}
	}
	u := newMTRUI(nil, 0)
	u.replay = &mtrReplayControls{commands: make(chan mtrReplayCommand, 1), duration: time.Hour}
	u.replay.cursor.Store(int64(5 * time.Second))
	var keys mtrKeyInput
	keys.feed(u, 'j', time.Now())
	if !u.IsPaused() || !u.replayEditor.Active || u.replayEditor.Draft != "00:00:05.000" {
		t.Fatalf("editor=%+v", u.replayEditor)
	}
	keys.feed(u, 21, time.Now())
	for _, b := range []byte("\x1b[200~00:00:12.500\n\x1b[201~") {
		keys.feed(u, b, time.Now())
	}
	if !u.replayEditor.Active {
		t.Fatal("paste submitted editor")
	}
	keys.feed(u, '\r', time.Now())
	if u.replayEditor.Active {
		t.Fatalf("submit error=%s", u.replayEditor.Error)
	}
	command := <-u.replay.commands
	if command.kind != "seek" || command.at != 12500*time.Millisecond {
		t.Fatalf("command=%+v", command)
	}
	u.applyReplayAction(mtrActionReplayJump)
	u.editReplayTime(21, false)
	for _, b := range []byte("02:00:00") {
		u.editReplayTime(b, false)
	}
	u.editReplayTime('\r', false)
	if !u.replayEditor.Active || u.replayEditor.Error == "" {
		t.Fatal("out of range accepted")
	}
	u.editReplayTime(27, false)
	if u.replayEditor.Active || !u.IsPaused() {
		t.Fatal("cancel changed playback")
	}
}

func TestMTRReplayPendingSeekKeepsImmediatePlay(t *testing.T) {
	r := &mtrReplayControls{commands: make(chan mtrReplayCommand, 1)}
	r.send(mtrReplayCommand{kind: "seek", at: 12 * time.Second})
	r.send(mtrReplayCommand{kind: "play"})
	got := <-r.commands
	if got.kind != "seek" || got.at != 12*time.Second || !got.playAfter {
		t.Fatalf("seek lost: %+v", got)
	}
	r.send(got)
	r.send(mtrReplayCommand{kind: "pause"})
	got = <-r.commands
	if got.kind != "seek" || got.at != 12*time.Second || got.playAfter {
		t.Fatalf("pause lost: %+v", got)
	}
}

func TestMTRReplayDisplaySanitization(t *testing.T) {
	original := []trace.MTRHopStat{{TTL: 1, IP: "192.0.2.1", Host: "bad\x1b[2Jhost", Geo: &ipgeo.IPGeoData{Owner: "evil\u009b[2J"}, MPLS: []string{"label\nnext"}, Response: &trace.MTRProbeResponse{Marker: "!\x1b[2J"}}}
	clean := sanitizeMTRReplayStats(original)
	if strings.ContainsAny(clean[0].Host, "\x1b\n") || strings.ContainsAny(clean[0].Geo.Owner, "\u009b") || strings.Contains(clean[0].MPLS[0], "\n") {
		t.Fatalf("unsafe=%+v", clean)
	}
	if original[0].Host == clean[0].Host || original[0].Geo.Owner == clean[0].Geo.Owner || original[0].MPLS[0] == clean[0].MPLS[0] {
		t.Fatal("modified original")
	}
	h, err := mtrReplayHeader(&mtrsession.Session{Target: "target\x1b[2J", SourceHost: "source\nnext", SourceIP: "192.0.2.9", Version: "v\x1b[2J"}, mtrReplayOptions{})
	if err != nil || strings.Contains(h.Target, "\x1b") || strings.Contains(h.SrcHost, "\n") || h.SrcIP != "192.0.2.9" {
		t.Fatalf("header=%+v err=%v", h, err)
	}
}

func TestMTRReplayLongSessionStreamingSeek(t *testing.T) {
	started := time.Now()
	path := filepath.Join(t.TempDir(), "long.ndjson")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	buffer := bufio.NewWriter(file)
	encoder := json.NewEncoder(buffer)
	start := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	seq := uint64(0)
	write := func(record mtrsession.Record) {
		t.Helper()
		seq++
		record.Format, record.SchemaVersion, record.Seq = mtrsession.FormatName, mtrsession.SchemaVersion, seq
		record.Timestamp = start.Add(time.Duration(record.ElapsedNS))
		if err := encoder.Encode(record); err != nil {
			t.Fatal(err)
		}
	}
	write(mtrsession.Record{MTRSessionEvent: trace.MTRSessionEvent{Type: mtrsession.StartEvent}, Session: &mtrsession.Session{
		StartedAt: start, Target: "192.0.2.1", ResolvedIP: "192.0.2.1", Protocol: "icmp",
		EffectiveParameters: &mtrsession.Parameters{BeginHop: 1, MaxHops: 1, HopIntervalMs: 100, TimeoutMs: 1000, ParallelRequests: 1},
	}})
	for i := 1; i <= 4000; i++ {
		elapsed := time.Duration(i) * 100 * time.Millisecond
		write(mtrsession.Record{ElapsedNS: int64(elapsed), MTRSessionEvent: trace.MTRSessionEvent{
			Type: trace.MTRSessionProbeEvent, Iteration: i,
			Probe: &trace.MTRSessionProbe{TTL: 1, IP: "192.0.2.1", Success: true, RTT: time.Millisecond, CompletedAt: start.Add(elapsed)},
		}})
	}
	write(mtrsession.Record{ElapsedNS: int64(400 * time.Second), MTRSessionEvent: trace.MTRSessionEvent{Type: mtrsession.EndEvent}, End: &mtrsession.End{EndedAt: start.Add(400 * time.Second), EndReason: "completed"}})
	if err := buffer.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	generated := time.Since(started)
	r, err := mtrsession.OpenReader(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	started = time.Now()
	final, err := readMTRReplay(t.Context(), r, time.Duration(1<<63-1))
	if err != nil {
		t.Fatal(err)
	}
	loaded := time.Since(started)
	history := final.history.Snapshot(start.Add(400 * time.Second))
	if len(history) != 1 || len(history[0].Samples) != 1801 || !history[0].Samples[0].At.Equal(start.Add(220*time.Second)) {
		t.Fatalf("final history retained the wrong window: %+v", history)
	}
	if stats := final.state.Snapshot().Stats; len(stats) != 1 || stats[0].Snt != 4000 {
		t.Fatalf("final stats=%+v", stats)
	}
	started = time.Now()
	early, err := readMTRReplay(t.Context(), r, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	sought := time.Since(started)
	history = early.history.Snapshot(start.Add(10 * time.Second))
	if len(history) != 1 || len(history[0].Samples) != 100 || !history[0].Samples[0].At.Equal(start.Add(100*time.Millisecond)) {
		t.Fatalf("seek did not recover the discarded early window: %+v", history)
	}
	if stats := early.state.Snapshot().Stats; len(stats) != 1 || stats[0].Snt != 100 {
		t.Fatalf("early stats=%+v", stats)
	}
	t.Logf("400s / 4000 probes, bytes=%d generation=%s load=%s seek-to-10s=%s", r.Size(), generated, loaded, sought)
}
