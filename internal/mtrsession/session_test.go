package mtrsession

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/nxtrace/NTrace-core/ipgeo"
	"github.com/nxtrace/NTrace-core/trace"
)

func testSession() Session {
	return Session{
		Version: "test", Target: "example.invalid", ResolvedIP: "192.0.2.1", Protocol: "icmp",
		StartedAt: time.Date(2026, 9, 8, 1, 2, 3, 0, time.UTC), SourceHost: "test-host",
		EffectiveParameters: &Parameters{BeginHop: 1, MaxHops: 30, HopIntervalMs: 1000, TimeoutMs: 2000, ParallelRequests: 8},
	}
}

func testProbe(at time.Time) trace.MTRSessionEvent {
	return trace.MTRSessionEvent{Type: trace.MTRSessionProbeEvent, At: at, Probe: &trace.MTRSessionProbe{
		TTL: 1, IP: "192.0.2.1", Host: "example.invalid", Success: true, RTT: 1234567,
		CompletedAt: at, MPLS: []string{"test-label"}, Geo: &ipgeo.IPGeoData{Country: "测试", Owner: "Example"},
	}}
}

func writeFixture(t *testing.T, finish bool) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "session.ndjson")
	w, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.Close() })
	s := testSession()
	if err = w.Start(s); err != nil {
		t.Fatal(err)
	}
	if err = w.Event(testProbe(s.StartedAt.Add(time.Second))); err != nil {
		t.Fatal(err)
	}
	if finish {
		err = w.Finish(End{EndedAt: s.StartedAt.Add(2 * time.Second), EndReason: "completed"})
	} else {
		err = w.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func readRecords(t *testing.T, path string) ([]Record, bool, error) {
	t.Helper()
	r, err := OpenReader(path)
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = r.Close() }()
	var records []Record
	for {
		record, err := r.Next()
		if errors.Is(err, io.EOF) {
			return records, r.Incomplete(), nil
		}
		if err != nil {
			return records, r.Incomplete(), err
		}
		records = append(records, record)
	}
}

func TestRoundTrip(t *testing.T) {
	path := writeFixture(t, true)
	records, incomplete, err := readRecords(t, path)
	if err != nil || incomplete || len(records) != 3 {
		t.Fatalf("records=%d incomplete=%v err=%v", len(records), incomplete, err)
	}
	for i, r := range records {
		if r.Format != FormatName || r.SchemaVersion != SchemaVersion || r.Seq != uint64(i+1) || r.ElapsedNS != int64(i)*int64(time.Second) || !r.At.Equal(r.Timestamp) {
			t.Fatalf("record %d: %+v", i, r)
		}
	}
	p := records[1].Probe
	if p.RTT != 1234567 || p.Geo.Country != "测试" || p.MPLS[0] != "test-label" || !p.CompletedAt.Equal(records[1].At) {
		t.Fatalf("probe not preserved: %+v", p)
	}
	if records[0].Session.EffectiveParameters.MaxHops != 30 || records[2].End.EndReason != "completed" {
		t.Fatal("header or footer lost")
	}
}

func TestProbeResponseKinds(t *testing.T) {
	for _, kind := range []string{trace.MTRResponseTransit, trace.MTRResponseDestination, trace.MTRResponseUnreachable, "", "future_response"} {
		t.Run(kind, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "recording.jsonl")
			w, err := Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = w.Close() }()
			session := testSession()
			if err := w.Start(session); err != nil {
				t.Fatal(err)
			}
			probe := testProbe(session.StartedAt.Add(time.Second))
			probe.Probe.Response = &trace.MTRProbeResponse{Kind: kind}
			err = w.Event(probe)
			if kind == "" || kind == "future_response" {
				if err == nil || !strings.Contains(err.Error(), "response kind") {
					t.Fatalf("invalid kind %q: %v", kind, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := w.Finish(End{EndedAt: session.StartedAt.Add(2 * time.Second), EndReason: "completed"}); err != nil {
				t.Fatal(err)
			}
			records, incomplete, err := readRecords(t, path)
			if err != nil || incomplete || len(records) != 3 || records[1].Probe.Response.Kind != kind {
				t.Fatalf("kind=%q records=%v incomplete=%v err=%v", kind, records, incomplete, err)
			}
		})
	}
}

func TestWriterRejectsResponseWithoutSuccessfulPeer(t *testing.T) {
	for _, peer := range []struct {
		success bool
		ip      string
	}{{false, ""}, {false, "192.0.2.1"}, {true, ""}, {true, "not-an-ip"}} {
		w, err := Open(filepath.Join(t.TempDir(), "recording.jsonl"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = w.Close() })
		session := testSession()
		if err := w.Start(session); err != nil {
			t.Fatal(err)
		}
		probe := testProbe(session.StartedAt.Add(time.Second))
		probe.Probe.Success, probe.Probe.IP = peer.success, peer.ip
		probe.Probe.Response = &trace.MTRProbeResponse{Kind: trace.MTRResponseDestination}
		if err := w.Event(probe); err == nil {
			t.Fatalf("writer accepted response without a successful peer: %+v", peer)
		}
	}
}

func TestExclusivePrivateFile(t *testing.T) {
	path := writeFixture(t, true)
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if w, err := Open(path); !errors.Is(err, os.ErrExist) || w != nil {
		t.Fatalf("existing file: writer=%v err=%v", w, err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(original, after) {
		t.Fatal("existing file changed")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
		t.Fatalf("permissions = %o", info.Mode().Perm())
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(path, link); err == nil {
		if w, err := Open(link); !errors.Is(err, os.ErrExist) || w != nil {
			t.Fatalf("symlink: writer=%v err=%v", w, err)
		}
	}
}

func TestTruncatedTail(t *testing.T) {
	original, err := os.ReadFile(writeFixture(t, true))
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.SplitAfter(original, []byte{'\n'})
	tests := []struct {
		name       string
		data       []byte
		count      int
		incomplete bool
		invalid    bool
	}{
		{"complete", original, 3, false, false},
		{"no-final-newline", bytes.TrimSuffix(original, []byte{'\n'}), 3, false, false},
		{"missing-end", bytes.Join(lines[:2], nil), 2, true, false},
		{"partial-end", append(bytes.Join(lines[:2], nil), lines[2][:len(lines[2])/2]...), 2, true, false},
		{"partial-probe", append(append([]byte{}, lines[0]...), lines[1][:len(lines[1])/2]...), 1, true, false},
		{"header-only", lines[0], 1, true, false},
		{"empty", nil, 0, true, true},
		{"partial-header", lines[0][:len(lines[0])/2], 0, true, true},
		{"broken-middle", bytes.Join([][]byte{lines[0], []byte("{broken}\n"), lines[2]}, nil), 1, true, true},
		{"broken-complete-last-line", append(append([]byte{}, lines[0]...), []byte("{broken}\n")...), 1, true, true},
		{"partial-after-end", append(append([]byte{}, original...), []byte("{broken")...), 3, true, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "input")
			if err := os.WriteFile(path, tc.data, 0600); err != nil {
				t.Fatal(err)
			}
			records, incomplete, err := readRecords(t, path)
			if (err != nil) != tc.invalid || len(records) != tc.count || incomplete != tc.incomplete {
				t.Fatalf("count=%d incomplete=%v error=%v", len(records), incomplete, err)
			}
		})
	}
}

func TestRejectInvalidRecordContract(t *testing.T) {
	path := writeFixture(t, true)
	original, _, err := readRecords(t, path)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		index  int
		mutate func(*Record)
	}{
		{"format", 0, func(r *Record) { r.Format = "" }},
		{"version", 0, func(r *Record) { r.SchemaVersion++ }},
		{"version-midstream", 1, func(r *Record) { r.SchemaVersion++ }},
		{"missing-sequence", 1, func(r *Record) { r.Seq = 0 }},
		{"duplicate-sequence", 1, func(r *Record) { r.Seq = 1 }},
		{"sequence-gap", 1, func(r *Record) { r.Seq++ }},
		{"decreasing-elapsed", 2, func(r *Record) { r.ElapsedNS = 0 }},
		{"unknown-event", 1, func(r *Record) { r.Type = "future_event" }},
		{"missing-probe", 1, func(r *Record) { r.Probe = nil }},
		{"bad-generation", 1, func(r *Record) { r.Generation = 1 }},
		{"missing-timestamp", 1, func(r *Record) { r.Timestamp = time.Time{} }},
		{"negative-probe-age", 1, func(r *Record) { age := int64(-1); r.ProbeAgeNS = &age }},
		{"probe-age-on-start", 0, func(r *Record) { age := int64(0); r.ProbeAgeNS = &age }},
		{"probe-age-on-end", 2, func(r *Record) { age := int64(0); r.ProbeAgeNS = &age }},
		{"unexpected-header", 1, func(r *Record) { r.Session = original[0].Session }},
		{"missing-end-payload", 2, func(r *Record) { r.End = nil }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			records := append([]Record(nil), original...)
			tc.mutate(&records[tc.index])
			var data bytes.Buffer
			for _, record := range records {
				if err := json.NewEncoder(&data).Encode(record); err != nil {
					t.Fatal(err)
				}
			}
			p := filepath.Join(t.TempDir(), "input")
			if err := os.WriteFile(p, data.Bytes(), 0600); err != nil {
				t.Fatal(err)
			}
			if _, _, err := readRecords(t, p); err == nil {
				t.Fatal("accepted malformed recording")
			}
		})
	}
}

func TestReaderDoesNotFollowGrowthAndRewinds(t *testing.T) {
	path := writeFixture(t, false)
	r, err := OpenReader(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	size := r.Size()
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("not part of the original file\n"); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	for pass := 0; pass < 2; pass++ {
		count := 0
		for {
			_, err := r.Next()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
			count++
		}
		if count != 2 || !r.Incomplete() || r.Offset() != size {
			t.Fatalf("pass=%d count=%d incomplete=%v offset=%d size=%d", pass, count, r.Incomplete(), r.Offset(), size)
		}
		if err := r.Rewind(); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Next(); !errors.Is(err, ErrClosed) {
		t.Fatalf("closed Next: %v", err)
	}
	if err := r.Rewind(); !errors.Is(err, ErrClosed) {
		t.Fatalf("closed Rewind: %v", err)
	}
}

type failingFile struct {
	bytes.Buffer
	writeErr, syncErr, closeErr error
	short                       bool
	writes, syncs, closes       int
}

func (f *failingFile) Write(data []byte) (int, error) {
	f.writes++
	if f.writeErr != nil {
		return 0, f.writeErr
	}
	if f.short {
		return len(data) - 1, nil
	}
	return f.Buffer.Write(data)
}
func (f *failingFile) Sync() error  { f.syncs++; return f.syncErr }
func (f *failingFile) Close() error { f.closes++; return f.closeErr }

func TestWriterFailuresAreStickyAndClose(t *testing.T) {
	diskFull, syncFail, closeFail := errors.New("disk full"), errors.New("sync failure"), errors.New("close failure")
	for _, tc := range []struct {
		name string
		file *failingFile
		want error
	}{
		{"write", &failingFile{writeErr: diskFull}, diskFull},
		{"short-write", &failingFile{short: true}, io.ErrShortWrite},
		{"sync", &failingFile{syncErr: syncFail}, syncFail},
		{"close", &failingFile{closeErr: closeFail}, closeFail},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := &Writer{file: tc.file}
			_ = w.Start(testSession())
			err := w.Finish(End{EndReason: "completed"})
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v want %v", err, tc.want)
			}
			writes := tc.file.writes
			if err := w.Finish(End{}); !errors.Is(err, tc.want) {
				t.Fatal(err)
			}
			if err := w.Close(); !errors.Is(err, tc.want) {
				t.Fatal(err)
			}
			if tc.file.writes != writes || tc.file.syncs != 1 || tc.file.closes != 1 {
				t.Fatalf("writes=%d syncs=%d closes=%d", tc.file.writes, tc.file.syncs, tc.file.closes)
			}
			if tc.file.writeErr != nil || tc.file.short {
				if writes != 1 {
					t.Fatalf("retried failed write: %d", writes)
				}
			}
		})
	}
}

func TestWriterMarshalFailure(t *testing.T) {
	f := &failingFile{}
	w := &Writer{file: f}
	s := testSession()
	if err := w.Start(s); err != nil {
		t.Fatal(err)
	}
	event := testProbe(s.StartedAt)
	event.Probe.Geo.Lat = math.NaN()
	if err := w.Event(event); err == nil {
		t.Fatal("accepted NaN")
	}
	if err := w.Finish(End{EndReason: "error"}); err == nil {
		t.Fatal("forgot marshal failure")
	}
	if f.writes != 1 || f.syncs != 1 || f.closes != 1 {
		t.Fatalf("file: %+v", f)
	}
}

func TestLineLimit(t *testing.T) {
	f := &failingFile{}
	w := &Writer{file: f}
	s := testSession()
	if err := w.Start(s); err != nil {
		t.Fatal(err)
	}
	event := trace.MTRSessionEvent{Type: trace.MTRSessionMetadataEvent, At: s.StartedAt, Metadata: &trace.MTRSessionMetadata{IP: "192.0.2.1"}}
	record := Record{Format: FormatName, SchemaVersion: SchemaVersion, Seq: 2, Timestamp: s.StartedAt, MTRSessionEvent: event}
	// Host is omitted when empty, so account for the added field and quotes.
	event.Metadata.Host = "x"
	record.Metadata = event.Metadata
	encoded, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	event.Metadata.Host = strings.Repeat("x", MaxLineBytes-len(encoded))
	if err := w.Event(event); err != nil {
		t.Fatalf("exact-limit record rejected: %v", err)
	}
	lines := bytes.SplitAfter(f.Bytes(), []byte{'\n'})
	if len(lines[1]) != MaxLineBytes {
		t.Fatalf("line=%d", len(lines[1]))
	}
	p := filepath.Join(t.TempDir(), "exact")
	if err := os.WriteFile(p, f.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	if records, incomplete, err := readRecords(t, p); err != nil || len(records) != 2 || !incomplete {
		t.Fatalf("reader exact limit: %d %v %v", len(records), incomplete, err)
	}
	event.Metadata.Host += "x"
	if err := w.Event(event); !errors.Is(err, ErrLineTooLarge) {
		t.Fatalf("oversized writer: %v", err)
	}
	for _, terminated := range []bool{false, true} {
		over := append([]byte{}, lines[0]...)
		over = append(over, bytes.Repeat([]byte{'x'}, MaxLineBytes+1)...)
		if terminated {
			over = append(over, '\n')
		}
		if err := os.WriteFile(p, over, 0600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := readRecords(t, p); !errors.Is(err, ErrLineTooLarge) {
			t.Fatalf("oversized reader terminated=%v: %v", terminated, err)
		}
	}
}

func TestControlEventsAndClockRegression(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session")
	w, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	s := testSession()
	if err := w.Start(s); err != nil {
		t.Fatal(err)
	}
	for _, event := range []trace.MTRSessionEvent{
		{Type: trace.MTRSessionPauseEvent, At: s.StartedAt.Add(time.Second)},
		{Type: trace.MTRSessionResetEvent, Generation: 1, At: s.StartedAt.Add(-time.Second)},
		{Type: trace.MTRSessionResumeEvent, Generation: 1, At: s.StartedAt.Add(2 * time.Second)},
		{Type: trace.MTRSessionPathEndEvent, Generation: 1, At: s.StartedAt.Add(3 * time.Second)},
	} {
		if err := w.Event(event); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Finish(End{EndedAt: s.StartedAt.Add(4 * time.Second), EndReason: "interrupted", Signal: "SIGINT"}); err != nil {
		t.Fatal(err)
	}
	records, incomplete, err := readRecords(t, path)
	if err != nil || incomplete || len(records) != 6 {
		t.Fatalf("%d %v %v", len(records), incomplete, err)
	}
	if records[2].ElapsedNS != int64(time.Second) || !records[2].Timestamp.Equal(s.StartedAt.Add(-time.Second)) || records[5].Generation != 1 {
		t.Fatal("clock or generation not preserved")
	}
}

func TestInitializationFailureSession(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session")
	w, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	s := testSession()
	s.ResolvedIP, s.EffectiveParameters = "", nil
	if err := w.Start(s); err != nil {
		t.Fatal(err)
	}
	if err := w.Finish(End{EndReason: "error", Error: &Error{Stage: "initialize", Message: "backend unavailable"}}); err != nil {
		t.Fatal(err)
	}
	records, incomplete, err := readRecords(t, path)
	if err != nil || incomplete || len(records) != 2 || records[1].End.Error.Stage != "initialize" {
		t.Fatalf("%+v %v %v", records, incomplete, err)
	}
}

func TestReaderRejectsDirectory(t *testing.T) {
	if r, err := OpenReader(t.TempDir()); err == nil {
		_ = r.Close()
		t.Fatal("accepted directory")
	}
}

func TestWriterProbeAgePreservesMonotonicTime(t *testing.T) {
	for _, fallback := range []bool{false, true} {
		t.Run(map[bool]string{false: "event-time", true: "fallback-time"}[fallback], func(t *testing.T) {
			f := &failingFile{}
			w := &Writer{file: f}
			completed := time.Now().Add(-time.Second)
			applied := time.Now()
			s := testSession()
			s.StartedAt = completed.Add(-time.Second)
			if err := w.Start(s); err != nil {
				t.Fatal(err)
			}
			event := testProbe(completed)
			event.At = applied
			if fallback {
				event.At = time.Time{}
			}
			if err := w.Event(event); err != nil {
				t.Fatal(err)
			}
			after := time.Now()
			lines := bytes.Split(f.Bytes(), []byte{'\n'})
			var record Record
			if err := json.Unmarshal(lines[1], &record); err != nil {
				t.Fatal(err)
			}
			if record.ProbeAgeNS == nil {
				t.Fatal("probe age was omitted")
			}
			want := int64(applied.Sub(completed))
			if fallback {
				if *record.ProbeAgeNS < want || *record.ProbeAgeNS > int64(after.Sub(completed)) {
					t.Fatalf("fallback age out of bounds: %d", *record.ProbeAgeNS)
				}
			} else if *record.ProbeAgeNS != want {
				t.Fatalf("age = %d, want %d", *record.ProbeAgeNS, want)
			}
		})
	}
}

func TestReaderProbeAgeIndependentOfWallClock(t *testing.T) {
	original, _, err := readRecords(t, writeFixture(t, true))
	if err != nil {
		t.Fatal(err)
	}
	for _, shift := range []time.Duration{-24 * time.Hour, 24 * time.Hour} {
		for _, legacy := range []bool{false, true} {
			records := append([]Record(nil), original...)
			records[1].Timestamp = records[1].Probe.CompletedAt.Add(shift)
			age := int64(50 * time.Millisecond)
			records[1].ProbeAgeNS = &age
			if legacy {
				records[1].ProbeAgeNS = nil
			}
			var data bytes.Buffer
			for _, record := range records {
				if err := json.NewEncoder(&data).Encode(record); err != nil {
					t.Fatal(err)
				}
			}
			path := filepath.Join(t.TempDir(), "wall-clock.session")
			if err := os.WriteFile(path, data.Bytes(), 0600); err != nil {
				t.Fatal(err)
			}
			got, incomplete, err := readRecords(t, path)
			if err != nil || incomplete || len(got) != 3 {
				t.Fatalf("shift=%v legacy=%v err=%v", shift, legacy, err)
			}
			if legacy {
				if got[1].ProbeAgeNS != nil {
					t.Fatal("invented an age for an older record")
				}
			} else if got[1].ProbeAgeNS == nil || *got[1].ProbeAgeNS != age {
				t.Fatal("stored probe age was changed by wall-clock timestamps")
			}
		}
	}
}

func TestRejectContradictoryFooter(t *testing.T) {
	for _, scenario := range []string{"timestamp", "unknown_reason", "completed_error", "completed_signal", "interrupted_error", "interrupted_signal", "error_missing", "error_stage", "error_message", "error_signal"} {
		t.Run(scenario, func(t *testing.T) {
			path := writeFixture(t, true)
			records, _, err := readRecords(t, path)
			if err != nil {
				t.Fatal(err)
			}
			record := &records[len(records)-1]
			switch scenario {
			case "timestamp":
				record.End.EndedAt = record.End.EndedAt.Add(time.Second)
			case "unknown_reason":
				record.End.EndReason = "future_reason"
			case "completed_error":
				record.End.Error = &Error{Stage: "run", Message: "failed"}
			case "completed_signal":
				record.End.Signal = "SIGINT"
			case "interrupted_error":
				record.End.EndReason = "interrupted"
				record.End.Error = &Error{Stage: "run", Message: "failed"}
			case "interrupted_signal":
				record.End.EndReason = "interrupted"
				record.End.Signal = "SIGKILL"
			case "error_missing":
				record.End.EndReason = "error"
			case "error_stage":
				record.End.EndReason = "error"
				record.End.Error = &Error{Message: "failed"}
			case "error_message":
				record.End.EndReason = "error"
				record.End.Error = &Error{Stage: "run"}
			case "error_signal":
				record.End.EndReason = "error"
				record.End.Error = &Error{Stage: "run", Message: "failed"}
				record.End.Signal = "SIGINT"
			}
			var data bytes.Buffer
			for _, r := range records {
				if err := json.NewEncoder(&data).Encode(r); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(path, data.Bytes(), 0600); err != nil {
				t.Fatal(err)
			}
			if _, _, err := readRecords(t, path); err == nil {
				t.Fatal("reader accepted contradictory footer")
			}
			if scenario != "timestamp" { // Finish supplies one timestamp for both fields.
				writer, err := Open(filepath.Join(t.TempDir(), "invalid.jsonl"))
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = writer.Close() }()
				if err := writer.Start(testSession()); err != nil {
					t.Fatal(err)
				}
				if err := writer.Finish(*record.End); err == nil {
					t.Fatal("writer accepted contradictory footer")
				}
			}
		})
	}
}
