package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/nxtrace/NTrace-core/internal/mtrsession"
	"github.com/nxtrace/NTrace-core/trace"
	"github.com/nxtrace/NTrace-core/util"
)

func TestMTRRecordFlagsRespectValues(t *testing.T) {
	for _, args := range [][]string{{"--mtr-record", "out"}, {"--mtr-record=out"}, {"-t", "--mtr-record", "--doctor"}} {
		if !containsMTRRecordFlag(args) {
			t.Fatalf("missing record flag: %v", args)
		}
	}
	for _, args := range [][]string{{"--", "--mtr-record"}, {"--file", "--mtr-record"}, {"--mtr-replay", "--mtr-record"}} {
		if containsMTRRecordFlag(args) {
			t.Fatalf("mistook value for recording option: %v", args)
		}
	}
	if containsDoctorFlag([]string{"-t", "--mtr-record", "--doctor"}) {
		t.Fatal("recording filename invoked doctor")
	}
	if requestsMTRJSON([]string{"-t", "--mtr-record", "--json"}) {
		t.Fatal("recording filename invoked JSON output")
	}
	if containsFWMarkFlag([]string{"-t", "--mtr-record", "--fwmark"}) {
		t.Fatal("recording filename invoked fwmark")
	}
}

func TestMTRRecordOpenFailurePrecedesResolution(t *testing.T) {
	old := domainLookupFn
	t.Cleanup(func() { domainLookupFn = old })
	domainLookupFn = func(context.Context, string, string, string, bool) (net.IP, error) {
		t.Fatal("record open failure reached DNS")
		return nil, nil
	}
	opts := testMTRJSONOptions()
	opts.RecordPath = filepath.Join(t.TempDir(), "existing")
	if err := os.WriteFile(opts.RecordPath, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := runMTRJSON(t.Context(), opts, &stdout, &stderr); code != 1 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	data, err := os.ReadFile(opts.RecordPath)
	if err != nil || string(data) != "keep" {
		t.Fatal("overwrote recording")
	}
}

func TestMTRRecordedHumanOptionsPreserveCountAndRandomPort(t *testing.T) {
	for _, tc := range []struct {
		modes effectiveMTRModes
		count int
	}{
		{effectiveMTRModes{mtr: true, report: true}, 10},
		{effectiveMTRModes{mtr: true, report: true, raw: true}, 0},
		{effectiveMTRModes{mtr: true}, 0},
	} {
		opts := testMTRJSONOptions()
		opts.Method, opts.Config.SrcPort, opts.MaxPerHop = trace.UDPTrace, -1, 0
		if err := normalizeMTRRecordedOptions(&opts, tc.modes, io.Discard); err != nil {
			t.Fatal(err)
		}
		if opts.Config.SrcPort != -1 || opts.MaxPerHop != tc.count {
			t.Fatalf("changed human semantics: %+v", opts)
		}
	}
}

func TestMTRRecordedHumanKeepsAddressSelection(t *testing.T) {
	old := domainLookupFn
	t.Cleanup(func() { domainLookupFn = old })
	called := false
	domainLookupFn = func(_ context.Context, _, _, _ string, disableOutput bool) (net.IP, error) {
		called = true
		if disableOutput {
			t.Fatal("recording suppressed human address selection")
		}
		return nil, errors.New("test lookup stop")
	}
	opts := testMTRJSONOptions()
	opts.RecordPath = filepath.Join(t.TempDir(), "selection.jsonl")
	code := runMTRRecorded(t.Context(), opts, effectiveMTRModes{mtr: true}, false, 0, "", nil, io.Discard)
	if !called || code != 1 {
		t.Fatalf("lookup=%v code=%d", called, code)
	}
}

func TestMTRRecordInitializationFailureIsReadable(t *testing.T) {
	old := domainLookupFn
	t.Cleanup(func() { domainLookupFn = old })
	domainLookupFn = func(context.Context, string, string, string, bool) (net.IP, error) {
		return nil, errors.New("test resolution failure")
	}
	opts := testMTRJSONOptions()
	opts.RecordPath = filepath.Join(t.TempDir(), "failed.jsonl")
	var stdout, stderr bytes.Buffer
	if code := runMTRJSON(t.Context(), opts, &stdout, &stderr); code != 1 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	records := readMTRRecordingFixture(t, opts.RecordPath)
	if len(records) != 2 || records[0].Session.EffectiveParameters != nil || records[1].End.EndReason != "error" || records[1].End.Error.Stage != "resolve" {
		t.Fatalf("invalid failed session: %+v", records)
	}
}

func readMTRRecordingFixture(t *testing.T, path string) []mtrsession.Record {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	decoder := json.NewDecoder(f)
	var records []mtrsession.Record
	for {
		var record mtrsession.Record
		err := decoder.Decode(&record)
		if err == io.EOF {
			return records
		}
		if err != nil {
			t.Fatal(err)
		}
		records = append(records, record)
	}
}

func TestMTRJSONRecordedReportRebuildsSameSnapshot(t *testing.T) {
	oldLookup, oldReport := domainLookupFn, runMTRReportFn
	oldPort, oldDst := util.SrcPort, util.DstIP
	t.Cleanup(func() {
		domainLookupFn, runMTRReportFn = oldLookup, oldReport
		util.SrcPort, util.DstIP = oldPort, oldDst
	})
	domainLookupFn = func(context.Context, string, string, string, bool) (net.IP, error) {
		return net.ParseIP("127.0.0.1"), nil
	}
	runMTRReportFn = func(_ context.Context, _ trace.Method, cfg trace.Config, opts trace.MTROptions, snapshot trace.MTROnSnapshot) error {
		state := trace.NewMTRReplayState(true, cfg.MaxHops)
		events := []trace.MTRSessionEvent{
			{Type: trace.MTRSessionProbeEvent, Iteration: 1, Probe: &trace.MTRSessionProbe{TTL: 1, IP: "192.0.2.1", Success: true, RTT: 1234567, CompletedAt: time.Now()}},
			{Type: trace.MTRSessionProbeEvent, Iteration: 1, Probe: &trace.MTRSessionProbe{TTL: 1, CompletedAt: time.Now()}},
			{Type: trace.MTRSessionMetadataEvent, Metadata: &trace.MTRSessionMetadata{IP: "192.0.2.1", Host: "router.example"}},
			{Type: trace.MTRSessionPathEndEvent, PathEnd: &trace.StopReason{Hop: cfg.MaxHops, Reason: trace.StopReasonMaxHops}},
		}
		for _, event := range events {
			event.At = time.Now()
			if err := state.Apply(event); err != nil {
				return err
			}
			if opts.OnEvent != nil {
				if err := opts.OnEvent(event); err != nil {
					return err
				}
			}
		}
		opts.OnPathEnd(state.PathEnd())
		result := state.Snapshot()
		snapshot(result.Iteration, result.Stats)
		return nil
	}
	opts := testMTRJSONOptions()
	opts.Report = true
	opts.RecordDisplay = mtrRecordingDisplay{hostMode: 4, showIPs: true, wide: true}
	var plain, recorded, stderr bytes.Buffer
	if code := runMTRJSON(t.Context(), opts, &plain, &stderr); code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	opts.RecordPath = filepath.Join(t.TempDir(), "report.jsonl")
	if code := runMTRJSON(t.Context(), opts, &recorded, &stderr); code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	var before, after mtrJSONReport
	if err := json.Unmarshal(plain.Bytes(), &before); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(recorded.Bytes(), &after); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before.Stats, after.Stats) || !reflect.DeepEqual(before.EffectiveParameters, after.EffectiveParameters) {
		t.Fatal("recording changed JSON report data")
	}
	state := trace.NewMTRReplayState(true, opts.Config.MaxHops)
	for _, record := range readMTRRecordingFixture(t, opts.RecordPath) {
		if record.Session != nil && (record.Session.Display.HostMode != 4 || !record.Session.Display.ShowIPs || !record.Session.Display.Wide) {
			t.Fatal("recording lost initial display settings")
		}
		if record.Type != mtrsession.StartEvent && record.Type != mtrsession.EndEvent {
			if err := state.Apply(record.MTRSessionEvent); err != nil {
				t.Fatal(err)
			}
		}
	}
	if !reflect.DeepEqual(state.Snapshot().Stats, after.Stats) || !reflect.DeepEqual(state.PathEnd(), after.PathEnd) {
		t.Fatalf("replay mismatch: %+v / %+v", state.Snapshot(), after)
	}
}

func TestMTRRecordCLIRejectsModesBeforeNetwork(t *testing.T) {
	if os.Getenv("NTRACE_TEST_MTR_RECORD_ARGS") == "1" {
		domainLookupFn = func(context.Context, string, string, string, bool) (net.IP, error) {
			panic("invalid recording arguments reached resolution")
		}
		for i, arg := range os.Args {
			if arg == "--" {
				os.Args = append([]string{appBinName}, os.Args[i+1:]...)
				break
			}
		}
		Execute()
		os.Exit(0)
	}
	for _, extra := range [][]string{{"--speed"}, {"--dns"}, {"--doctor"}, {"--mtu"}, {"--deploy"}, {"--mtr-replay", "missing"}, {"--setup-api-v4-token"}, {"--table"}} {
		args := []string{"-test.run=^TestMTRRecordCLIRejectsModesBeforeNetwork$", "--", "--mtr-record", filepath.Join(t.TempDir(), "record"), "127.0.0.1"}
		if enableTraceroute {
			args = append(args, "--mtr")
		}
		args = append(args, extra...)
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		process := exec.CommandContext(ctx, os.Args[0], args...)
		process.Env = append(os.Environ(), "NTRACE_TEST_MTR_RECORD_ARGS=1")
		output, err := process.CombinedOutput()
		cancel()
		var exit *exec.ExitError
		if !errors.As(err, &exit) || exit.ExitCode() != 2 || strings.Contains(string(output), "panic") {
			t.Fatalf("args=%v error=%v output=%s", extra, err, output)
		}
	}
}
