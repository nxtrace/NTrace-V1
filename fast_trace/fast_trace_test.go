package fastTrace

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fatih/color"

	"github.com/nxtrace/NTrace-core/trace"
	"github.com/nxtrace/NTrace-core/util"
	"github.com/nxtrace/NTrace-core/wshandle"
)

func TestTrace(t *testing.T) {
	//pFastTrace := ParamsFastTrace{
	//	SrcDev:         "",
	//	SrcAddr:        "",
	//	BeginHop:       1,
	//	MaxHops:        30,
	//	RDNS:           false,
	//	AlwaysWaitRDNS: false,
	//	Lang:           "",
	//	PktSize:        52,
	//}
	//ft := FastTracer{ParamsFastTrace: pFastTrace}
	//// 建立 WebSocket 连接
	//w := wshandle.New()
	//w.Interrupt = make(chan os.Signal, 1)
	//signal.Notify(w.Interrupt, os.Interrupt)
	//defer func() {
	//	w.Conn.Close()
	//}()
	//fmt.Println("TCP v4")
	//ft.TracerouteMethod = trace.TCPTrace
	//ft.tracert(TestIPsCollection.Beijing.Location, TestIPsCollection.Beijing.EDU)
	//fmt.Println("TCP v6")
	//ft.tracert_v6(TestIPsCollection.Beijing.Location, TestIPsCollection.Beijing.EDU)
	//fmt.Println("ICMP v4")
	//ft.TracerouteMethod = trace.ICMPTrace
	//ft.tracert(TestIPsCollection.Beijing.Location, TestIPsCollection.Beijing.EDU)
	//fmt.Println("ICMP v6")
	//ft.tracert_v6(TestIPsCollection.Beijing.Location, TestIPsCollection.Beijing.EDU)
}

func TestPromptFastTraceChoiceCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	choice, ok := promptFastTraceChoice(ctx, "请选择选项：", "1")
	if ok {
		t.Fatal("promptFastTraceChoice ok = true, want false for canceled context")
	}
	if choice != "" {
		t.Fatalf("promptFastTraceChoice choice = %q, want empty", choice)
	}
}

func TestPromptFastTraceChoiceDeadlineExceededContext(t *testing.T) {
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()

	choice, ok := promptFastTraceChoice(ctx, "请选择选项：", "1")
	if ok {
		t.Fatal("promptFastTraceChoice ok = true, want false for deadline exceeded context")
	}
	if choice != "" {
		t.Fatalf("promptFastTraceChoice choice = %q, want empty", choice)
	}
}

func TestReadFastTestv6ChoiceCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	choice, ok := readFastTestv6Choice(ctx)
	if ok {
		t.Fatal("readFastTestv6Choice ok = true, want false for canceled context")
	}
	if choice != "" {
		t.Fatalf("readFastTestv6Choice choice = %q, want empty", choice)
	}
}

func TestFastTraceStopReasonReachesTerminalAndOutputFile(t *testing.T) {
	t.Setenv("NO_COLOR", "")
	t.Setenv("TERM", "xterm-256color")
	previousTraceroute := fastTraceTracerouteFn
	previousLookup := fastTraceDomainLookupFn
	previousOutput := color.Output
	previousNoColor := color.NoColor
	t.Cleanup(func() {
		fastTraceTracerouteFn = previousTraceroute
		fastTraceDomainLookupFn = previousLookup
		color.Output = previousOutput
		color.NoColor = previousNoColor
	})

	fastTraceDomainLookupFn = func(_ context.Context, host, _, _ string, _ bool) (net.IP, error) {
		return net.ParseIP(host), nil
	}
	reason := &trace.StopReason{Hop: 5, Reason: trace.StopReasonDestination, Responses: []string{"ICMP Echo Reply"}}

	tests := []struct {
		name string
		run  func(outputPath string)
	}{
		{
			name: "file target",
			run: func(outputPath string) {
				runFileTraceTarget(fastTraceTestParams(outputPath), trace.ICMPTrace, IpListElement{Ip: "192.0.2.1", Desc: "file target", Version4: true})
			},
		},
		{
			name: "IPv4 interactive target",
			run: func(outputPath string) {
				f := FastTracer{TracerouteMethod: trace.ICMPTrace, ParamsFastTrace: fastTraceTestParams(outputPath)}
				f.tracert("test", ISPCollection{ISPName: "ISP", IP: "192.0.2.1"})
			},
		},
		{
			name: "IPv6 interactive target",
			run: func(outputPath string) {
				f := FastTracer{TracerouteMethod: trace.ICMPTrace, ParamsFastTrace: fastTraceTestParams(outputPath)}
				f.tracert_v6("test", ISPCollection{ISPName: "ISP", IPv6: "2001:db8::1"})
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var terminal bytes.Buffer
			var styledHop bool
			var calls int
			fastTraceTracerouteFn = func(_ trace.Method, conf trace.Config) (*trace.Result, error) {
				calls++
				if conf.RealtimePrinter == nil {
					t.Fatal("RealtimePrinter = nil, want configured output printer")
				}
				before := terminal.Len()
				conf.RealtimePrinter(&trace.Result{Hops: [][]trace.Hop{{}}}, 0)
				styledHop = strings.Contains(terminal.String()[before:], "\x1b[")
				return &trace.Result{StopReason: reason}, nil
			}
			color.Output = &terminal
			color.NoColor = false
			outputPath := filepath.Join(t.TempDir(), "trace.log")

			tt.run(outputPath)

			if calls != 1 {
				t.Fatalf("Traceroute calls = %d, want 1", calls)
			}
			if !styledHop {
				t.Fatalf("terminal hop output is not styled: %q", terminal.String())
			}
			if got := strings.Count(terminal.String(), "Trace Stopped:"); got != 1 {
				t.Fatalf("terminal stop reason count = %d, want 1; output=%q", got, terminal.String())
			}
			fileOutput, err := os.ReadFile(outputPath)
			if err != nil {
				t.Fatalf("ReadFile output: %v", err)
			}
			if got := strings.Count(string(fileOutput), "Trace Stopped:"); got != 1 {
				t.Fatalf("file stop reason count = %d, want 1; output=%q", got, fileOutput)
			}
			if bytes.Contains(fileOutput, []byte("\x1b[")) {
				t.Fatalf("file contains ANSI escapes: %q", fileOutput)
			}
		})
	}
}

func TestFastTraceTracerErrorDoesNotWriteStopReason(t *testing.T) {
	previousTraceroute := fastTraceTracerouteFn
	previousOutput := color.Output
	previousNoColor := color.NoColor
	t.Cleanup(func() {
		fastTraceTracerouteFn = previousTraceroute
		color.Output = previousOutput
		color.NoColor = previousNoColor
	})

	fastTraceTracerouteFn = func(trace.Method, trace.Config) (*trace.Result, error) {
		return nil, errors.New("probe failed")
	}
	var terminal bytes.Buffer
	color.Output = &terminal
	color.NoColor = true
	outputPath := filepath.Join(t.TempDir(), "trace.log")

	runFileTraceTarget(fastTraceTestParams(outputPath), trace.ICMPTrace, IpListElement{Ip: "192.0.2.1", Desc: "file target", Version4: true})

	if strings.Contains(terminal.String(), "Trace Stopped:") {
		t.Fatalf("terminal contains misleading stop reason: %q", terminal.String())
	}
	fileOutput, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("ReadFile output: %v", err)
	}
	if strings.Contains(string(fileOutput), "Trace Stopped:") {
		t.Fatalf("file contains misleading stop reason: %q", fileOutput)
	}
}

func TestFastTraceNilResultDoesNotPanicOrWriteStopReason(t *testing.T) {
	previousTraceroute := fastTraceTracerouteFn
	previousOutput := color.Output
	previousNoColor := color.NoColor
	t.Cleanup(func() {
		fastTraceTracerouteFn = previousTraceroute
		color.Output = previousOutput
		color.NoColor = previousNoColor
	})

	fastTraceTracerouteFn = func(trace.Method, trace.Config) (*trace.Result, error) {
		return nil, nil
	}
	var terminal bytes.Buffer
	color.Output = &terminal
	color.NoColor = true
	outputPath := filepath.Join(t.TempDir(), "trace.log")

	runFileTraceTarget(fastTraceTestParams(outputPath), trace.ICMPTrace, IpListElement{Ip: "192.0.2.1", Desc: "file target", Version4: true})

	if strings.Contains(terminal.String(), "Trace Stopped:") {
		t.Fatalf("terminal contains misleading stop reason: %q", terminal.String())
	}
}

func TestFileTraceWritesStopReasonForEveryTarget(t *testing.T) {
	previousTraceroute := fastTraceTracerouteFn
	previousOutput := color.Output
	previousNoColor := color.NoColor
	t.Cleanup(func() {
		fastTraceTracerouteFn = previousTraceroute
		color.Output = previousOutput
		color.NoColor = previousNoColor
	})

	reasons := []*trace.StopReason{
		{Hop: 2, Reason: trace.StopReasonDestination, Responses: []string{"ICMP Echo Reply"}},
		{Hop: 4, Reason: trace.StopReasonUnreachable, Responses: []string{"ICMP Host Unreachable"}, Markers: []string{"!H"}},
	}
	var calls int
	fastTraceTracerouteFn = func(trace.Method, trace.Config) (*trace.Result, error) {
		if calls >= len(reasons) {
			t.Fatalf("unexpected traceroute call %d", calls+1)
		}
		reason := reasons[calls]
		calls++
		return &trace.Result{StopReason: reason}, nil
	}

	dir := t.TempDir()
	targetsPath := filepath.Join(dir, "targets.txt")
	if err := os.WriteFile(targetsPath, []byte("192.0.2.1 first\n2001:db8::1 second\n"), 0o600); err != nil {
		t.Fatalf("WriteFile targets: %v", err)
	}
	outputPath := filepath.Join(dir, "trace.log")
	var terminal bytes.Buffer
	color.Output = &terminal
	color.NoColor = true

	testFile(ParamsFastTrace{
		Context:         context.Background(),
		File:            targetsPath,
		MaxHops:         30,
		Timeout:         time.Second,
		OutputPath:      outputPath,
		RuntimePrepared: true,
	}, trace.ICMPTrace)

	if calls != len(reasons) {
		t.Fatalf("Traceroute calls = %d, want %d", calls, len(reasons))
	}
	if got := strings.Count(terminal.String(), "Trace Stopped:"); got != len(reasons) {
		t.Fatalf("terminal stop reason count = %d, want %d; output=%q", got, len(reasons), terminal.String())
	}
	fileOutput, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("ReadFile output: %v", err)
	}
	if got := strings.Count(string(fileOutput), "Trace Stopped:"); got != len(reasons) {
		t.Fatalf("file stop reason count = %d, want %d; output=%q", got, len(reasons), fileOutput)
	}
	first := strings.Index(string(fileOutput), "Destination Reached at Hop 2")
	second := strings.Index(string(fileOutput), "No Continuing Route Observed at Hop 4")
	if first < 0 || second < 0 || first >= second {
		t.Fatalf("file stop reasons out of order: %q", fileOutput)
	}
}

func fastTraceTestParams(outputPath string) ParamsFastTrace {
	return ParamsFastTrace{
		Context:    context.Background(),
		MaxHops:    30,
		Timeout:    time.Second,
		OutputPath: outputPath,
	}
}

func TestTestFileSkipsFastTraceWSWhenRuntimePrepared(t *testing.T) {
	file := emptyFastTraceFile(t)
	oldInit := initFastTraceWSFn
	oldClose := closeFastTraceWSFn
	var initCalls int
	var closeCalls int
	initFastTraceWSFn = func(context.Context) *wshandle.WsConn {
		initCalls++
		return nil
	}
	closeFastTraceWSFn = func(*wshandle.WsConn) {
		closeCalls++
	}
	t.Cleanup(func() {
		initFastTraceWSFn = oldInit
		closeFastTraceWSFn = oldClose
	})

	testFile(ParamsFastTrace{
		Context:         context.Background(),
		File:            file,
		RuntimePrepared: true,
	}, trace.ICMPTrace)

	if initCalls != 0 {
		t.Fatalf("initFastTraceWS calls = %d, want 0 when runtime is prepared", initCalls)
	}
	if closeCalls != 0 {
		t.Fatalf("closeFastTraceWS calls = %d, want 0 when runtime is prepared", closeCalls)
	}
}

func TestTestFileInitializesFastTraceWSByDefault(t *testing.T) {
	isolateFastTraceNextTraceAPIV4TokenFiles(t)
	file := emptyFastTraceFile(t)
	oldInit := initFastTraceWSFn
	oldClose := closeFastTraceWSFn
	var initCalls int
	var closeCalls int
	initFastTraceWSFn = func(context.Context) *wshandle.WsConn {
		initCalls++
		return nil
	}
	closeFastTraceWSFn = func(*wshandle.WsConn) {
		closeCalls++
	}
	t.Cleanup(func() {
		initFastTraceWSFn = oldInit
		closeFastTraceWSFn = oldClose
	})

	testFile(ParamsFastTrace{
		Context: context.Background(),
		File:    file,
	}, trace.ICMPTrace)

	if initCalls != 1 {
		t.Fatalf("initFastTraceWS calls = %d, want 1 by default", initCalls)
	}
	if closeCalls != 1 {
		t.Fatalf("closeFastTraceWS calls = %d, want 1 by default", closeCalls)
	}
}

func TestTestFileSkipsFastTraceWSWhenAPIV4TokenConfigured(t *testing.T) {
	t.Setenv(util.EnvNextTraceAPIV4TokenKey, "v4-token")
	file := emptyFastTraceFile(t)
	oldInit := initFastTraceWSFn
	oldClose := closeFastTraceWSFn
	var initCalls int
	var closeCalls int
	initFastTraceWSFn = func(context.Context) *wshandle.WsConn {
		initCalls++
		return nil
	}
	closeFastTraceWSFn = func(*wshandle.WsConn) {
		closeCalls++
	}
	t.Cleanup(func() {
		initFastTraceWSFn = oldInit
		closeFastTraceWSFn = oldClose
	})

	testFile(ParamsFastTrace{
		Context: context.Background(),
		File:    file,
	}, trace.ICMPTrace)

	if initCalls != 0 {
		t.Fatalf("initFastTraceWS calls = %d, want 0 when API v4 token is configured", initCalls)
	}
	if closeCalls != 0 {
		t.Fatalf("closeFastTraceWS calls = %d, want 0 when API v4 token is configured", closeCalls)
	}
}

func emptyFastTraceFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "targets.txt")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("WriteFile targets: %v", err)
	}
	return path
}

func isolateFastTraceNextTraceAPIV4TokenFiles(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("TMPDIR", dir)
	t.Setenv("TMP", dir)
	t.Setenv("TEMP", dir)
	t.Setenv(util.EnvNextTraceAPIV4TokenKey, "")
}
