package service

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/spf13/viper"

	"github.com/nxtrace/NTrace-core/ipgeo"
	"github.com/nxtrace/NTrace-core/trace"
	mtutrace "github.com/nxtrace/NTrace-core/trace/mtu"
	"github.com/nxtrace/NTrace-core/util"
)

func TestNormalizeDataProviderCanonicalizesNextTraceAPIAliases(t *testing.T) {
	for _, input := range []string{
		ipgeo.NextTraceAPIProvider,
		"nexttrace-api",
		"NEXTTRACE-API",
		"LeoMoeAPI",
		"leomoeapi",
		"LeoMoe",
	} {
		t.Run(input, func(t *testing.T) {
			if got := normalizeDataProvider(input, ""); got != ipgeo.NextTraceAPIProvider {
				t.Fatalf("normalizeDataProvider(%q) = %q, want %q", input, got, ipgeo.NextTraceAPIProvider)
			}
		})
	}
}

func TestResolveDataProviderCanonicalizesEnvironmentOverride(t *testing.T) {
	oldEnvDataProvider := util.EnvDataProvider
	defer func() { util.EnvDataProvider = oldEnvDataProvider }()
	util.EnvDataProvider = "leomoeapi"

	req := TraceRequest{DataProvider: "NEXTTRACE-API"}
	got, needsV3 := resolveDataProvider(&req)
	if got != ipgeo.NextTraceAPIProvider {
		t.Fatalf("resolveDataProvider() = %q, want %q", got, ipgeo.NextTraceAPIProvider)
	}
	if !needsV3 {
		t.Fatal("resolveDataProvider() needsV3 = false, want true")
	}
}

func TestResolveDataProviderAppliesDN42EnvironmentOverride(t *testing.T) {
	t.Chdir(t.TempDir())
	oldEnvDataProvider := util.EnvDataProvider
	defer func() { util.EnvDataProvider = oldEnvDataProvider }()
	util.EnvDataProvider = "dn42"

	req := TraceRequest{DataProvider: ipgeo.NextTraceAPIProvider}
	got, needsV3 := resolveDataProvider(&req)
	if got != "DN42" || needsV3 || !req.DN42 || !req.DisableMaptrace {
		t.Fatalf("resolveDataProvider() = (%q, %v, DN42=%v, disableMaptrace=%v)", got, needsV3, req.DN42, req.DisableMaptrace)
	}
}

func TestMCPTracerouteServiceResponseCanonicalizesLegacyProvider(t *testing.T) {
	restore := stubServiceRuntimeForTests(t)
	defer restore()
	tracerouteWithContextFn = func(context.Context, trace.Method, trace.Config) (*trace.Result, error) {
		return &trace.Result{}, nil
	}

	response, err := New().Traceroute(context.Background(), TraceRequest{
		Target:          "192.0.2.1",
		DataProvider:    "lEoMoEaPi",
		DisableMaptrace: true,
	})
	if err != nil {
		t.Fatalf("Traceroute returned error: %v", err)
	}
	if response.DataProvider != ipgeo.NextTraceAPIProvider {
		t.Fatalf("data_provider = %q, want %q", response.DataProvider, ipgeo.NextTraceAPIProvider)
	}
}

func TestMTRParameterBoundariesMatchMCPBehavior(t *testing.T) {
	caps, err := New().Capabilities(context.Background(), CapabilitiesRequest{})
	if err != nil {
		t.Fatalf("Capabilities returned error: %v", err)
	}
	tools := map[string]ParameterBoundaries{}
	for _, tool := range caps.Tools {
		tools[tool.Name] = tool.Parameters
	}
	report := requireToolBoundaries(t, tools, "nexttrace_mtr_report")
	raw := requireToolBoundaries(t, tools, "nexttrace_mtr_raw")

	for _, params := range []struct {
		name       string
		boundaries ParameterBoundaries
		supported  []string
		notApp     []string
	}{
		{
			name:       "report",
			boundaries: report,
			supported:  []string{"target", "hop_interval_ms", "max_per_hop"},
			notApp:     []string{"queries", "packet_interval", "ttl_interval"},
		},
		{
			name:       "raw",
			boundaries: raw,
			supported:  []string{"target", "hop_interval_ms", "max_per_hop", "duration_ms"},
			notApp:     []string{"queries", "packet_interval", "ttl_interval"},
		},
	} {
		t.Run(params.name, func(t *testing.T) {
			for _, param := range params.supported {
				if !containsParam(params.boundaries.Supported, param) {
					t.Fatalf("%s supported missing %s: %+v", params.name, param, params.boundaries)
				}
			}
			for _, param := range params.notApp {
				if containsParam(params.boundaries.Supported, param) {
					t.Fatalf("%s supported includes non-applicable %s: %+v", params.name, param, params.boundaries)
				}
				if !containsParam(params.boundaries.NotApplicable, param) {
					t.Fatalf("%s not_applicable missing %s: %+v", params.name, param, params.boundaries)
				}
			}
		})
	}
}

func requireToolBoundaries(t *testing.T, tools map[string]ParameterBoundaries, name string) ParameterBoundaries {
	t.Helper()
	boundaries, ok := tools[name]
	if ok {
		return boundaries
	}
	names := make([]string, 0, len(tools))
	for toolName := range tools {
		names = append(names, toolName)
	}
	sort.Strings(names)
	t.Fatalf("Capabilities missing tool %s; got tools=%v", name, names)
	return ParameterBoundaries{}
}

func TestMTRRawReturnsParentCancellation(t *testing.T) {
	restore := stubServiceRuntimeForTests(t)
	defer restore()

	runMTRRawFn = func(context.Context, trace.Method, trace.Config, trace.MTRRawOptions, trace.MTRRawOnRecord) error {
		return context.Canceled
	}
	_, err := New().MTRRaw(context.Background(), MTRRawRequest{
		TraceRequest: TraceRequest{Target: "192.0.2.1", DataProvider: "disable-geoip"},
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("MTRRaw error = %v, want context.Canceled", err)
	}

	parent, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	cancel()
	errStub := errors.New("stub error")
	runMTRRawFn = func(context.Context, trace.Method, trace.Config, trace.MTRRawOptions, trace.MTRRawOnRecord) error {
		return errStub
	}
	_, err = New().MTRRaw(parent, MTRRawRequest{
		TraceRequest: TraceRequest{Target: "192.0.2.1", DataProvider: "disable-geoip"},
		DurationMs:   1000,
	})
	if errors.Is(err, errStub) {
		t.Fatalf("MTRRaw deadline error = %v, want parent context deadline", err)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("MTRRaw deadline error = %v, want context.DeadlineExceeded", err)
	}
}

func TestMTRRawAllowsLocalDurationTimeout(t *testing.T) {
	restore := stubServiceRuntimeForTests(t)
	defer restore()

	runMTRRawFn = func(_ context.Context, _ trace.Method, _ trace.Config, _ trace.MTRRawOptions, onRecord trace.MTRRawOnRecord) error {
		onRecord(trace.MTRRawRecord{TTL: 1, Success: true, IP: "192.0.2.1"})
		return context.DeadlineExceeded
	}
	resp, err := New().MTRRaw(context.Background(), MTRRawRequest{
		TraceRequest: TraceRequest{Target: "192.0.2.1", DataProvider: "disable-geoip"},
		DurationMs:   1,
	})
	if err != nil {
		t.Fatalf("MTRRaw returned error: %v", err)
	}
	if len(resp.Records) != 1 || resp.Records[0].IP != "192.0.2.1" {
		t.Fatalf("MTRRaw records = %+v, want one preserved record", resp.Records)
	}
	if resp.PathEnd != nil {
		t.Fatalf("local duration timeout fabricated path_end = %#v", resp.PathEnd)
	}
}

func TestMTRRawLocalDurationTimeoutPreservesSemanticPathEnd(t *testing.T) {
	restore := stubServiceRuntimeForTests(t)
	defer restore()

	runMTRRawFn = func(_ context.Context, _ trace.Method, _ trace.Config, opts trace.MTRRawOptions, _ trace.MTRRawOnRecord) error {
		opts.OnPathEnd(&trace.StopReason{Hop: 2, Reason: trace.StopReasonUnreachable, Markers: []string{"!H"}})
		return context.DeadlineExceeded
	}
	resp, err := New().MTRRaw(context.Background(), MTRRawRequest{
		TraceRequest: TraceRequest{Target: "192.0.2.1", DataProvider: "disable-geoip"},
		DurationMs:   1,
	})
	if err != nil {
		t.Fatalf("MTRRaw returned error: %v", err)
	}
	if resp.PathEnd == nil || resp.PathEnd.Hop != 2 || resp.PathEnd.Reason != trace.StopReasonUnreachable || len(resp.PathEnd.Markers) != 1 || resp.PathEnd.Markers[0] != "!H" {
		t.Fatalf("duration timeout path_end = %#v, want unreachable !H", resp.PathEnd)
	}
}

func TestMTRResponsesUseMTRParameterBoundaries(t *testing.T) {
	restore := stubServiceRuntimeForTests(t)
	defer restore()

	runMTRFn = func(_ context.Context, _ trace.Method, _ trace.Config, opts trace.MTROptions, onUpdate trace.MTROnSnapshot) error {
		opts.OnPathEnd(&trace.StopReason{Hop: 1, Reason: trace.StopReasonDestination, Responses: []string{"ICMP Echo Reply"}})
		onUpdate(1, []trace.MTRHopStat{{TTL: 1, IP: "192.0.2.1", Geo: &ipgeo.IPGeoData{}}})
		return nil
	}
	runMTRRawFn = func(_ context.Context, _ trace.Method, _ trace.Config, opts trace.MTRRawOptions, onRecord trace.MTRRawOnRecord) error {
		opts.OnPathEnd(&trace.StopReason{Hop: 1, Reason: trace.StopReasonUnreachable, Markers: []string{"!H"}})
		onRecord(trace.MTRRawRecord{TTL: 1, Success: true, IP: "192.0.2.1"})
		return nil
	}

	report, err := New().MTRReport(context.Background(), MTRReportRequest{
		TraceRequest: TraceRequest{Target: "192.0.2.1", DataProvider: "disable-geoip"},
	})
	if err != nil {
		t.Fatalf("MTRReport returned error: %v", err)
	}
	assertMTRBoundaries(t, "report", report.Parameters, false)
	if report.PathEnd == nil || report.PathEnd.Reason != trace.StopReasonDestination {
		t.Fatalf("report path_end = %#v, want destination", report.PathEnd)
	}
	if len(report.Stats) != 1 || report.Stats[0].Geo == nil || report.Stats[0].Geo.Router == nil {
		t.Fatalf("report geo = %#v, want schema-safe non-nil router", report.Stats)
	}

	raw, err := New().MTRRaw(context.Background(), MTRRawRequest{
		TraceRequest: TraceRequest{Target: "192.0.2.1", DataProvider: "disable-geoip"},
		MaxPerHop:    1,
	})
	if err != nil {
		t.Fatalf("MTRRaw returned error: %v", err)
	}
	assertMTRBoundaries(t, "raw", raw.Parameters, true)
	if raw.PathEnd == nil || raw.PathEnd.Reason != trace.StopReasonUnreachable || len(raw.PathEnd.Markers) != 1 || raw.PathEnd.Markers[0] != "!H" {
		t.Fatalf("raw path_end = %#v, want unreachable !H", raw.PathEnd)
	}
}

func TestMTRReportCarriesPinnedDN42SourceAndRefresh(t *testing.T) {
	restore := stubServiceRuntimeForTests(t)
	defer restore()
	t.Chdir(t.TempDir())

	dir := t.TempDir()
	geoFeedPath := filepath.Join(dir, "geofeed.csv")
	ptrPath := filepath.Join(dir, "ptr.csv")
	if err := os.WriteFile(geoFeedPath, []byte("10.0.0.0/8,us,US,First\n"), 0o600); err != nil {
		t.Fatalf("write first geofeed: %v", err)
	}
	if err := os.WriteFile(ptrPath, nil, 0o600); err != nil {
		t.Fatalf("write ptr: %v", err)
	}
	previousGeoFeedPath := viper.Get("geoFeedPath")
	previousPtrPath := viper.Get("ptrPath")
	viper.Set("geoFeedPath", geoFeedPath)
	viper.Set("ptrPath", ptrPath)
	t.Cleanup(func() {
		viper.Set("geoFeedPath", previousGeoFeedPath)
		viper.Set("ptrPath", previousPtrPath)
	})

	runMTRFn = func(_ context.Context, _ trace.Method, cfg trace.Config, _ trace.MTROptions, _ trace.MTROnSnapshot) error {
		if !cfg.DN42 || cfg.IPGeoSource == nil || cfg.IPGeoDescriptor == nil || cfg.RefreshIPGeoSource == nil {
			return errors.New("MTR did not receive the DN42 source session")
		}
		if descriptor := cfg.IPGeoDescriptor(); descriptor.Namespace != ipgeo.SourceNamespaceDN42 || !descriptor.HasGeneration {
			return fmt.Errorf("MTR descriptor = %+v", descriptor)
		}
		first, err := cfg.IPGeoSource("10.0.0.1", time.Second, "en", false)
		if err != nil || first.City != "First" {
			return fmt.Errorf("first DN42 source = (%+v, %v)", first, err)
		}
		if err := os.WriteFile(geoFeedPath, []byte("10.0.0.0/8,us,US,Second City\n"), 0o600); err != nil {
			return err
		}
		stillFirst, err := cfg.IPGeoSource("10.0.0.1", time.Second, "en", false)
		if err != nil || stillFirst.City != "First" {
			return fmt.Errorf("pinned DN42 source = (%+v, %v)", stillFirst, err)
		}
		cfg.RefreshIPGeoSource()
		second, err := cfg.IPGeoSource("10.0.0.1", time.Second, "en", false)
		if err != nil || second.City != "Second City" {
			return fmt.Errorf("refreshed DN42 source = (%+v, %v)", second, err)
		}
		return nil
	}

	if _, err := New().MTRReport(context.Background(), MTRReportRequest{
		TraceRequest: TraceRequest{
			Target:       "10.0.0.1",
			DataProvider: "DN42",
			DisableRDNS:  true,
		},
		MaxPerHop: 1,
	}); err != nil {
		t.Fatalf("MTRReport returned error: %v", err)
	}
}

func TestNewTraceStopReasonCopiesStableFields(t *testing.T) {
	core := &trace.StopReason{
		Hop:       7,
		Reason:    trace.StopReasonUnreachable,
		Responses: []string{"ICMP Host Unreachable"},
		Markers:   []string{"!H"},
	}
	got := NewTraceStopReason(core)
	core.Responses[0] = "mutated"
	core.Markers[0] = "mutated"
	if got == nil || got.Hop != 7 || got.Reason != trace.StopReasonUnreachable || got.Responses[0] != "ICMP Host Unreachable" || got.Markers[0] != "!H" {
		t.Fatalf("NewTraceStopReason() = %#v", got)
	}
}

func TestMTUTraceInitializesDefaultNextTraceAPIV3Runtime(t *testing.T) {
	restore := stubServiceRuntimeForTests(t)
	defer restore()

	var ensureCalls int
	ensureNextTraceAPIV3ConnectionFn = func(context.Context) {
		ensureCalls++
	}
	runMTUTraceFn = func(_ context.Context, cfg mtutrace.Config) (*mtutrace.Result, error) {
		return &mtutrace.Result{
			Target:     cfg.Target,
			ResolvedIP: cfg.DstIP.String(),
			Protocol:   "udp",
			IPVersion:  4,
			StartMTU:   1500,
			PathMTU:    1500,
		}, nil
	}

	resp, err := New().MTUTrace(context.Background(), MTUTraceRequest{Target: "192.0.2.1"})
	if err != nil {
		t.Fatalf("MTUTrace returned error: %v", err)
	}
	if ensureCalls != 1 {
		t.Fatalf("ensureNextTraceAPIV3Connection calls = %d, want 1", ensureCalls)
	}
	if resp.ResolvedIP != "192.0.2.1" {
		t.Fatalf("ResolvedIP = %q, want 192.0.2.1", resp.ResolvedIP)
	}
}

func TestAnnotateIPsAndGeoLookupInitializeDefaultNextTraceAPIV3Runtime(t *testing.T) {
	restore := stubServiceRuntimeForTests(t)
	defer restore()

	var ensureCalls int
	var lookupDescriptor ipgeo.SourceDescriptor
	ensureNextTraceAPIV3ConnectionFn = func(context.Context) {
		ensureCalls++
	}
	lookupIPGeoWithDescriptorFn = func(_ context.Context, descriptor ipgeo.SourceDescriptor, _ string, _ bool, _ int, query string) (*ipgeo.IPGeoData, error) {
		lookupDescriptor = descriptor
		return &ipgeo.IPGeoData{IP: query, Asnumber: "AS13335"}, nil
	}

	if _, err := New().AnnotateIPs(context.Background(), AnnotateIPsRequest{Text: "plain text"}); err != nil {
		t.Fatalf("AnnotateIPs returned error: %v", err)
	}
	if _, err := New().GeoLookup(context.Background(), GeoLookupRequest{Query: "8.8.8.8"}); err != nil {
		t.Fatalf("GeoLookup returned error: %v", err)
	}
	if ensureCalls != 2 {
		t.Fatalf("ensureNextTraceAPIV3Connection calls = %d, want 2", ensureCalls)
	}
	if lookupDescriptor.Namespace != ipgeo.SourceNamespaceNextTraceAPI || lookupDescriptor.Backend != ipgeo.SourceBackendNextTraceAPIV3 {
		t.Fatalf("GeoLookup descriptor = %+v, want NextTrace API v3", lookupDescriptor)
	}
}

func TestGeoLookupUsesNextTraceAPIV4FastIPInsteadOfV3WebSocketWhenTokenConfigured(t *testing.T) {
	restore := stubServiceRuntimeForTests(t)
	defer restore()
	t.Setenv(util.EnvNextTraceAPIV4TokenKey, "v4-token")

	var ensureCalls int
	var prepareCalls int
	var lookupDescriptor ipgeo.SourceDescriptor
	ensureNextTraceAPIV3ConnectionFn = func(context.Context) {
		ensureCalls++
	}
	prepareNextTraceAPIV4FastIPFn = func(ctx context.Context, enableOutput bool) error {
		prepareCalls++
		if ctx == nil {
			t.Fatal("PrepareNextTraceAPIV4FastIP context = nil")
		}
		if enableOutput {
			t.Fatal("PrepareNextTraceAPIV4FastIP enableOutput = true, want false for service runtime")
		}
		return nil
	}
	lookupIPGeoWithDescriptorFn = func(_ context.Context, descriptor ipgeo.SourceDescriptor, _ string, _ bool, _ int, query string) (*ipgeo.IPGeoData, error) {
		lookupDescriptor = descriptor
		return &ipgeo.IPGeoData{IP: query, Asnumber: "AS13335"}, nil
	}

	if _, err := New().GeoLookup(context.Background(), GeoLookupRequest{Query: "8.8.8.8"}); err != nil {
		t.Fatalf("GeoLookup returned error: %v", err)
	}
	if ensureCalls != 0 {
		t.Fatalf("ensureNextTraceAPIV3Connection calls = %d, want 0 with API v4 token", ensureCalls)
	}
	if prepareCalls != 1 {
		t.Fatalf("PrepareNextTraceAPIV4FastIP calls = %d, want 1", prepareCalls)
	}
	if lookupDescriptor.Namespace != ipgeo.SourceNamespaceNextTraceAPI || lookupDescriptor.Backend != ipgeo.SourceBackendNextTraceAPIV4 {
		t.Fatalf("GeoLookup descriptor = %+v, want NextTrace API v4", lookupDescriptor)
	}
}

func TestGeoLookupFallsBackToNextTraceAPIV3WebSocketWhenV4FastIPFails(t *testing.T) {
	restore := stubServiceRuntimeForTests(t)
	defer restore()
	t.Setenv(util.EnvNextTraceAPIV4TokenKey, "v4-token")

	var ensureCalls int
	var prepareCalls int
	ensureNextTraceAPIV3ConnectionFn = func(context.Context) {
		ensureCalls++
	}
	prepareNextTraceAPIV4FastIPFn = func(context.Context, bool) error {
		prepareCalls++
		return errors.New("fastip unavailable")
	}
	lookupIPGeoWithDescriptorFn = func(_ context.Context, _ ipgeo.SourceDescriptor, _ string, _ bool, _ int, query string) (*ipgeo.IPGeoData, error) {
		return &ipgeo.IPGeoData{IP: query, Asnumber: "AS13335"}, nil
	}

	if _, err := New().GeoLookup(context.Background(), GeoLookupRequest{Query: "8.8.8.8"}); err != nil {
		t.Fatalf("GeoLookup returned error: %v", err)
	}
	if prepareCalls != 1 {
		t.Fatalf("PrepareNextTraceAPIV4FastIP calls = %d, want 1", prepareCalls)
	}
	if ensureCalls != 1 {
		t.Fatalf("ensureNextTraceAPIV3Connection calls = %d, want 1 after API v4 preheat failure", ensureCalls)
	}
}

func TestAnnotateIPsAndGeoLookupSkipNextTraceAPIRuntimeForDisabledGeoIP(t *testing.T) {
	restore := stubServiceRuntimeForTests(t)
	defer restore()

	var ensureCalls int
	ensureNextTraceAPIV3ConnectionFn = func(context.Context) {
		ensureCalls++
	}
	lookupIPGeoWithDescriptorFn = func(_ context.Context, _ ipgeo.SourceDescriptor, _ string, _ bool, _ int, query string) (*ipgeo.IPGeoData, error) {
		return &ipgeo.IPGeoData{IP: query}, nil
	}

	if _, err := New().AnnotateIPs(context.Background(), AnnotateIPsRequest{Text: "plain text", DataProvider: "disable-geoip"}); err != nil {
		t.Fatalf("AnnotateIPs returned error: %v", err)
	}
	if _, err := New().GeoLookup(context.Background(), GeoLookupRequest{Query: "8.8.8.8", DataProvider: "disable-geoip"}); err != nil {
		t.Fatalf("GeoLookup returned error: %v", err)
	}
	if ensureCalls != 0 {
		t.Fatalf("ensureNextTraceAPIV3Connection calls = %d, want 0", ensureCalls)
	}
}

func TestAnnotateIPsAndGeoLookupDN42BypassReservedFilter(t *testing.T) {
	restore := stubServiceRuntimeForTests(t)
	defer restore()

	dir := t.TempDir()
	t.Chdir(dir)
	geoFeedPath := filepath.Join(dir, "geofeed.csv")
	ptrPath := filepath.Join(dir, "ptr.csv")
	if err := os.WriteFile(geoFeedPath, []byte("10.0.0.0/8,us,US,Test City,AS4242420001,Example Owner\n"), 0o600); err != nil {
		t.Fatalf("write geofeed: %v", err)
	}
	if err := os.WriteFile(ptrPath, nil, 0o600); err != nil {
		t.Fatalf("write ptr: %v", err)
	}
	previousGeoFeedPath := viper.Get("geoFeedPath")
	previousPtrPath := viper.Get("ptrPath")
	viper.Set("geoFeedPath", geoFeedPath)
	viper.Set("ptrPath", ptrPath)
	t.Cleanup(func() {
		viper.Set("geoFeedPath", previousGeoFeedPath)
		viper.Set("ptrPath", previousPtrPath)
	})

	annotated, err := New().AnnotateIPs(context.Background(), AnnotateIPsRequest{
		Text:         "router 10.0.0.1",
		DataProvider: "DN42",
		Language:     "en",
	})
	if err != nil {
		t.Fatalf("AnnotateIPs returned error: %v", err)
	}
	if !strings.Contains(annotated.Text, "AS4242420001, United States, Test City, Example Owner") {
		t.Fatalf("AnnotateIPs text = %q", annotated.Text)
	}

	lookup, err := New().GeoLookup(context.Background(), GeoLookupRequest{
		Query:        "10.0.0.1",
		DataProvider: "DN42",
		Language:     "en",
	})
	if err != nil {
		t.Fatalf("GeoLookup returned error: %v", err)
	}
	if lookup.Geo == nil || lookup.Geo.Asnumber != "AS4242420001" || lookup.Geo.Country != "United States" {
		t.Fatalf("GeoLookup geo = %+v", lookup.Geo)
	}

	var gotMTUConfig mtutrace.Config
	runMTUTraceFn = func(_ context.Context, cfg mtutrace.Config) (*mtutrace.Result, error) {
		gotMTUConfig = cfg
		return &mtutrace.Result{Target: cfg.Target, ResolvedIP: cfg.DstIP.String(), Protocol: "udp"}, nil
	}
	if _, err := New().MTUTrace(context.Background(), MTUTraceRequest{Target: "10.0.0.1", DataProvider: "DN42"}); err != nil {
		t.Fatalf("MTUTrace returned error: %v", err)
	}
	if !gotMTUConfig.DN42 || gotMTUConfig.IPGeoSource == nil {
		t.Fatalf("MTU DN42 config = %+v", gotMTUConfig)
	}
}

func containsParam(params []string, target string) bool {
	for _, param := range params {
		if param == target {
			return true
		}
	}
	return false
}

func assertMTRBoundaries(t *testing.T, name string, boundaries ParameterBoundaries, wantDuration bool) {
	t.Helper()

	if containsParam(boundaries.Supported, "queries") {
		t.Fatalf("%s supported includes queries: %+v", name, boundaries)
	}
	if !containsParam(boundaries.NotApplicable, "queries") {
		t.Fatalf("%s not_applicable missing queries: %+v", name, boundaries)
	}
	if !containsParam(boundaries.Supported, "hop_interval_ms") || !containsParam(boundaries.Supported, "max_per_hop") {
		t.Fatalf("%s supported missing MTR controls: %+v", name, boundaries)
	}
	if gotDuration := containsParam(boundaries.Supported, "duration_ms"); gotDuration != wantDuration {
		t.Fatalf("%s duration_ms supported = %v, want %v: %+v", name, gotDuration, wantDuration, boundaries)
	}
}

func stubServiceRuntimeForTests(t *testing.T) func() {
	t.Helper()

	oldEnsureNextTraceAPIV3 := ensureNextTraceAPIV3ConnectionFn
	oldPrepareFastIP := prepareNextTraceAPIV4FastIPFn
	oldTracerouteWithContext := tracerouteWithContextFn
	oldLookupIPGeoWithDescriptor := lookupIPGeoWithDescriptorFn
	oldRunMTR := runMTRFn
	oldRunMTRRaw := runMTRRawFn
	oldRunMTU := runMTUTraceFn
	oldEnvDataProvider := util.EnvDataProvider
	tokenDir := t.TempDir()
	t.Setenv(util.EnvNextTraceAPIV4TokenKey, "")
	t.Setenv("TMPDIR", tokenDir)
	t.Setenv("TMP", tokenDir)
	t.Setenv("TEMP", tokenDir)
	util.EnvDataProvider = ""
	ensureNextTraceAPIV3ConnectionFn = func(context.Context) {}
	prepareNextTraceAPIV4FastIPFn = func(context.Context, bool) error { return nil }
	return func() {
		ensureNextTraceAPIV3ConnectionFn = oldEnsureNextTraceAPIV3
		prepareNextTraceAPIV4FastIPFn = oldPrepareFastIP
		tracerouteWithContextFn = oldTracerouteWithContext
		lookupIPGeoWithDescriptorFn = oldLookupIPGeoWithDescriptor
		runMTRFn = oldRunMTR
		runMTRRawFn = oldRunMTRRaw
		runMTUTraceFn = oldRunMTU
		util.EnvDataProvider = oldEnvDataProvider
	}
}
