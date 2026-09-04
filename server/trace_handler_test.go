package server

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"

	"github.com/nxtrace/NTrace-core/internal/service"
	"github.com/nxtrace/NTrace-core/ipgeo"
	"github.com/nxtrace/NTrace-core/trace"
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

func TestOptionsExposeOnlyCanonicalNextTraceAPIProvider(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	optionsHandler(c)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
	var body struct {
		DataProviders []string       `json:"dataProviders"`
		Defaults      map[string]any `json:"defaultOptions"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode options: %v", err)
	}
	if len(body.DataProviders) == 0 || body.DataProviders[0] != ipgeo.NextTraceAPIProvider {
		t.Fatalf("dataProviders = %v, want canonical provider first", body.DataProviders)
	}
	if got := body.Defaults["data_provider"]; got != ipgeo.NextTraceAPIProvider {
		t.Fatalf("default data_provider = %v, want %q", got, ipgeo.NextTraceAPIProvider)
	}
	for _, provider := range body.DataProviders {
		if strings.Contains(strings.ToUpper(provider), "LEOMOE") {
			t.Fatalf("dataProviders leaked legacy name: %v", body.DataProviders)
		}
	}
}

func TestResolveTraceDataProviderCanonicalizesEnvironmentOverride(t *testing.T) {
	isolateServerNextTraceAPIV4Token(t, "")
	oldEnvDataProvider := util.EnvDataProvider
	defer func() { util.EnvDataProvider = oldEnvDataProvider }()
	util.EnvDataProvider = "leomoe"

	req := traceRequest{DataProvider: "nexttrace-api"}
	got, needsV3 := resolveTraceDataProvider(&req)
	if got != ipgeo.NextTraceAPIProvider {
		t.Fatalf("resolveTraceDataProvider() = %q, want %q", got, ipgeo.NextTraceAPIProvider)
	}
	if !needsV3 {
		t.Fatal("resolveTraceDataProvider() needsV3 = false, want true")
	}
}

func TestResolveTraceDataProviderAppliesDN42EnvironmentOverride(t *testing.T) {
	isolateServerNextTraceAPIV4Token(t, "")
	oldEnvDataProvider := util.EnvDataProvider
	oldInitDN42Config := initDN42Config
	t.Cleanup(func() {
		util.EnvDataProvider = oldEnvDataProvider
		initDN42Config = oldInitDN42Config
	})
	var initCalls atomic.Int32
	initDN42Config = sync.OnceFunc(func() { initCalls.Add(1) })
	util.EnvDataProvider = "dn42"

	var invalidResults atomic.Int32
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			req := traceRequest{DataProvider: ipgeo.NextTraceAPIProvider}
			got, needsV3 := resolveTraceDataProvider(&req)
			if got != "DN42" || needsV3 || !req.DN42 || !req.DisableMaptrace {
				invalidResults.Add(1)
			}
		})
	}
	wg.Wait()
	if got := initCalls.Load(); got != 1 {
		t.Fatalf("DN42 config initialization calls = %d, want 1", got)
	}
	if got := invalidResults.Load(); got != 0 {
		t.Fatalf("invalid concurrent DN42 resolutions = %d, want 0", got)
	}
}

func TestResolveTraceDataProviderSkipsV3ForV4Token(t *testing.T) {
	isolateServerNextTraceAPIV4Token(t, "v4-token")
	oldEnvDataProvider := util.EnvDataProvider
	t.Cleanup(func() { util.EnvDataProvider = oldEnvDataProvider })
	util.EnvDataProvider = ""

	req := traceRequest{DataProvider: "nexttrace-api"}
	got, needsV3 := resolveTraceDataProvider(&req)
	if got != ipgeo.NextTraceAPIProvider {
		t.Fatalf("resolveTraceDataProvider() = %q, want %q", got, ipgeo.NextTraceAPIProvider)
	}
	if needsV3 {
		t.Fatal("resolveTraceDataProvider() needsV3 = true with v4 token")
	}

	util.EnvDataProvider = "disable-geoip"
	got, needsV3 = resolveTraceDataProvider(&req)
	if got != "disable-geoip" || needsV3 {
		t.Fatalf("resolveTraceDataProvider() = (%q, %v), want (disable-geoip, false)", got, needsV3)
	}
}

func isolateServerNextTraceAPIV4Token(t *testing.T, token string) {
	t.Helper()
	dir := t.TempDir()
	for _, key := range []string{"TMPDIR", "TMP", "TEMP"} {
		t.Setenv(key, dir)
	}
	t.Setenv(util.EnvNextTraceAPIV4TokenKey, token)
}

func TestTraceHandlerCanonicalizesLegacyProviderInJSONResponse(t *testing.T) {
	gin.SetMode(gin.TestMode)
	oldLookup := traceDomainLookupFn
	oldTraceroute := traceTracerouteFn
	oldEnsure := ensureNextTraceAPIV3ConnectionFn
	t.Cleanup(func() {
		traceDomainLookupFn = oldLookup
		traceTracerouteFn = oldTraceroute
		ensureNextTraceAPIV3ConnectionFn = oldEnsure
	})
	traceDomainLookupFn = func(context.Context, string, string, string, bool) (net.IP, error) {
		return net.ParseIP("192.0.2.1"), nil
	}
	traceTracerouteFn = func(trace.Method, trace.Config) (*trace.Result, error) {
		return &trace.Result{}, nil
	}
	ensureNextTraceAPIV3ConnectionFn = func() {}

	req := httptest.NewRequest(http.MethodPost, "/api/trace", strings.NewReader(`{"target":"example.test","data_provider":"lEoMoEaPi","disable_maptrace":true}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req

	traceHandler(c)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", w.Code, w.Body.String())
	}
	var response traceResponse
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.DataProvider != ipgeo.NextTraceAPIProvider {
		t.Fatalf("data_provider = %q, want %q", response.DataProvider, ipgeo.NextTraceAPIProvider)
	}
}

func TestPrepareTrace_DoesNotForceLegacyInterval(t *testing.T) {
	setup, statusCode, err := prepareTrace(context.Background(), traceRequest{
		Target:       "1.1.1.1",
		Mode:         "mtr",
		DataProvider: "disable-geoip",
	})
	if err != nil {
		t.Fatalf("prepareTrace returned error: %v (status=%d)", err, statusCode)
	}
	if setup.Req.IntervalMs != 0 {
		t.Fatalf("prepareTrace IntervalMs = %d, want 0", setup.Req.IntervalMs)
	}
}

func TestResolveWebMTRHopInterval_DefaultsToOneSecond(t *testing.T) {
	got := resolveWebMTRHopInterval(traceRequest{})
	if got != time.Second {
		t.Fatalf("resolveWebMTRHopInterval() = %v, want %v", got, time.Second)
	}
}

func TestResolveWebMTRHopInterval_PrefersHopIntervalMs(t *testing.T) {
	got := resolveWebMTRHopInterval(traceRequest{IntervalMs: 2500, HopIntervalMs: 750})
	if got != 750*time.Millisecond {
		t.Fatalf("resolveWebMTRHopInterval() = %v, want %v", got, 750*time.Millisecond)
	}
}

func TestBuildTraceConfig_PropagatesSessionScopedFields(t *testing.T) {
	packetSize := 52
	tos := 0
	cfg, err := buildTraceConfig(traceRequest{
		SourceDevice: "en7",
		DisableMPLS:  true,
		DotServer:    "cloudflare",
		PacketSize:   &packetSize,
		TOS:          &tos,
	}, trace.ICMPTrace, net.ParseIP("1.1.1.1"), "IPInfo", 80)
	if err != nil {
		t.Fatalf("buildTraceConfig returned error: %v", err)
	}

	if cfg.SourceDevice != "en7" {
		t.Fatalf("buildTraceConfig SourceDevice = %q, want en7", cfg.SourceDevice)
	}
	if !cfg.DisableMPLS {
		t.Fatal("buildTraceConfig DisableMPLS = false, want true")
	}
	if cfg.IPGeoSource == nil {
		t.Fatal("buildTraceConfig IPGeoSource = nil, want wrapped source")
	}
	if cfg.IPGeoDescriptor == nil {
		t.Fatal("buildTraceConfig IPGeoDescriptor = nil")
	}
	if descriptor := cfg.IPGeoDescriptor(); descriptor.Namespace != ipgeo.SourceNamespaceIPInfo {
		t.Fatalf("buildTraceConfig descriptor = %+v, want IPInfo", descriptor)
	}
	if cfg.TOS != 0 {
		t.Fatalf("buildTraceConfig TOS = %d, want 0", cfg.TOS)
	}
}

func TestBuildTraceConfig_DN42CarriesRefreshableSession(t *testing.T) {
	cfg, err := buildTraceConfig(traceRequest{}, trace.ICMPTrace, net.ParseIP("10.0.0.1"), "DN42", 0)
	if err != nil {
		t.Fatalf("buildTraceConfig returned error: %v", err)
	}
	if !cfg.DN42 || cfg.IPGeoSource == nil || cfg.IPGeoDescriptor == nil || cfg.RefreshIPGeoSource == nil {
		t.Fatalf("DN42 config = %+v", cfg)
	}
}

func TestBuildTraceConfig_DN42PinsRequestAndWebSocketSession(t *testing.T) {
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

	first, err := buildTraceConfig(traceRequest{DN42: true}, trace.ICMPTrace, net.ParseIP("10.0.0.1"), "DN42", 0)
	if err != nil {
		t.Fatalf("first buildTraceConfig returned error: %v", err)
	}
	if err := os.WriteFile(geoFeedPath, []byte("10.0.0.0/8,us,US,Second City\n"), 0o600); err != nil {
		t.Fatalf("write second geofeed: %v", err)
	}
	second, err := buildTraceConfig(traceRequest{DN42: true}, trace.ICMPTrace, net.ParseIP("10.0.0.1"), "DN42", 0)
	if err != nil {
		t.Fatalf("second buildTraceConfig returned error: %v", err)
	}

	firstGeo, err := first.IPGeoSource("10.0.0.1", time.Second, "en", false)
	if err != nil || firstGeo.City != "First" {
		t.Fatalf("first pinned source = (%+v, %v), want First", firstGeo, err)
	}
	secondGeo, err := second.IPGeoSource("10.0.0.1", time.Second, "en", false)
	if err != nil || secondGeo.City != "Second City" {
		t.Fatalf("second source = (%+v, %v), want Second City", secondGeo, err)
	}
}

func TestBuildTraceConfig_PreservesNegativePacketSizeAndTOS(t *testing.T) {
	packetSize := -123
	tos := 255
	cfg, err := buildTraceConfig(traceRequest{
		PacketSize: &packetSize,
		TOS:        &tos,
	}, trace.ICMPTrace, net.ParseIP("1.1.1.1"), "disable-geoip", 80)
	if err != nil {
		t.Fatalf("buildTraceConfig returned error: %v", err)
	}
	if !cfg.RandomPacketSize {
		t.Fatal("buildTraceConfig RandomPacketSize = false, want true")
	}
	if cfg.TOS != 255 {
		t.Fatalf("buildTraceConfig TOS = %d, want 255", cfg.TOS)
	}
}

func TestBuildTraceConfig_DefaultsPacketSizeByProtocolAndFamily(t *testing.T) {
	cfg, err := buildTraceConfig(traceRequest{}, trace.TCPTrace, net.ParseIP("2a00:1450:4009:81a::200e"), "disable-geoip", 80)
	if err != nil {
		t.Fatalf("buildTraceConfig returned error: %v", err)
	}
	if cfg.PktSize != 0 {
		t.Fatalf("buildTraceConfig PktSize = %d, want 0 payload bytes for default TCP/IPv6 minimum", cfg.PktSize)
	}
	if cfg.RandomPacketSize {
		t.Fatal("buildTraceConfig RandomPacketSize = true, want false")
	}
}

func TestNormalizeTraceRequest_RejectsInvalidTOS(t *testing.T) {
	tos := 256
	statusCode, err := normalizeTraceRequest(&traceRequest{TOS: &tos})
	if err == nil {
		t.Fatal("normalizeTraceRequest should reject invalid tos")
	}
	if statusCode != http.StatusBadRequest {
		t.Fatalf("statusCode = %d, want %d", statusCode, http.StatusBadRequest)
	}
}

func TestPrepareTrace_RejectsUnknownSourceDevice(t *testing.T) {
	_, statusCode, err := prepareTrace(context.Background(), traceRequest{
		Target:       "1.1.1.1",
		DataProvider: "disable-geoip",
		SourceDevice: "codex-nonexistent-dev0",
	})
	if err == nil {
		t.Fatal("prepareTrace should reject unknown source_device")
	}
	if statusCode != http.StatusBadRequest {
		t.Fatalf("statusCode = %d, want %d", statusCode, http.StatusBadRequest)
	}
}

func TestNormalizeTarget(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		want   string
		hasErr bool
	}{
		{name: "empty", input: " ", hasErr: true},
		{name: "url host", input: "https://example.com/path", want: "example.com"},
		{name: "host with port", input: "example.com:8443", want: "example.com"},
		{name: "ipv6 with brackets", input: "[2001:db8::1]:443", want: "2001:db8::1"},
		{name: "bare ipv6 brackets", input: "[::1]", want: "::1"},
		{name: "malformed reversed brackets", input: "foo]bar[", want: "foo]bar["},
		{name: "malformed open only", input: "[abc", want: "[abc"},
		{name: "malformed close only", input: "abc]", want: "abc]"},
		{name: "slash target", input: "example.com/path", want: "example.com"},
		{name: "invalid slash target", input: "/only-path", hasErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := normalizeTarget(tc.input)
			if tc.hasErr {
				if err == nil {
					t.Fatalf("normalizeTarget(%q) error = nil, want error", tc.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("normalizeTarget(%q) returned error: %v", tc.input, err)
			}
			if got != tc.want {
				t.Fatalf("normalizeTarget(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestTraceHandler_RejectsOversizedJSONBody(t *testing.T) {
	gin.SetMode(gin.TestMode)

	body := `{"target":"` + strings.Repeat("a", maxTraceRequestBodyBytes) + `"}`
	req := httptest.NewRequest(http.MethodPost, "/api/trace", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req

	traceHandler(c)

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusRequestEntityTooLarge)
	}
}

func TestTraceHandlerReturnsSnakeCaseStopReason(t *testing.T) {
	gin.SetMode(gin.TestMode)
	oldLookup := traceDomainLookupFn
	oldTraceroute := traceTracerouteFn
	defer func() {
		traceDomainLookupFn = oldLookup
		traceTracerouteFn = oldTraceroute
	}()
	traceDomainLookupFn = func(context.Context, string, string, string, bool) (net.IP, error) {
		return net.ParseIP("192.0.2.1"), nil
	}
	traceTracerouteFn = func(trace.Method, trace.Config) (*trace.Result, error) {
		return &trace.Result{
			Hops: [][]trace.Hop{{{TTL: 1, Success: true, Address: &net.IPAddr{IP: net.ParseIP("198.51.100.8")}}}},
			StopReason: &trace.StopReason{
				Hop:       1,
				Reason:    trace.StopReasonUnreachable,
				Responses: []string{"ICMP Host Unreachable from 198.51.100.8"},
				Markers:   []string{"!H"},
			},
		}, nil
	}

	req := httptest.NewRequest(http.MethodPost, "/api/trace", strings.NewReader(`{"target":"example.test","data_provider":"disable-geoip","disable_maptrace":true}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req
	traceHandler(c)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", w.Code, w.Body.String())
	}
	var body map[string]json.RawMessage
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	var reason service.TraceStopReason
	if err := json.Unmarshal(body["stop_reason"], &reason); err != nil {
		t.Fatalf("stop_reason decode: %v body=%s", err, w.Body.String())
	}
	if reason.Reason != trace.StopReasonUnreachable || reason.Hop != 1 || len(reason.Markers) != 1 || reason.Markers[0] != "!H" {
		t.Fatalf("stop_reason = %#v", reason)
	}
	if _, ok := body["StopReason"]; ok {
		t.Fatalf("REST leaked core PascalCase StopReason: %s", w.Body.String())
	}
}

func TestExecuteMTRRaw_PerHopDoesNotMutateSessionGlobals(t *testing.T) {
	oldRunMTRRaw := traceRunMTRRawFn
	defer func() { traceRunMTRRawFn = oldRunMTRRaw }()

	oldSrcDev := util.SrcDev
	oldDisableMPLS := util.DisableMPLS
	oldPowProvider := util.PowProviderParam
	defer func() {
		util.SrcDev = oldSrcDev
		util.DisableMPLS = oldDisableMPLS
		util.PowProviderParam = oldPowProvider
	}()

	util.SrcDev = "keep-dev"
	util.DisableMPLS = false
	util.PowProviderParam = "keep-pow"

	traceRunMTRRawFn = func(_ context.Context, _ trace.Method, cfg trace.Config, opts trace.MTRRawOptions, _ trace.MTRRawOnRecord) error {
		if cfg.SourceDevice != "en7" {
			t.Fatalf("cfg.SourceDevice = %q, want en7", cfg.SourceDevice)
		}
		if !cfg.DisableMPLS {
			t.Fatal("cfg.DisableMPLS = false, want true")
		}
		if opts.HopInterval != time.Second {
			t.Fatalf("opts.HopInterval = %v, want %v", opts.HopInterval, time.Second)
		}
		return nil
	}

	err := executeMTRRaw(context.Background(), &wsTraceSession{}, &traceExecution{
		Req: traceRequest{
			SourceDevice:  "en7",
			DisableMPLS:   true,
			HopIntervalMs: 1000,
			DotServer:     "cloudflare",
		},
		Target: "1.1.1.1",
		Method: trace.ICMPTrace,
		IP:     net.ParseIP("1.1.1.1"),
		Config: trace.Config{
			DstIP:            net.ParseIP("1.1.1.1"),
			SourceDevice:     "en7",
			DisableMPLS:      true,
			IPGeoSource:      nil,
			Timeout:          time.Second,
			MaxHops:          30,
			ParallelRequests: 1,
		},
	}, trace.MTRRawOptions{
		HopInterval: time.Second,
	}, nil)
	if err != nil {
		t.Fatalf("executeMTRRaw returned error: %v", err)
	}

	if util.SrcDev != "keep-dev" {
		t.Fatalf("util.SrcDev = %q, want keep-dev", util.SrcDev)
	}
	if util.DisableMPLS {
		t.Fatal("util.DisableMPLS = true, want false")
	}
	if util.PowProviderParam != "keep-pow" {
		t.Fatalf("util.PowProviderParam = %q, want keep-pow", util.PowProviderParam)
	}
}

func TestTraceMapURLForResult_UsesRequestScopedMapHelper(t *testing.T) {
	oldMapFn := traceMapURLFn
	oldScopeFn := withTraceMapScopeFn
	defer func() {
		traceMapURLFn = oldMapFn
		withTraceMapScopeFn = oldScopeFn
	}()

	scopeCalled := false
	traceMapCalled := false

	withTraceMapScopeFn = func(setup *traceExecution, callback func() (string, error)) (string, error) {
		scopeCalled = true
		if setup == nil {
			t.Fatal("setup should not be nil")
		}
		if strings.TrimSpace(setup.Req.DotServer) != "cloudflare" {
			t.Fatalf("DotServer = %q, want cloudflare", setup.Req.DotServer)
		}
		return callback()
	}
	traceMapURLFn = func(ctx context.Context, payload string) (string, error) {
		traceMapCalled = true
		if ctx == nil {
			t.Fatal("context should not be nil")
		}
		if payload == "" {
			t.Fatal("payload should not be empty")
		}
		var body map[string]json.RawMessage
		if err := json.Unmarshal([]byte(payload), &body); err != nil {
			t.Fatalf("invalid tracemap payload: %v", err)
		}
		if _, ok := body["StopReason"]; ok {
			t.Fatalf("tracemap payload leaked StopReason: %s", payload)
		}
		if _, ok := body["Hops"]; !ok {
			t.Fatalf("tracemap payload lost historical Hops field: %s", payload)
		}
		return "https://map.example.test", nil
	}

	got := traceMapURLForResult(&traceExecution{
		Req:          traceRequest{DotServer: "cloudflare"},
		DataProvider: "IPInfo",
		Config:       trace.Config{Maptrace: true},
	}, &trace.Result{
		Hops:       [][]trace.Hop{{{TTL: 1}}},
		StopReason: &trace.StopReason{Hop: 1, Reason: trace.StopReasonDestination},
	})

	if got != "https://map.example.test" {
		t.Fatalf("traceMapURLForResult() = %q, want https://map.example.test", got)
	}
	if !scopeCalled {
		t.Fatal("expected request-scoped map helper to be used")
	}
	if !traceMapCalled {
		t.Fatal("expected traceMapURLFn to be called")
	}
}

func TestPrepareTraceHonorsCanceledContext(t *testing.T) {
	oldLookup := traceDomainLookupFn
	traceDomainLookupFn = func(ctx context.Context, target, ipVersion, dotServer string, disableOutput bool) (net.IP, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	defer func() { traceDomainLookupFn = oldLookup }()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	start := time.Now()
	_, _, err := prepareTrace(ctx, traceRequest{
		Target:       "example.com",
		DataProvider: "disable-geoip",
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("prepareTrace error = %v, want context.Canceled", err)
	}
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Fatalf("prepareTrace returned too slowly after cancel: %v", elapsed)
	}
}
