package ipgeo

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"runtime"
	"testing"
	"time"

	"github.com/nxtrace/NTrace-core/util"
	"github.com/nxtrace/NTrace-core/wshandle"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetSourceMappings(t *testing.T) {
	t.Helper()
	isolateNextTraceAPIV4TokenFiles(t)
	t.Setenv(util.EnvNextTraceAPIV4TokenKey, "")
	tests := []struct {
		name  string
		input string
		want  Source
	}{
		{name: "nexttrace api", input: NextTraceAPIProvider, want: NextTraceAPIV3GeoIP},
		{name: "nexttrace api mixed case", input: "nExTtRaCe-ApI", want: NextTraceAPIV3GeoIP},
		{name: "nexttrace api surrounding whitespace", input: "  nexttrace-api\n", want: NextTraceAPIV3GeoIP},
		{name: "legacy LeoMoeAPI", input: "LEOMOEAPI", want: NextTraceAPIV3GeoIP},
		{name: "legacy LeoMoe", input: "leomoe", want: NextTraceAPIV3GeoIP},
		{name: "ipsb", input: "ip.sb", want: IPSB},
		{name: "ipinsight", input: "ipinsight", want: IPInSight},
		{name: "ipapi alias", input: "ip-api.com", want: IPApiCom},
		{name: "ipapi uppercase", input: "IPAPI.COM", want: IPApiCom},
		{name: "ipinfo", input: "IPINFO", want: IPInfo},
		{name: "ipinfo local", input: "ipinfolocal", want: IPInfoLocal},
		{name: "chunzhen", input: "ChunZhen", want: Chunzhen},
		{name: "disable geoip", input: "disable-geoip", want: disableGeoIP},
		{name: "ipdb", input: "IPDB.One", want: IPDBOne},
		{name: "fallback", input: "unknown", want: NextTraceAPIV3GeoIP},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := GetSource(tc.input)
			require.NotNil(t, got)
			assert.Equal(t, reflect.ValueOf(tc.want).Pointer(), reflect.ValueOf(got).Pointer())
		})
	}
}

func TestGetSourceDescriptorMappings(t *testing.T) {
	isolateNextTraceAPIV4TokenFiles(t)
	t.Setenv(util.EnvNextTraceAPIV4TokenKey, "")
	tests := []struct {
		name      string
		input     string
		want      Source
		namespace string
		backend   string
	}{
		{name: "nexttrace api", input: NextTraceAPIProvider, want: NextTraceAPIV3GeoIP, namespace: SourceNamespaceNextTraceAPI, backend: SourceBackendNextTraceAPIV3},
		{name: "nexttrace legacy alias", input: "leomoeapi", want: NextTraceAPIV3GeoIP, namespace: SourceNamespaceNextTraceAPI, backend: SourceBackendNextTraceAPIV3},
		{name: "ipsb", input: "ip.sb", want: IPSB, namespace: SourceNamespaceIPSB, backend: SourceNamespaceIPSB},
		{name: "ipinsight", input: "IPInsight", want: IPInSight, namespace: SourceNamespaceIPInsight, backend: SourceNamespaceIPInsight},
		{name: "ipapi alias", input: "IPAPI.COM", want: IPApiCom, namespace: SourceNamespaceIPAPI, backend: SourceNamespaceIPAPI},
		{name: "ip-api alias", input: "ip-api.com", want: IPApiCom, namespace: SourceNamespaceIPAPI, backend: SourceNamespaceIPAPI},
		{name: "ipinfo", input: "IPInfo", want: IPInfo, namespace: SourceNamespaceIPInfo, backend: SourceNamespaceIPInfo},
		{name: "ipinfo whitespace", input: "  ipinfo\n", want: IPInfo, namespace: SourceNamespaceIPInfo, backend: SourceNamespaceIPInfo},
		{name: "ipinfo local", input: "IPInfoLocal", want: IPInfoLocal, namespace: SourceNamespaceIPInfoLocal, backend: SourceNamespaceIPInfoLocal},
		{name: "chunzhen", input: "ChunZhen", want: Chunzhen, namespace: SourceNamespaceChunzhen, backend: SourceNamespaceChunzhen},
		{name: "disable geoip", input: "disable-geoip", want: disableGeoIP, namespace: SourceNamespaceDisableGeoIP, backend: SourceNamespaceDisableGeoIP},
		{name: "ipdb one", input: "IPDB.One", want: IPDBOne, namespace: SourceNamespaceIPDBOne, backend: SourceNamespaceIPDBOne},
		{name: "unknown fallback", input: "unknown", want: NextTraceAPIV3GeoIP, namespace: SourceNamespaceNextTraceAPI, backend: SourceBackendNextTraceAPIV3},
		{name: "empty fallback", want: NextTraceAPIV3GeoIP, namespace: SourceNamespaceNextTraceAPI, backend: SourceBackendNextTraceAPIV3},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			descriptor := GetSourceDescriptor(tc.input)
			require.NotNil(t, descriptor.Source)
			assert.Equal(t, reflect.ValueOf(tc.want).Pointer(), reflect.ValueOf(descriptor.Source).Pointer())
			assert.Equal(t, tc.namespace, descriptor.Namespace)
			assert.Equal(t, tc.backend, descriptor.Backend)
			assert.False(t, descriptor.HasGeneration)
			assert.Zero(t, descriptor.Generation)
		})
	}
}

func TestGetSourceSessionNonRefreshableProvider(t *testing.T) {
	session := GetSourceSession("disable-geoip")
	require.NotNil(t, session.Source)
	assert.Nil(t, session.Refresh)
	assert.Equal(t, reflect.ValueOf(disableGeoIP).Pointer(), reflect.ValueOf(session.Source).Pointer())
}

func TestCanonicalizeNextTraceAPIProvider(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		want        string
		isNextTrace bool
	}{
		{name: "canonical", input: NextTraceAPIProvider, want: NextTraceAPIProvider, isNextTrace: true},
		{name: "canonical lowercase", input: "nexttrace-api", want: NextTraceAPIProvider, isNextTrace: true},
		{name: "canonical surrounding whitespace", input: "  NextTrace-API\t", want: NextTraceAPIProvider, isNextTrace: true},
		{name: "legacy LeoMoeAPI", input: "lEoMoEaPi", want: NextTraceAPIProvider, isNextTrace: true},
		{name: "legacy LeoMoe", input: "LEOMOE", want: NextTraceAPIProvider, isNextTrace: true},
		{name: "legacy surrounding whitespace", input: "\n leomoeapi ", want: NextTraceAPIProvider, isNextTrace: true},
		{name: "space form is not a machine value", input: "NextTrace API", want: "NextTrace API"},
		{name: "unknown unchanged", input: "IPInfo", want: "IPInfo"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, CanonicalizeNextTraceAPIProvider(tc.input))
			assert.Equal(t, tc.isNextTrace, IsNextTraceAPIProvider(tc.input))
		})
	}
}

func TestGetSourceUsesNextTraceAPIV4WhenTokenConfigured(t *testing.T) {
	t.Setenv(util.EnvNextTraceAPIV4TokenKey, "v4-token")

	got := GetSource(NextTraceAPIProvider)
	require.NotNil(t, got)
	assert.Equal(t, reflect.ValueOf(NextTraceAPIV4GeoIP).Pointer(), reflect.ValueOf(got).Pointer())

	fallback := GetSource("unknown")
	require.NotNil(t, fallback)
	assert.Equal(t, reflect.ValueOf(NextTraceAPIV4GeoIP).Pointer(), reflect.ValueOf(fallback).Pointer())

	nonNextTrace := GetSource("IPInfo")
	require.NotNil(t, nonNextTrace)
	assert.Equal(t, reflect.ValueOf(IPInfo).Pointer(), reflect.ValueOf(nonNextTrace).Pointer())

	descriptor := GetSourceDescriptor("leomoe")
	assert.Equal(t, SourceNamespaceNextTraceAPI, descriptor.Namespace)
	assert.Equal(t, SourceBackendNextTraceAPIV4, descriptor.Backend)
	assert.Equal(t, reflect.ValueOf(NextTraceAPIV4GeoIP).Pointer(), reflect.ValueOf(descriptor.Source).Pointer())
}

func TestGetSourceDescriptorSessionStaticProvider(t *testing.T) {
	session := GetSourceDescriptorSession("IPAPI.COM")
	require.NotNil(t, session.Current)
	assert.Nil(t, session.Refresh)

	first := session.Current()
	second := session.Current()
	assert.Equal(t, SourceNamespaceIPAPI, first.Namespace)
	assert.Equal(t, SourceNamespaceIPAPI, first.Backend)
	assert.Equal(t, reflect.ValueOf(IPApiCom).Pointer(), reflect.ValueOf(first.Source).Pointer())
	assert.Equal(t, reflect.ValueOf(first.Source).Pointer(), reflect.ValueOf(second.Source).Pointer())
}

func TestGetSourceDescriptorWithGeoDNSPreservesIdentity(t *testing.T) {
	descriptor := GetSourceDescriptorWithGeoDNS("disable-geoip", " CloudFlare ")
	require.NotNil(t, descriptor.Source)
	assert.Equal(t, SourceNamespaceDisableGeoIP, descriptor.Namespace)
	assert.Equal(t, SourceNamespaceDisableGeoIP, descriptor.Backend)
	assert.False(t, descriptor.HasGeneration)

	geo, err := descriptor.Source("192.0.2.1", time.Second, "en", false)
	require.NoError(t, err)
	assert.Equal(t, &IPGeoData{}, geo)
}

func TestDeprecatedNextTraceAPIWrappers(t *testing.T) {
	isolateNextTraceAPIV4ProxyState(t)
	isolateNextTraceAPIV4TokenFiles(t)
	t.Setenv(util.EnvNextTraceAPIV4TokenKey, "")
	assert.Equal(
		t,
		reflect.ValueOf(NextTraceAPISource()).Pointer(),
		reflect.ValueOf(LeoMoeAPISource()).Pointer(),
	)

	oldGet := getNextTraceAPIV3WSConn
	getNextTraceAPIV3WSConn = func() *wshandle.WsConn { return nil }
	t.Cleanup(func() { getNextTraceAPIV3WSConn = oldGet })
	wantV3, wantErr := NextTraceAPIV3GeoIP("192.0.2.1", time.Second, "en", false)
	gotV3, gotErr := LeoIP("192.0.2.1", time.Second, "en", false)
	assert.Equal(t, wantV3, gotV3)
	require.Error(t, wantErr)
	assert.EqualError(t, gotErr, wantErr.Error())

	oldEndpoint := nextTraceAPIV4GeoEndpoint
	t.Cleanup(func() {
		nextTraceAPIV4GeoEndpoint = oldEndpoint
		resetNextTraceAPIV4TransportCache()
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_, _ = w.Write([]byte(`{"ip":"` + r.URL.Query().Get("ip") + `"}`))
	}))
	defer srv.Close()
	nextTraceAPIV4GeoEndpoint = srv.URL
	resetNextTraceAPIV4TransportCache()

	wantV4, err := NextTraceAPIV4GeoIP("198.51.100.1", time.Second, "en", false)
	require.NoError(t, err)
	gotV4, err := LeoIPNextTraceAPIV4HTTP("198.51.100.1", time.Second, "en", false)
	require.NoError(t, err)
	assert.Equal(t, wantV4, gotV4)
}

func TestNextTraceAPIV4TokenConfiguredReadsCurrentProcessEnv(t *testing.T) {
	isolateNextTraceAPIV4TokenFiles(t)
	t.Setenv(util.EnvNextTraceAPIV4TokenKey, "")
	assert.False(t, NextTraceAPIV4TokenConfigured())

	require.NoError(t, os.Setenv(util.EnvNextTraceAPIV4TokenKey, " runtime-token "))
	t.Cleanup(func() { _ = os.Unsetenv(util.EnvNextTraceAPIV4TokenKey) })
	assert.True(t, NextTraceAPIV4TokenConfigured())
}

func isolateNextTraceAPIV4TokenFiles(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("TMPDIR", dir)
	t.Setenv("TMP", dir)
	t.Setenv("TEMP", dir)
}

func TestDisableGeoIP(t *testing.T) {
	res, err := disableGeoIP("1.1.1.1", time.Second, "en", false)
	require.NoError(t, err)
	assert.Equal(t, &IPGeoData{}, res)
}

func TestGetSourceWithGeoDNSEmptyResolverUsesIsolatedScope(t *testing.T) {
	util.SetGeoDNSResolver("google")
	util.SetGeoDNSFallback(false)
	defer func() {
		util.SetGeoDNSResolver("")
		util.SetGeoDNSFallback(true)
	}()

	dotEntered := make(chan struct{})
	releaseDot := make(chan struct{})
	dotDone := make(chan struct{})
	go func() {
		defer close(dotDone)
		_, _ = util.WithGeoDNSResolver("cloudflare", func() (struct{}, error) {
			close(dotEntered)
			<-releaseDot
			return struct{}{}, nil
		})
	}()
	<-dotEntered

	sourceStarted := make(chan struct{})
	sourceDone := make(chan error, 1)
	go observeEmptyGeoSourceScope(GetSourceWithGeoDNS("disable-geoip", ""), sourceStarted, sourceDone)
	<-sourceStarted

	blocked, completed, earlyErr := waitForGeoSourceScopeBlock(t, sourceDone)
	if completed {
		close(releaseDot)
		<-dotDone
		t.Fatalf("empty-resolver source bypassed active scope: %v", earlyErr)
	}
	if !blocked {
		close(releaseDot)
		<-dotDone
		t.Fatal("empty-resolver source never reached the active scope lock")
	}

	close(releaseDot)
	<-dotDone
	select {
	case err := <-sourceDone:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("empty-resolver source did not resume after active scope exited")
	}
}

//go:noinline
func observeEmptyGeoSourceScope(source Source, started chan<- struct{}, result chan<- error) {
	close(started)
	_, err := source("1.1.1.1", time.Second, "en", false)
	result <- err
}

func waitForGeoSourceScopeBlock(t *testing.T, result <-chan error) (blocked bool, completed bool, err error) {
	t.Helper()
	const maxStackDumpSize = 16 << 20
	deadline := time.Now().Add(2 * time.Second)
	stack := make([]byte, 1<<20)
	for time.Now().Before(deadline) {
		select {
		case err = <-result:
			return false, true, err
		default:
		}
		n := runtime.Stack(stack, true)
		for n == len(stack) {
			if len(stack) >= maxStackDumpSize {
				t.Errorf("goroutine stack dump exceeded %d bytes", maxStackDumpSize)
				return false, false, err
			}
			stack = make([]byte, min(len(stack)*2, maxStackDumpSize))
			n = runtime.Stack(stack, true)
		}
		for _, goroutine := range bytes.Split(stack[:n], []byte("\n\n")) {
			if bytes.Contains(goroutine, []byte("observeEmptyGeoSourceScope")) &&
				bytes.Contains(goroutine, []byte("[sync.Mutex.Lock")) {
				return true, false, nil
			}
		}
		runtime.Gosched()
	}
	return false, false, nil
}
