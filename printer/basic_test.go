package printer

import (
	"io"
	"net"
	"os"
	"strings"
	"testing"

	"github.com/nxtrace/NTrace-core/ipgeo"
	"github.com/nxtrace/NTrace-core/trace"
)

func TestApplyLangSettingRecognizesNextTraceAPIProviderAliases(t *testing.T) {
	for _, source := range []string{ipgeo.NextTraceAPIProvider, "LeoMoeAPI"} {
		hop := &trace.Hop{Geo: &ipgeo.IPGeoData{Source: source}}
		applyLangSetting(hop)
		if hop.Geo.Country != "未知" || hop.Geo.CountryEn != "Unknown" {
			t.Fatalf("source %q produced country %q/%q, want NextTrace API unknown labels", source, hop.Geo.Country, hop.Geo.CountryEn)
		}
	}
}

func TestApplyLangSettingKeepsOtherProviderNetworkError(t *testing.T) {
	hop := &trace.Hop{Geo: &ipgeo.IPGeoData{Source: "IPInfo"}}
	applyLangSetting(hop)
	if hop.Geo.Country != "网络故障" || hop.Geo.CountryEn != "Network Error" {
		t.Fatalf("country = %q/%q, want network error labels", hop.Geo.Country, hop.Geo.CountryEn)
	}
}

func TestPrintTraceRouteNavCanonicalizesLegacyNextTraceAPIProvider(t *testing.T) {
	originalStdout := os.Stdout
	readPipe, writePipe, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = writePipe
	t.Cleanup(func() {
		os.Stdout = originalStdout
		_ = readPipe.Close()
		_ = writePipe.Close()
	})

	PrintTraceRouteNav(net.ParseIP("1.1.1.1"), "1.1.1.1", "LeoMoeAPI", 30, 28, "", "icmp")
	if err := writePipe.Close(); err != nil {
		t.Fatal(err)
	}
	os.Stdout = originalStdout
	output, err := io.ReadAll(readPipe)
	if err != nil {
		t.Fatal(err)
	}

	lines := strings.Split(strings.TrimSuffix(string(output), "\n"), "\n")
	if len(lines) == 0 || lines[0] != "IP Geo Data Provider: NextTrace-API" {
		t.Fatalf("provider output line = %q, want canonical NextTrace API name", lines[0])
	}
	if strings.Contains(strings.ToUpper(string(output)), "LEOMOE") {
		t.Fatalf("output leaks legacy provider name: %q", output)
	}
}
