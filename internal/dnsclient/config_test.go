//go:build !flavor_tiny && !flavor_ntr

package dnsclient

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	flags "github.com/jessevdk/go-flags"
	"github.com/miekg/dns"
)

func TestParseConfigDefaults(t *testing.T) {
	parseOpts := testParseOptions(t, nil)
	config, err := ParseConfig(nil, parseOpts)
	if err != nil {
		t.Fatalf("ParseConfig() error = %v", err)
	}

	if config.Flags.Name != "" {
		t.Fatalf("Name = %q, want empty", config.Flags.Name)
	}
	if !reflect.DeepEqual(config.RRTypes, []uint16{dns.TypeNS}) {
		t.Fatalf("RRTypes = %v, want NS", config.RRTypes)
	}
	if !reflect.DeepEqual(config.Flags.Server, []string{"192.0.2.53"}) {
		t.Fatalf("Server = %v, want resolver server", config.Flags.Server)
	}
	if !config.Flags.Color {
		t.Fatal("Color = false, want terminal default true")
	}
	for name, enabled := range map[string]bool{
		"answer":             config.Flags.ShowAnswer,
		"edns":               config.Flags.EDNS,
		"id-check":           config.Flags.IDCheck,
		"pmtud":              config.Flags.PMTUD,
		"pretty-ttls":        config.Flags.PrettyTTLs,
		"quic-length-prefix": config.Flags.QUICLengthPrefix,
		"rd":                 config.Flags.RecursionDesired,
		"reuse-conn":         config.Flags.ReuseConn,
		"short-ttls":         config.Flags.ShortTTLs,
	} {
		if !enabled {
			t.Errorf("default-true flag %s = false", name)
		}
	}
}

func TestParseConfigQRCEnvironmentAndCommandLine(t *testing.T) {
	homeDir := t.TempDir()
	qrc := strings.Join([]string{
		"# q defaults",
		"; another comment",
		"--format column",
		"--server qrc.example",
		"--type MX",
		"--answer=false",
	}, "\n")
	if err := os.WriteFile(filepath.Join(homeDir, ".qrc"), []byte(qrc), 0o600); err != nil {
		t.Fatal(err)
	}

	parseOpts := testParseOptions(t, map[string]string{
		"NO_COLOR":         "1",
		"Q_DEFAULT_SERVER": "ignored.example",
		"SSLKEYLOGFILE":    "/tmp/q.keys",
	})
	parseOpts.HomeDir = homeDir
	config, err := ParseConfig([]string{
		"--format=json", "example.com", "TXT", "@1.1.1.1", "+noedns",
	}, parseOpts)
	if err != nil {
		t.Fatalf("ParseConfig() error = %v", err)
	}

	if config.Flags.Name != "example.com" {
		t.Errorf("Name = %q, want example.com", config.Flags.Name)
	}
	if config.Flags.Format != "json" {
		t.Errorf("Format = %q, want command-line json", config.Flags.Format)
	}
	if !reflect.DeepEqual(config.Flags.Server, []string{"qrc.example", "1.1.1.1"}) {
		t.Errorf("Server = %v", config.Flags.Server)
	}
	if !reflect.DeepEqual(config.RRTypes, []uint16{dns.TypeMX, dns.TypeTXT}) {
		t.Errorf("RRTypes = %v, want MX/TXT", config.RRTypes)
	}
	if config.Flags.Color {
		t.Error("Color = true with NO_COLOR")
	}
	if config.Flags.EDNS {
		t.Error("EDNS = true after +noedns")
	}
	if config.Flags.ShowAnswer {
		t.Error("ShowAnswer = true after --answer=false")
	}
	if config.Flags.TLSKeyLogFile != "/tmp/q.keys" {
		t.Errorf("TLSKeyLogFile = %q", config.Flags.TLSKeyLogFile)
	}
}

func TestParseConfigShortPlusFlags(t *testing.T) {
	tests := []struct {
		name    string
		enabled func(Config) bool
	}{
		{name: "aa", enabled: func(config Config) bool { return config.Flags.AuthoritativeAnswer }},
		{name: "ad", enabled: func(config Config) bool { return config.Flags.AuthenticData }},
		{name: "cd", enabled: func(config Config) bool { return config.Flags.CheckingDisabled }},
		{name: "ra", enabled: func(config Config) bool { return config.Flags.RecursionAvailable }},
		{name: "rd", enabled: func(config Config) bool { return config.Flags.RecursionDesired }},
		{name: "t", enabled: func(config Config) bool { return config.Flags.Truncated }},
		{name: "z", enabled: func(config Config) bool { return config.Flags.Zero }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config, err := ParseConfig([]string{"--" + test.name + "=false", "+" + test.name, "example.com", "A", "@1.1.1.1"}, testParseOptions(t, nil))
			if err != nil {
				t.Fatal(err)
			}
			if !test.enabled(config) {
				t.Fatalf("+%s did not enable its query flag", test.name)
			}

			config, err = ParseConfig([]string{"--" + test.name + "=true", "+no" + test.name, "example.com", "A", "@1.1.1.1"}, testParseOptions(t, nil))
			if err != nil {
				t.Fatal(err)
			}
			if test.enabled(config) {
				t.Fatalf("+no%s did not disable its query flag", test.name)
			}
		})
	}

	config, err := ParseConfig([]string{"+nord", "+rd", "example.com", "A", "@1.1.1.1"}, testParseOptions(t, nil))
	if err != nil {
		t.Fatal(err)
	}
	if !config.Flags.RecursionDesired {
		t.Fatal("+rd did not restore recursion after +nord")
	}
}

func TestParseConfigRejectsUnsupportedTCPlusAlias(t *testing.T) {
	_, err := ParseConfig([]string{"+tc", "example.com", "A", "@1.1.1.1"}, testParseOptions(t, nil))
	if err == nil || !strings.Contains(err.Error(), "unknown flag +tc") {
		t.Fatalf("error = %v, want unknown +tc flag", err)
	}
}

func TestParseConfigPositionalsIDNAAndChaos(t *testing.T) {
	config, err := ParseConfig([]string{
		"--qname", "_sip.例子.测试", "NS", "CH", "@9.9.9.9",
	}, testParseOptions(t, nil))
	if err != nil {
		t.Fatalf("ParseConfig() error = %v", err)
	}

	if config.Flags.Name != "_sip.xn--fsqu00a.xn--0zwm56d" {
		t.Errorf("Name = %q", config.Flags.Name)
	}
	if config.Flags.Class != dns.ClassCHAOS {
		t.Errorf("Class = %d, want CHAOS", config.Flags.Class)
	}
	if !reflect.DeepEqual(config.RRTypes, []uint16{dns.TypeNS}) {
		t.Errorf("RRTypes = %v, want NS", config.RRTypes)
	}
	if !config.Flags.ShowAuthority || !config.Flags.ShowAdditional {
		t.Error("positional NS did not enable authority and additional output")
	}
}

func TestParseConfigReverse(t *testing.T) {
	config, err := ParseConfig([]string{
		"--reverse", "--qname=192.0.2.1", "--type=PTR", "@1.1.1.1",
	}, testParseOptions(t, nil))
	if err != nil {
		t.Fatalf("ParseConfig() error = %v", err)
	}

	if config.Flags.Name != "1.2.0.192.in-addr.arpa." {
		t.Errorf("Name = %q", config.Flags.Name)
	}
	if !reflect.DeepEqual(config.RRTypes, []uint16{dns.TypePTR}) {
		t.Errorf("RRTypes = %v, want PTR", config.RRTypes)
	}
}

func TestParseConfigReverseAddsPTRToDefaultTypes(t *testing.T) {
	config, err := ParseConfig([]string{"--reverse", "192.0.2.1", "@1.1.1.1"}, testParseOptions(t, nil))
	if err != nil {
		t.Fatal(err)
	}
	want := map[uint16]bool{
		dns.TypeA: true, dns.TypeAAAA: true, dns.TypeNS: true, dns.TypeMX: true,
		dns.TypeTXT: true, dns.TypeHTTPS: true, dns.TypeCNAME: true, dns.TypePTR: true,
	}
	if len(config.RRTypes) != len(want) {
		t.Fatalf("RRTypes = %v", config.RRTypes)
	}
	for _, rrType := range config.RRTypes {
		if !want[rrType] {
			t.Fatalf("unexpected RR type %d in %v", rrType, config.RRTypes)
		}
	}
}

func TestParseConfigDefaultRRTypesAreStable(t *testing.T) {
	config, err := ParseConfig([]string{"example.com", "@1.1.1.1"}, testParseOptions(t, nil))
	if err != nil {
		t.Fatalf("ParseConfig() error = %v", err)
	}
	want := []uint16{
		dns.TypeA, dns.TypeAAAA, dns.TypeNS, dns.TypeMX, dns.TypeTXT, dns.TypeHTTPS, dns.TypeCNAME,
	}
	if !reflect.DeepEqual(config.RRTypes, want) {
		t.Fatalf("RRTypes = %v, want %v", config.RRTypes, want)
	}
}

func TestParseConfigNumericRRTypes(t *testing.T) {
	config, err := ParseConfig([]string{
		"--qname=example.com", "--type", "TYPE65", "--type=28", "@1.1.1.1",
	}, testParseOptions(t, nil))
	if err != nil {
		t.Fatalf("ParseConfig() error = %v", err)
	}
	if !reflect.DeepEqual(config.RRTypes, []uint16{65, 28}) {
		t.Fatalf("RRTypes = %v", config.RRTypes)
	}
}

func TestParseConfigReturnsErrorsInsteadOfExiting(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{name: "unknown plus flag", args: []string{"+not-a-real-flag"}, want: "unknown flag"},
		{name: "invalid RR type", args: []string{"--type=NOTATYPE"}, want: "not a valid RR type"},
		{name: "invalid reverse", args: []string{"--reverse", "not-an-ip"}, want: "dns reverse"},
		{name: "unknown option", args: []string{"--not-a-real-option"}, want: "unknown flag"},
		{name: "insecure ODoH proxy", args: []string{"--odoh-proxy=http://proxy", "@https://target"}, want: "proxy must use HTTPS"},
		{name: "insecure ODoH target", args: []string{"--odoh-proxy=https://proxy", "@1.1.1.1"}, want: "target must use HTTPS"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := ParseConfig(test.args, testParseOptions(t, nil))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want containing %q", err, test.want)
			}
		})
	}
}

func TestParseConfigHelpRemainsDetectable(t *testing.T) {
	_, err := ParseConfig([]string{"--help"}, testParseOptions(t, nil))
	var flagErr *flags.Error
	if !errors.As(err, &flagErr) || flagErr.Type != flags.ErrHelp {
		t.Fatalf("error = %v, want flags.ErrHelp", err)
	}
}

func TestParseConfigCapturesShellCompletionWithoutExiting(t *testing.T) {
	t.Setenv("GO_FLAGS_COMPLETION", "1")
	config, err := ParseConfig([]string{"--fo"}, testParseOptions(t, map[string]string{
		"GO_FLAGS_COMPLETION": "1",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if !config.CompletionRequested {
		t.Fatal("CompletionRequested = false")
	}
	wantItem := "--format"
	if runtime.GOOS == "windows" {
		// go-flags uses the native Windows option style for completion items.
		wantItem = "/format"
	}
	found := false
	for _, completion := range config.Completions {
		if completion.Item == wantItem {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("completions = %#v, want item %q", config.Completions, wantItem)
	}
}

func TestParseConfigVersionSkipsQueryValidation(t *testing.T) {
	config, err := ParseConfig([]string{
		"--version", "--reverse", "--type=NOTATYPE",
	}, testParseOptions(t, nil))
	if err != nil {
		t.Fatalf("ParseConfig() error = %v", err)
	}
	if !config.Flags.ShowVersion {
		t.Fatal("ShowVersion = false")
	}
	if len(config.RRTypes) != 0 || len(config.Flags.Server) != 0 {
		t.Fatalf("version mode initialized query state: RRTypes=%v Server=%v", config.RRTypes, config.Flags.Server)
	}
}

func TestParseConfigVerboseTakesPrecedenceOverTrace(t *testing.T) {
	config, err := ParseConfig([]string{
		"--verbose", "--trace", "example.com", "A", "@1.1.1.1",
	}, testParseOptions(t, nil))
	if err != nil {
		t.Fatalf("ParseConfig() error = %v", err)
	}
	if config.Flags.ShowAll {
		t.Fatal("ShowAll = true when verbose and trace are both set")
	}
}

func TestParseConfigDefaultServerEnvironmentAndFallback(t *testing.T) {
	t.Run("environment", func(t *testing.T) {
		config, err := ParseConfig([]string{"example.com", "A"}, testParseOptions(t, map[string]string{
			defaultServerEnv: "tls://dns.example",
		}))
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(config.Flags.Server, []string{"tls://dns.example"}) {
			t.Fatalf("Server = %v", config.Flags.Server)
		}
	})

	t.Run("fallback", func(t *testing.T) {
		parseOpts := testParseOptions(t, nil)
		parseOpts.ResolverConfigPath = filepath.Join(t.TempDir(), "missing-resolv.conf")
		config, err := ParseConfig([]string{"example.com", "A"}, parseOpts)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(config.Flags.Server, []string{fallbackServer}) {
			t.Fatalf("Server = %v", config.Flags.Server)
		}
	})
}

func testParseOptions(t *testing.T, environment map[string]string) ParseOptions {
	t.Helper()
	t.Setenv("SSLKEYLOGFILE", environment["SSLKEYLOGFILE"])
	homeDir := t.TempDir()
	resolverPath := filepath.Join(t.TempDir(), "resolv.conf")
	if err := os.WriteFile(resolverPath, []byte("nameserver 192.0.2.53\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return ParseOptions{
		StdoutIsTerminal: true,
		HomeDir:          homeDir,
		LookupEnv: func(name string) (string, bool) {
			value, ok := environment[name]
			return value, ok
		},
		ResolverConfigPath: resolverPath,
	}
}
