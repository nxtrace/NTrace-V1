//go:build !flavor_tiny && !flavor_ntr

package dnsclient

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"

	flags "github.com/jessevdk/go-flags"
	"github.com/miekg/dns"
	"github.com/natesales/q/cli"
	"golang.org/x/net/idna"
)

const (
	defaultServerEnv = "Q_DEFAULT_SERVER"
	fallbackServer   = "https://cloudflare-dns.com/dns-query"
)

// Config is the normalized q-compatible input consumed by the DNS runner.
type Config struct {
	Flags               cli.Flags
	RRTypes             []uint16
	Warnings            []string
	EarlyDebugMessages  []string
	DebugMessages       []string
	CompletionRequested bool
	CompletionVerbose   bool
	Completions         []flags.Completion
}

// ParseOptions isolates filesystem and environment input for argument parsing.
type ParseOptions struct {
	StdoutIsTerminal   bool
	HomeDir            string
	LookupEnv          func(string) (string, bool)
	ResolverConfigPath string
}

// DefaultParseOptions returns the process-backed parsing dependencies.
func DefaultParseOptions(stdoutIsTerminal bool) ParseOptions {
	homeDir, _ := os.UserHomeDir()
	return ParseOptions{
		StdoutIsTerminal:   stdoutIsTerminal,
		HomeDir:            homeDir,
		LookupEnv:          os.LookupEnv,
		ResolverConfigPath: "/etc/resolv.conf",
	}
}

// ParseConfig parses q arguments without terminating the process on invalid input.
func ParseConfig(args []string, parseOpts ParseOptions) (Config, error) {
	lookupEnv := parseOpts.LookupEnv
	if lookupEnv == nil {
		lookupEnv = os.LookupEnv
	}

	opts := cli.Flags{}
	cli.SetDefaultTrueBools(&opts)
	opts.Color = parseOpts.StdoutIsTerminal
	if value, _ := lookupEnv("NO_COLOR"); value != "" {
		opts.Color = false
	}

	configArgs, warnings := loadQRC(parseOpts.HomeDir)
	allArgs := append(configArgs, args...)
	allArgs = cli.SetFalseBooleans(&opts, append([]string(nil), allArgs...))
	allArgs = cli.AddEqualSigns(allArgs)

	var completions []flags.Completion
	completionRequested := false
	parser := newFlagsParser(&opts, func(items []flags.Completion) {
		completionRequested = true
		completions = append([]flags.Completion(nil), items...)
	})
	if _, err := parser.ParseArgs(allArgs); err != nil {
		return Config{}, err
	}
	if !hasLongOption(allArgs, "tls-key-log-file") {
		if value, ok := lookupEnv("SSLKEYLOGFILE"); ok {
			opts.TLSKeyLogFile = value
		}
	}
	if completionRequested {
		completionValue, _ := lookupEnv("GO_FLAGS_COMPLETION")
		return Config{
			Flags:               opts,
			Warnings:            warnings,
			CompletionRequested: true,
			CompletionVerbose:   completionValue == "verbose",
			Completions:         completions,
		}, nil
	}
	if err := applyPlusFlags(&opts, allArgs); err != nil {
		return Config{}, err
	}

	if !opts.Verbose && opts.Trace {
		opts.ShowAll = true
	}
	if opts.ShowVersion {
		return Config{Flags: opts, Warnings: warnings}, nil
	}
	expandShowAll(&opts)
	rrTypes, err := collectRRTypes(&opts, allArgs)
	if err != nil {
		return Config{}, err
	}
	earlyDebugMessages := numericRRTypeDebugMessages(opts.Types)
	if err := normalizeName(&opts, &rrTypes); err != nil {
		return Config{}, err
	}
	debugMessages := setDefaultServer(&opts, lookupEnv, parseOpts.ResolverConfigPath)
	if err := validateODoH(opts); err != nil {
		return Config{}, err
	}
	if opts.Chaos {
		opts.Class = dns.ClassCHAOS
	}
	if opts.NSIDOnly {
		opts.NSID = true
	}

	return Config{
		Flags:              opts,
		RRTypes:            rrTypes,
		Warnings:           warnings,
		EarlyDebugMessages: earlyDebugMessages,
		DebugMessages:      debugMessages,
	}, nil
}

func hasLongOption(args []string, name string) bool {
	prefix := "--" + name
	for _, arg := range args {
		if arg == prefix || strings.HasPrefix(arg, prefix+"=") {
			return true
		}
	}
	return false
}

func newFlagsParser(
	opts *cli.Flags,
	onCompletion func([]flags.Completion),
) *flags.Parser {
	parser := flags.NewNamedParser("nexttrace --dns", flags.HelpFlag|flags.PassDoubleDash)
	parser.Usage = `[OPTIONS] [@server] [type...] [name]

All long form (--) flags can be toggled with the dig-standard +[no]flag notation.`
	_, _ = parser.AddGroup("Application Options", "", opts)
	parser.CompletionHandler = onCompletion
	return parser
}

func loadQRC(homeDir string) ([]string, []string) {
	if homeDir == "" {
		return nil, nil
	}
	configPath := filepath.Join(homeDir, ".qrc")
	file, err := os.Open(configPath)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, []string{fmt.Sprintf("could not open config file %s: %v", configPath, err)}
	}
	defer file.Close()

	var configArgs []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		configArgs = append(configArgs, strings.Fields(line)...)
	}
	if err := scanner.Err(); err != nil {
		return configArgs, []string{fmt.Sprintf("error reading config file %s: %v", configPath, err)}
	}
	return configArgs, nil
}

func applyPlusFlags(opts *cli.Flags, args []string) error {
	value := reflect.ValueOf(opts).Elem()
	typ := value.Type()
	for _, arg := range args {
		if len(arg) <= 3 || arg[0] != '+' {
			continue
		}
		state := arg[1:3] != "no"
		name := strings.ToLower(arg[3:])
		if state {
			name = strings.ToLower(arg[1:])
		}

		found := false
		for i := 0; i < value.NumField(); i++ {
			field := typ.Field(i)
			if field.Type.Kind() == reflect.Bool && field.Tag.Get("long") == name {
				value.Field(i).SetBool(state)
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("unknown flag %s", arg)
		}
	}
	return nil
}

func expandShowAll(opts *cli.Flags) {
	if opts.ShowAll {
		opts.ShowQuestion = true
		opts.ShowAnswer = true
		opts.ShowAuthority = true
		opts.ShowAdditional = true
		opts.ShowStats = true
	}
}

func collectRRTypes(opts *cli.Flags, args []string) ([]uint16, error) {
	var rrTypes []uint16
	seen := make(map[uint16]bool)
	for _, requestedType := range opts.Types {
		parsed, err := cli.ParseRRTypes([]string{requestedType})
		if err != nil {
			return nil, err
		}
		for rrType := range parsed {
			rrTypes = appendRRType(rrTypes, seen, rrType)
		}
	}

	for _, arg := range args {
		if strings.HasPrefix(arg, "@") {
			opts.Server = append(opts.Server, strings.TrimPrefix(arg, "@"))
		}
		if strings.EqualFold(arg, "ch") {
			opts.Chaos = true
		}
		rrType, typeFound := dns.StringToType[strings.ToUpper(arg)]
		if typeFound {
			rrTypes = appendRRType(rrTypes, seen, rrType)
			if rrType == dns.TypeNS {
				opts.ShowAuthority = true
				opts.ShowAdditional = true
			}
		}
		if opts.Name == "" && isQNameArgument(arg, typeFound) {
			opts.Name = arg
		}
	}

	if len(rrTypes) == 0 {
		if opts.Name == "" {
			return []uint16{dns.TypeNS}, nil
		}
		for _, defaultType := range opts.DefaultRRTypes {
			rrTypes = appendRRType(rrTypes, seen, dns.StringToType[defaultType])
		}
	}
	return rrTypes, nil
}

func numericRRTypeDebugMessages(types []string) []string {
	messages := make([]string, 0, len(types))
	for _, requestedType := range types {
		upperType := strings.ToUpper(requestedType)
		if strings.HasPrefix(upperType, "TYPE") {
			if typeCode, err := strconv.Atoi(strings.TrimPrefix(upperType, "TYPE")); err == nil {
				messages = append(messages, fmt.Sprintf("using RR type %d from TYPE notation", typeCode))
			}
			continue
		}
		if _, known := dns.StringToType[upperType]; known {
			continue
		}
		if typeCode, err := strconv.Atoi(requestedType); err == nil {
			messages = append(messages, fmt.Sprintf("using RR type %d as integer", typeCode))
		}
	}
	return messages
}

func appendRRType(types []uint16, seen map[uint16]bool, rrType uint16) []uint16 {
	if !seen[rrType] {
		seen[rrType] = true
		return append(types, rrType)
	}
	return types
}

func isQNameArgument(arg string, typeFound bool) bool {
	return !strings.ContainsAny(arg, "@/\\+") &&
		!typeFound &&
		!strings.HasSuffix(arg, ".exe") &&
		!strings.HasPrefix(arg, "-")
}

func normalizeName(opts *cli.Flags, rrTypes *[]uint16) error {
	if opts.Reverse {
		name, err := dns.ReverseAddr(opts.Name)
		if err != nil {
			return fmt.Errorf("dns reverse: %w", err)
		}
		opts.Name = name
		seen := make(map[uint16]bool, len(*rrTypes)+1)
		for _, rrType := range *rrTypes {
			seen[rrType] = true
		}
		*rrTypes = appendRRType(*rrTypes, seen, dns.TypePTR)
		return nil
	}
	if opts.Name == "" {
		return nil
	}
	lowerName := strings.ToLower(opts.Name)
	if strings.HasSuffix(lowerName, ".in-addr.arpa") || strings.HasSuffix(lowerName, ".ip6.arpa") {
		return nil
	}
	profile := idna.New(idna.MapForLookup(), idna.StrictDomainName(false))
	name, err := profile.ToASCII(opts.Name)
	if err != nil {
		return fmt.Errorf("idna toascii: %w", err)
	}
	opts.Name = name
	return nil
}

func setDefaultServer(opts *cli.Flags, lookupEnv func(string) (string, bool), resolverConfigPath string) []string {
	if len(opts.Server) != 0 {
		return nil
	}
	if server, _ := lookupEnv(defaultServerEnv); server != "" {
		opts.Server = []string{server}
		return []string{fmt.Sprintf("Using %s from %s environment variable", opts.Server, defaultServerEnv)}
	}
	debugMessages := []string{fmt.Sprintf("No server specified or %s set, using /etc/resolv.conf", defaultServerEnv)}
	if resolverConfigPath == "" {
		resolverConfigPath = "/etc/resolv.conf"
	}
	config, err := dns.ClientConfigFromFile(resolverConfigPath)
	if err == nil && len(config.Servers) > 0 {
		opts.Server = []string{config.Servers[0]}
		return append(debugMessages, fmt.Sprintf("found server %s from /etc/resolv.conf", opts.Server))
	}
	opts.Server = []string{fallbackServer}
	return append(debugMessages, fmt.Sprintf("no server set, using %s", opts.Server))
}

func validateODoH(opts cli.Flags) error {
	if opts.ODoHProxy == "" {
		return nil
	}
	if !strings.HasPrefix(opts.ODoHProxy, "https://") {
		return fmt.Errorf("ODoH proxy must use HTTPS")
	}
	for _, server := range opts.Server {
		if !strings.HasPrefix(server, "https://") {
			return fmt.Errorf("ODoH target must use HTTPS")
		}
	}
	return nil
}
