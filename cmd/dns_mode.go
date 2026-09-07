package cmd

import (
	"fmt"
	"io"

	"github.com/akamensky/argparse"
)

type dnsModeRunner func([]string, io.Writer, io.Writer) int

func registerDNSFlagWithAvailability(parser *argparse.Parser, enabled bool) *bool {
	if enabled {
		return parser.Flag("l", "dns", &argparse.Options{Help: "Run DNS client mode. See `nexttrace --dns --help` for details"})
	}
	return ptrBool(false)
}

func maybeRunDNSModeWithAvailability(
	enabled bool,
	rawArgs []string,
	stdout, stderr io.Writer,
	runner dnsModeRunner,
) (bool, int) {
	if !enabled && containsDNSModeMarker(rawArgs) {
		_, _ = fmt.Fprintf(stderr, "-l/--dns is not available in %s; please use the full nexttrace build\n", appBinName)
		return true, 1
	}
	if len(rawArgs) == 0 || !isDNSModeMarker(rawArgs[0]) {
		return false, 0
	}
	if !enabled {
		_, _ = fmt.Fprintf(stderr, "-l/--dns is not available in %s; please use the full nexttrace build\n", appBinName)
		return true, 1
	}
	if containsFWMarkFlag(rawArgs) {
		fmt.Fprintln(stderr, "--fwmark cannot be combined with --dns")
		return true, 2
	}
	if containsTracerouteFlag(rawArgs) {
		_, _ = fmt.Fprintln(stderr, "--traceroute cannot be combined with --dns")
		return true, 1
	}
	if containsMTRColumnsFlag(rawArgs) {
		_, _ = fmt.Fprintln(stderr, "--mtr-columns cannot be combined with a standalone mode")
		return true, 2
	}
	return true, runner(rawArgs[1:], stdout, stderr)
}

func isDNSModeMarker(arg string) bool {
	return arg == "-l" || arg == "--dns"
}

func containsDNSModeMarker(args []string) bool {
	for _, arg := range args {
		if arg == "--" {
			return false
		}
		if isDNSModeMarker(arg) {
			return true
		}
	}
	return false
}
