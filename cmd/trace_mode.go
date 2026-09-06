package cmd

import (
	"fmt"

	"github.com/akamensky/argparse"
)

func registerTracerouteFlag(parser *argparse.Parser) *bool {
	return registerTracerouteFlagWithAvailability(parser, enableTraceroute)
}

func registerTracerouteFlagWithAvailability(parser *argparse.Parser, enabled bool) *bool {
	if enabled {
		return parser.Flag("k", "traceroute", &argparse.Options{Help: "Use traditional traceroute mode; with --raw, preserve traditional raw output"})
	}
	return ptrBool(false)
}

type traceModeOptions struct {
	traceroute  bool
	mtr         bool
	report      bool
	wide        bool
	raw         bool
	traditional bool
	standalone  string
}

// Explicit modes take precedence over the default, never over conflicting flags.
// traditional covers traceroute output formats and its batch/remote workflows.
func resolveTraceModes(opts traceModeOptions, useMTRByDefault bool) (effectiveMTRModes, error) {
	if opts.traceroute {
		for _, flag := range []struct {
			name string
			set  bool
		}{
			{"--mtr", opts.mtr},
			{"--report", opts.report},
			{"--wide", opts.wide},
			{opts.standalone, opts.standalone != ""},
		} {
			if flag.set {
				return effectiveMTRModes{}, fmt.Errorf("--traceroute cannot be combined with %s", flag.name)
			}
		}
	}
	mtr := opts.mtr || (useMTRByDefault && !opts.traceroute && !opts.traditional && opts.standalone == "")
	return deriveEffectiveMTRModes(mtr, opts.report, opts.wide, opts.raw), nil
}

// DNS and speed dispatch before the main parser. Do not consume anything after --.
func containsTracerouteFlag(args []string) bool {
	for _, arg := range args {
		if arg == "--" {
			return false
		}
		if arg == "-k" || arg == "--traceroute" {
			return true
		}
	}
	return false
}
