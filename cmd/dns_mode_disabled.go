//go:build flavor_tiny || flavor_ntr

package cmd

import (
	"io"

	"github.com/akamensky/argparse"
)

func registerDNSFlag(parser *argparse.Parser) *bool {
	return registerDNSFlagWithAvailability(parser, false)
}

func maybeRunDNSMode(rawArgs []string, stdout, stderr io.Writer) (bool, int) {
	return maybeRunDNSModeWithAvailability(false, rawArgs, stdout, stderr, nil)
}
