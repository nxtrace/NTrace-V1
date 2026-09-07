package cmd

import (
	"fmt"
	"github.com/nxtrace/NTrace-core/printer"
	"strings"
)

func containsMTRColumnsFlag(args []string) bool {
	for _, arg := range args {
		if arg == "--" {
			break
		}
		if arg == "--mtr-columns" || strings.HasPrefix(arg, "--mtr-columns=") {
			return true
		}
	}
	return false
}

func resolveMTRColumns(value string, explicit bool, modes effectiveMTRModes, json bool, standalone string) ([]printer.MTRColumn, error) {
	if !explicit {
		return nil, nil
	}
	if !modes.mtr || modes.raw || json || standalone != "" {
		return nil, fmt.Errorf("--mtr-columns requires MTR text mode (--mtr/--report/--wide); unavailable with raw, JSON, traceroute or standalone modes")
	}
	return printer.ParseMTRColumns(value, false)
}
