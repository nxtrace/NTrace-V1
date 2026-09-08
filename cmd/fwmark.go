package cmd

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/nxtrace/NTrace-core/trace"
)

func parseFWMark(value string, explicit bool) (uint32, error) {
	if !explicit {
		return 0, nil
	}
	base := 10
	digits := value
	if strings.HasPrefix(digits, "0x") || strings.HasPrefix(digits, "0X") {
		base, digits = 16, digits[2:]
	}
	if digits == "" {
		return 0, fmt.Errorf("--fwmark requires a decimal or hexadecimal uint32")
	}
	for _, c := range digits {
		if (c >= '0' && c <= '9') || (base == 16 && ((c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
			continue
		}
		return 0, fmt.Errorf("invalid --fwmark %q: expected decimal or hexadecimal uint32", value)
	}
	mark, err := strconv.ParseUint(digits, base, 32)
	if err != nil {
		return 0, fmt.Errorf("invalid --fwmark %q: expected 0..4294967295", value)
	}
	return uint32(mark), nil
}

func containsFWMarkFlag(args []string) bool {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			break
		}
		name, _, inline := strings.Cut(arg, "=")
		if name == "--fwmark" {
			return true
		}
		if strings.HasPrefix(arg, "-") && !inline && doctorValueOption(strings.TrimLeft(name, "-")) {
			i++
		}
	}
	return false
}

func validateFWMarkMode(explicit bool, unsupported ...bool) error {
	if !explicit {
		return nil
	}
	if err := trace.ValidateFWMarkPlatform(true); err != nil {
		return err
	}
	for _, active := range unsupported {
		if active {
			return fmt.Errorf("--fwmark supports only local traceroute and MTR; standalone, batch and remote modes are unsupported")
		}
	}
	return nil
}

func resolveCLIProbeSource(method trace.Method, cfg trace.Config) (trace.Config, error) {
	// Resolve policy-routed sources before the legacy UDP fallback. In particular,
	// a nonzero TOS may select a different Linux route and source without a mark.
	normalized, err := trace.NormalizeExplicitSourceConfig(method, cfg)
	if err != nil {
		return cfg, err
	}
	src, _, err := trace.ResolveConfiguredSrcAddr(normalized.DstIP, normalized.SrcAddr, normalized.SourceDevice)
	if err != nil {
		return cfg, err
	}
	normalized.SrcAddr = src
	return normalized, nil
}
