package trace

import (
	"net"
	"runtime"
	"testing"
)

func TestFWMarkSourceConstraints(t *testing.T) {
	cfg := Config{DstIP: net.ParseIP("127.0.0.1"), SrcAddr: "127.0.0.1", FWMark: 256, FWMarkSet: true}
	got, err := PrepareFWMarkConfig(ICMPTrace, cfg)
	if runtime.GOOS != "linux" {
		if err == nil || !IsInitializationError(err) {
			t.Fatal(err)
		}
		return
	}
	if err != nil || got.SrcAddr != cfg.SrcAddr || got.FWMark != 256 {
		t.Fatalf("%+v %v", got, err)
	}
	for _, src := range []string{"::1", "0.0.0.0", "bad"} {
		cfg.SrcAddr = src
		if _, err := PrepareFWMarkConfig(ICMPTrace, cfg); err == nil || !IsInitializationError(err) {
			t.Fatalf("%s %v", src, err)
		}
	}
	cfg.FWMarkSet = false
	if _, err := PrepareFWMarkConfig(ICMPTrace, cfg); err != nil {
		t.Fatal("unmarked path changed", err)
	}
}

func TestTOSSourcePreparationPlatformBoundary(t *testing.T) {
	cfg := Config{TOS: 184}
	_, err := PrepareProbeSourceConfig(ICMPTrace, cfg)
	if runtime.GOOS == "linux" {
		if !IsInitializationError(err) {
			t.Fatalf("Linux policy route accepted an invalid target: %v", err)
		}
	} else if err != nil {
		t.Fatalf("TOS incorrectly acquired the Linux-only fwmark restriction: %v", err)
	}
}
