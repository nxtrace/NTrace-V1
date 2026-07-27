//go:build !flavor_tiny && !flavor_ntr

package dnsclient

import (
	"os"
	"testing"

	"golang.org/x/mod/modfile"
)

func TestQDependencyIsExactlyPinnedWithoutReplace(t *testing.T) {
	data, err := os.ReadFile("../../go.mod")
	if err != nil {
		t.Fatal(err)
	}
	module, err := modfile.Parse("go.mod", data, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, dependency := range module.Require {
		if dependency.Mod.Path != "github.com/natesales/q" {
			continue
		}
		if dependency.Mod.Version != qCompatibilityVersion {
			t.Fatalf("q version = %s, want %s", dependency.Mod.Version, qCompatibilityVersion)
		}
		for _, replacement := range module.Replace {
			if replacement.Old.Path == dependency.Mod.Path {
				t.Fatalf("q dependency uses replace: %s => %s", replacement.Old, replacement.New)
			}
		}
		return
	}
	t.Fatal("q dependency missing from go.mod")
}
