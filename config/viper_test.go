package config

import (
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/spf13/viper"
)

func TestConfigAccessorsAreSafeDuringConcurrentInit(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	geoFeedPath := filepath.Join(dir, "geofeed.csv")
	ptrPath := filepath.Join(dir, "ptr.csv")
	content := []byte("geoFeedPath: " + geoFeedPath + "\nptrPath: " + ptrPath + "\n")
	configPath := filepath.Join(dir, "nt_config.yaml")
	if err := os.WriteFile(configPath, content, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	viper.Reset()
	viper.SetConfigFile(configPath)
	InitConfig()
	t.Cleanup(viper.Reset)

	const workers = 16
	var wait sync.WaitGroup
	for range workers {
		wait.Go(func() {
			for range 25 {
				InitConfig()
				_ = GeoFeedPath()
				_ = PtrPath()
			}
		})
	}
	wait.Wait()

	if got := GeoFeedPath(); got != geoFeedPath {
		t.Fatalf("GeoFeedPath() = %q, want %q", got, geoFeedPath)
	}
	if got := PtrPath(); got != ptrPath {
		t.Fatalf("PtrPath() = %q, want %q", got, ptrPath)
	}
}
