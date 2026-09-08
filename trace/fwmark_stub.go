//go:build !linux || android

package trace

func resolveProbeRouteSource(_ Method, _ Config) (string, error) {
	return "", ValidateFWMarkPlatform(true)
}
