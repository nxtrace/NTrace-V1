//go:build !linux || android

package trace

func resolveFWMarkSource(_ Method, _ Config) (string, error) {
	return "", ValidateFWMarkPlatform(true)
}
