package windivert

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
)

//go:embed x64/WinDivert.dll
var winDivertDLL64 []byte

//go:embed x64/WinDivert64.sys
var winDivertSYS64 []byte

//go:embed x86/WinDivert.dll
var winDivertDLL32 []byte

//go:embed x86/WinDivert32.sys
var winDivertSYS32 []byte

// PrepareWinDivertRuntime extracts the embedded WinDivert DLL and driver to the directory
// containing the current executable. It selects 32- or 64-bit assets based on runtime.GOARCH
// and writes them as WinDivert.dll and WinDivert32.sys or WinDivert64.sys, overwriting files
// only when their contents differ; an error is returned if the executable path cannot be
// determined, the architecture is unsupported, or writing the files fails.
func PrepareWinDivertRuntime() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	exeDir := filepath.Dir(exe)

	var dllBytes, sysBytes []byte
	var sysName string

	switch runtime.GOARCH {
	case "amd64", "arm64":
		dllBytes, sysBytes, sysName = winDivertDLL64, winDivertSYS64, "WinDivert64.sys"
	case "386", "arm":
		dllBytes, sysBytes, sysName = winDivertDLL32, winDivertSYS32, "WinDivert32.sys"
	default:
		return errors.New("unsupported GOARCH for WinDivert: " + runtime.GOARCH)
	}

	// DLL
	if err := writeIfChecksumDiff(filepath.Join(exeDir, "WinDivert.dll"), dllBytes); err != nil {
		return err
	}

	// SYS
	if err := writeIfChecksumDiff(filepath.Join(exeDir, sysName), sysBytes); err != nil {
		return err
	}
	return nil
}

// writeIfChecksumDiff writes data to dst only when the SHA-256 checksum of data differs from the existing file.
// It creates or overwrites dst with file mode 0644 when the checksums differ or when dst cannot be read.
// Returns any error encountered while reading the existing file or writing dst.
func writeIfChecksumDiff(dst string, data []byte) error {
	file, err := os.Open(dst)
	if err != nil {
		return os.WriteFile(dst, data, 0o644) // 读失败，则尝试覆盖
	}

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		_ = file.Close()                      // 先关再写，避免 Windows 共享冲突
		return os.WriteFile(dst, data, 0o644) // 读失败，则尝试覆盖
	}

	sumFile := hash.Sum(nil)
	_ = file.Close() // 先关再写，避免 Windows 共享冲突
	sumMem := sha256.Sum256(data)
	if bytes.Equal(sumFile, sumMem[:]) {
		return nil // 一致，跳过
	}
	return os.WriteFile(dst, data, 0o644) // 不一致，则尝试覆盖
}