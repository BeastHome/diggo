//go:build !windows
// +build !windows

package output

func enableWindowsANSI() {
	// No-op on non-Windows platforms.
}
