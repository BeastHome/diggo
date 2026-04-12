//go:build windows
// +build windows

package output

import (
	"os"

	"golang.org/x/sys/windows"
)

func enableWindowsANSI() {
	handle := windows.Handle(os.Stdout.Fd())
	var mode uint32

	if err := windows.GetConsoleMode(handle, &mode); err != nil {
		defaultUseColor = false
		return
	}

	mode |= windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING
	if err := windows.SetConsoleMode(handle, mode); err != nil {
		defaultUseColor = false
	}
}
