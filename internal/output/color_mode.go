package output

import (
	"fmt"
	"os"
	"strings"
)

type ColorMode int

const (
	ColorAuto ColorMode = iota
	ColorAlways
	ColorNever
)

func ParseColorMode(value string) (ColorMode, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "auto":
		return ColorAuto, nil
	case "always", "on", "true", "1":
		return ColorAlways, nil
	case "never", "off", "false", "0":
		return ColorNever, nil
	default:
		return ColorAuto, fmt.Errorf("invalid color mode %q (expected auto|always|never)", value)
	}
}

func ResolveColorMode(cliValue string) (ColorMode, error) {
	if strings.TrimSpace(cliValue) != "" {
		return ParseColorMode(cliValue)
	}

	if noColor := os.Getenv("NO_COLOR"); strings.TrimSpace(noColor) != "" {
		return ColorNever, nil
	}

	if force := os.Getenv("CLICOLOR_FORCE"); strings.TrimSpace(force) != "" && force != "0" {
		return ColorAlways, nil
	}

	if clicolor := os.Getenv("CLICOLOR"); strings.TrimSpace(clicolor) == "0" {
		return ColorNever, nil
	}

	if strings.EqualFold(os.Getenv("TERM"), "dumb") {
		return ColorNever, nil
	}

	return ColorAuto, nil
}
