package output

import (
	"fmt"
	"strings"
)

const (
	ThemeDefault      = "default"
	ThemeHighContrast = "high-contrast"
	ThemeMinimal      = "minimal"
)

var defaultThemeName = ThemeDefault

func ParseTheme(name string) (string, error) {
	normalized := strings.ToLower(strings.TrimSpace(name))
	if normalized == "" {
		return ThemeDefault, nil
	}

	switch normalized {
	case ThemeDefault, ThemeHighContrast, ThemeMinimal:
		return normalized, nil
	default:
		return "", fmt.Errorf("invalid theme %q (expected default|high-contrast|minimal)", name)
	}
}

func SetTheme(name string) error {
	parsed, err := ParseTheme(name)
	if err != nil {
		return err
	}
	defaultThemeName = parsed
	return nil
}

func themeStyles(name string) map[styleRole]string {
	switch name {
	case ThemeHighContrast:
		return map[styleRole]string{
			styleHeader: bold + white,
			styleTitle:  bold + white,
			styleHost:   bold + cyan,
			styleIP:     bold + green,
			styleValue:  white,
			styleOK:     bold + green,
			styleWarn:   bold + yellow,
			styleError:  bold + red,
		}
	case ThemeMinimal:
		return map[styleRole]string{
			styleHeader: bold,
			styleTitle:  bold,
			styleHost:   "",
			styleIP:     "",
			styleValue:  "",
			styleOK:     bold,
			styleWarn:   bold,
			styleError:  bold,
		}
	default:
		return map[styleRole]string{
			styleHeader: blue,
			styleTitle:  cyan,
			styleHost:   magenta,
			styleIP:     yellow,
			styleValue:  "",
			styleOK:     green,
			styleWarn:   bold + yellow,
			styleError:  red,
		}
	}
}
