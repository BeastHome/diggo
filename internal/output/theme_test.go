package output

import (
	"bytes"
	"strings"
	"testing"

	"diggo/internal/model"
)

func TestParseTheme(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{name: "empty default", in: "", want: ThemeDefault},
		{name: "default", in: "default", want: ThemeDefault},
		{name: "high contrast", in: "high-contrast", want: ThemeHighContrast},
		{name: "minimal", in: "minimal", want: ThemeMinimal},
		{name: "invalid", in: "neon", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseTheme(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error for input %q", tc.in)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseTheme(%q) returned error: %v", tc.in, err)
			}
			if got != tc.want {
				t.Fatalf("ParseTheme(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestSetTheme(t *testing.T) {
	old := defaultThemeName
	t.Cleanup(func() { defaultThemeName = old })

	if err := SetTheme("high-contrast"); err != nil {
		t.Fatalf("SetTheme returned error: %v", err)
	}
	if defaultThemeName != ThemeHighContrast {
		t.Fatalf("expected defaultThemeName=%q, got %q", ThemeHighContrast, defaultThemeName)
	}

	if err := SetTheme("invalid"); err == nil {
		t.Fatalf("expected SetTheme invalid input to return error")
	}
}

func TestNewPrinterWithTheme_AppliesThemeStyles(t *testing.T) {
	report := &model.Report{Domain: "example.com"}

	var bufDefault bytes.Buffer
	defaultPrinter := NewPrinterWithTheme(&bufDefault, true, ThemeDefault)
	defaultPrinter.PrintReport(report)
	defaultOut := bufDefault.String()

	var bufHigh bytes.Buffer
	highPrinter := NewPrinterWithTheme(&bufHigh, true, ThemeHighContrast)
	highPrinter.PrintReport(report)
	highOut := bufHigh.String()

	if defaultOut == highOut {
		t.Fatalf("expected themed output to differ between default and high-contrast")
	}
	if !strings.Contains(highOut, "\x1b[1m\x1b[37mA record(s):") {
		t.Fatalf("expected high-contrast header style in output, got: %q", highOut)
	}
}
