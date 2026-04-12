package output

import "testing"

func TestParseColorMode(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    ColorMode
		wantErr bool
	}{
		{name: "empty defaults auto", in: "", want: ColorAuto},
		{name: "auto", in: "auto", want: ColorAuto},
		{name: "always", in: "always", want: ColorAlways},
		{name: "always alias on", in: "on", want: ColorAlways},
		{name: "never", in: "never", want: ColorNever},
		{name: "never alias off", in: "off", want: ColorNever},
		{name: "invalid", in: "rainbow", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseColorMode(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error for input %q", tc.in)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseColorMode(%q) returned error: %v", tc.in, err)
			}
			if got != tc.want {
				t.Fatalf("ParseColorMode(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestResolveColorMode_Precedence(t *testing.T) {
	t.Setenv("NO_COLOR", "")
	t.Setenv("CLICOLOR", "")
	t.Setenv("CLICOLOR_FORCE", "")
	t.Setenv("TERM", "xterm-256color")

	t.Run("cli always wins", func(t *testing.T) {
		t.Setenv("NO_COLOR", "1")
		got, err := ResolveColorMode("always")
		if err != nil {
			t.Fatalf("ResolveColorMode returned error: %v", err)
		}
		if got != ColorAlways {
			t.Fatalf("expected ColorAlways, got %v", got)
		}
	})

	t.Run("no_color env", func(t *testing.T) {
		t.Setenv("NO_COLOR", "1")
		got, err := ResolveColorMode("")
		if err != nil {
			t.Fatalf("ResolveColorMode returned error: %v", err)
		}
		if got != ColorNever {
			t.Fatalf("expected ColorNever, got %v", got)
		}
	})

	t.Run("clicolor_force env", func(t *testing.T) {
		t.Setenv("CLICOLOR_FORCE", "1")
		got, err := ResolveColorMode("")
		if err != nil {
			t.Fatalf("ResolveColorMode returned error: %v", err)
		}
		if got != ColorAlways {
			t.Fatalf("expected ColorAlways, got %v", got)
		}
	})

	t.Run("clicolor off env", func(t *testing.T) {
		t.Setenv("CLICOLOR", "0")
		got, err := ResolveColorMode("")
		if err != nil {
			t.Fatalf("ResolveColorMode returned error: %v", err)
		}
		if got != ColorNever {
			t.Fatalf("expected ColorNever, got %v", got)
		}
	})

	t.Run("term dumb env", func(t *testing.T) {
		t.Setenv("TERM", "dumb")
		got, err := ResolveColorMode("")
		if err != nil {
			t.Fatalf("ResolveColorMode returned error: %v", err)
		}
		if got != ColorNever {
			t.Fatalf("expected ColorNever, got %v", got)
		}
	})

	t.Run("default auto", func(t *testing.T) {
		got, err := ResolveColorMode("")
		if err != nil {
			t.Fatalf("ResolveColorMode returned error: %v", err)
		}
		if got != ColorAuto {
			t.Fatalf("expected ColorAuto, got %v", got)
		}
	})
}
