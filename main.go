package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"diggo/internal/app"
	"diggo/internal/dnsx"
	"diggo/internal/output"
	"diggo/internal/rdap"
)

/* ---------------- Metadata ---------------- */

const (
	Resolver = "1.1.1.1:53"
)

//go:embed metadata.json
var rawMetadata []byte

var versionFieldOrder = []string{"name", "version", "maintainer", "build_date"}

func loadMetadata() map[string]any {
	if len(rawMetadata) == 0 {
		return map[string]any{}
	}

	meta := map[string]any{}
	if err := json.Unmarshal(rawMetadata, &meta); err != nil {
		return map[string]any{}
	}
	return meta
}

func formatMetadataValue(v any) string {
	switch val := v.(type) {
	case nil:
		return ""
	case string:
		return val
	case float64:
		if val == float64(int64(val)) {
			return fmt.Sprintf("%d", int64(val))
		}
		return fmt.Sprintf("%v", val)
	case bool:
		if val {
			return "true"
		}
		return "false"
	default:
		b, err := json.Marshal(val)
		if err != nil {
			return fmt.Sprintf("%v", val)
		}
		return string(b)
	}
}

func printVersionMetadata() {
	meta := loadMetadata()
	if len(meta) == 0 {
		fmt.Println("diggo")
		return
	}

	printed := map[string]bool{}
	for _, key := range versionFieldOrder {
		value, ok := meta[key]
		if !ok {
			continue
		}
		fmt.Printf("%s: %s\n", key, formatMetadataValue(value))
		printed[key] = true
	}

	keys := make([]string, 0, len(meta))
	for key := range meta {
		if printed[key] {
			continue
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		fmt.Printf("%s: %s\n", key, formatMetadataValue(meta[key]))
	}
}

/* ---------------- Flags ---------------- */

var (
	noRDAP          = flag.Bool("no-rdap", false, "Skip RDAP metadata lookup")
	color           = flag.String("color", "", "Color mode: auto, always, or never")
	theme           = flag.String("theme", "default", "Output theme: default, high-contrast, or minimal")
	resolver        = flag.String("resolver", Resolver, "DNS resolver to use (host:port)")
	timeout         = flag.String("timeout", "8s", "Query timeout duration (for example 8s, 1500ms)")
	jsonOut         = flag.Bool("json", false, "Emit JSON report output")
	compareResolver = flag.String("compare-resolver", "", "Optional secondary resolver for core-record comparison")
	showVer         = flag.Bool("version", false, "Show version and exit")
	coreOnly        = flag.Bool("core", false, "Show core records summary only")
	fullOut         = flag.Bool("full", false, "Show full output including core records")
)

func init() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `
Usage:
  %s [options] domain

Description:
  dig-like DNS inspection tool with optional RDAP metadata,
  subdomain handling, expiration warnings, and detailed DNS records.

Options:
`, os.Args[0])
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, `

Examples:
  %s example.com
  %s example.com --no-rdap
  %s mail.example.com
`, os.Args[0], os.Args[0], os.Args[0])
	}
}

/* ---------------- Argument normalization ---------------- */
/* Allows flags before OR after the domain */

func normalizeArgs() {
	var flags, args []string
	for _, a := range os.Args[1:] {
		if strings.HasPrefix(a, "-") {
			flags = append(flags, a)
		} else {
			args = append(args, a)
		}
	}
	os.Args = append([]string{os.Args[0]}, append(flags, args...)...)
}

func parseDomainArg() (string, error) {
	var domain string
	for _, a := range flag.Args() {
		if strings.HasPrefix(a, "-") {
			return "", fmt.Errorf("unknown flag: %s", a)
		}
		if domain == "" {
			domain = a
		} else {
			return "", fmt.Errorf("too many arguments")
		}
	}
	if domain == "" {
		return "", fmt.Errorf("no domain provided")
	}
	return domain, nil
}

/* ---------------- Main ---------------- */

func main() {
	normalizeArgs()
	flag.Parse()

	colorMode, err := output.ResolveColorMode(*color)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		flag.Usage()
		os.Exit(2)
	}
	output.SetupColors(colorMode)

	if err := output.SetTheme(*theme); err != nil {
		fmt.Fprintln(os.Stderr, err)
		flag.Usage()
		os.Exit(2)
	}

	if *showVer {
		printVersionMetadata()
		return
	}

	input, err := parseDomainArg()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		flag.Usage()
		os.Exit(1)
	}

	queryTimeout, err := time.ParseDuration(*timeout)
	if err != nil || queryTimeout <= 0 {
		fmt.Fprintln(os.Stderr, "invalid timeout; use a positive duration like 8s")
		flag.Usage()
		os.Exit(2)
	}

	ctx, cancel := context.WithTimeout(context.Background(), queryTimeout)
	defer cancel()

	dnsClient := dnsx.NewClient(*resolver, queryTimeout)
	rdapClient := rdap.NewClient(queryTimeout)
	service := app.NewService(dnsClient, rdapClient)

	report, err := service.BuildReport(ctx, input, *noRDAP)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	if strings.TrimSpace(*compareResolver) != "" {
		cmpDNS := dnsx.NewClient(*compareResolver, queryTimeout)
		cmpService := app.NewService(cmpDNS, rdapClient)
		cmpReport, cmpErr := cmpService.BuildReport(ctx, input, true)
		if cmpErr != nil {
			fmt.Fprintln(os.Stderr, "compare resolver failed:", cmpErr)
			os.Exit(1)
		}

		if *jsonOut {
			payload := struct {
				Resolver        string `json:"resolver"`
				CompareResolver string `json:"compareResolver"`
				Primary         any    `json:"primary"`
				Comparison      any    `json:"comparison"`
			}{
				Resolver:        *resolver,
				CompareResolver: *compareResolver,
				Primary:         report,
				Comparison:      cmpReport,
			}
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			if err := enc.Encode(payload); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			return
		}

		output.PrintFull(report)
		output.PrintComparison(*resolver, *compareResolver, report, cmpReport)
		return
	}

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}

	switch {
	case *coreOnly:
		output.PrintCoreOnly(report)
	case *fullOut:
		output.PrintFull(report)
	default:
		output.PrintReport(report)
	}
}
