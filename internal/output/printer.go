package output

import (
	"fmt"
	"io"
	"os"
	"strings"

	"diggo/internal/model"

	"golang.org/x/term"
)

var defaultUseColor = true

const (
	reset   = "\033[0m"
	bold    = "\033[1m"
	red     = "\033[31m"
	green   = "\033[32m"
	yellow  = "\033[33m"
	blue    = "\033[34m"
	magenta = "\033[35m"
	cyan    = "\033[36m"
	white   = "\033[37m"
)

type styleRole int

const (
	styleHeader styleRole = iota
	styleTitle
	styleHost
	styleIP
	styleValue
	styleOK
	styleWarn
	styleError
)

func SetupColors(mode ColorMode) {
	switch mode {
	case ColorNever:
		defaultUseColor = false
		return
	case ColorAlways:
		defaultUseColor = true
		enableWindowsANSI()
		return
	default:
		defaultUseColor = term.IsTerminal(int(os.Stdout.Fd()))
		if defaultUseColor {
			enableWindowsANSI()
		}
	}
}

type Printer struct {
	w        io.Writer
	useColor bool
	styles   map[styleRole]string
}

func NewPrinter(w io.Writer, useColor bool) *Printer {
	return NewPrinterWithTheme(w, useColor, ThemeDefault)
}

func NewPrinterWithTheme(w io.Writer, useColor bool, themeName string) *Printer {
	if w == nil {
		w = io.Discard
	}
	parsedTheme, err := ParseTheme(themeName)
	if err != nil {
		parsedTheme = ThemeDefault
	}

	return &Printer{
		w:        w,
		useColor: useColor,
		styles:   themeStyles(parsedTheme),
	}
}

func (p *Printer) style(role styleRole, text string) string {
	if !p.useColor {
		return text
	}
	code := p.styles[role]
	if code == "" {
		return text
	}
	return code + text + reset
}

func (p *Printer) header(s string)          { fmt.Fprintln(p.w, p.style(styleHeader, s)) }
func (p *Printer) hostname(s string) string { return p.style(styleHost, s) }
func (p *Printer) ipaddr(s string) string   { return p.style(styleIP, s) }
func (p *Printer) txtval(s string) string   { return p.style(styleValue, s) }

func (p *Printer) okLabel(s string) string   { return p.style(styleOK, s) }
func (p *Printer) warnLabel(s string) string { return p.style(styleWarn, s) }

func PrintReport(r *model.Report) {
	NewPrinterWithTheme(os.Stdout, defaultUseColor, defaultThemeName).PrintReport(r)
}

func PrintFull(r *model.Report) {
	NewPrinterWithTheme(os.Stdout, defaultUseColor, defaultThemeName).PrintFull(r)
}

func PrintCoreOnly(r *model.Report) {
	NewPrinterWithTheme(os.Stdout, defaultUseColor, defaultThemeName).PrintCoreOnly(r)
}

func (p *Printer) PrintFull(r *model.Report) {
	p.printReport(r, true)
}

func (p *Printer) PrintReport(r *model.Report) {
	p.printReport(r, false)
}

func (p *Printer) PrintCoreOnly(r *model.Report) {
	p.printCoreRecords(r)
	fmt.Fprintln(p.w)
}

func (p *Printer) printReport(r *model.Report, includeCore bool) {
	if r.RDAPError {
		p.header("RDAP:")
		fmt.Fprintln(p.w, p.style(styleError, " RDAP lookup failed."))
		fmt.Fprintln(p.w)
	} else if r.RDAPUnavailable {
		p.header("RDAP:")
		fmt.Fprintln(p.w, p.style(styleWarn, " No RDAP data available (TLD may not support RDAP, or domain is unregistered)."))
		fmt.Fprintln(p.w)
	} else if r.RDAP != nil {
		p.header("RDAP:")
		fmt.Fprintln(p.w, " Domain:", r.RDAP.Domain)
		fmt.Fprintln(p.w, " Handle:", r.RDAP.Handle)
		for _, e := range r.RDAP.Events {
			fmt.Fprintf(p.w, " %s: %s\n", e.Action, e.Date)
		}
		if r.RDAP.Expired {
			fmt.Fprintln(p.w, p.style(styleError, " ⚠ Domain EXPIRED"))
		} else if r.RDAP.Warn30Days {
			fmt.Fprintln(p.w, p.style(styleWarn, " ⚠ Domain expires within 30 days"))
		}
		fmt.Fprintln(p.w)
	}

	if includeCore {
		p.printCoreRecords(r)
		fmt.Fprintln(p.w)
	}

	if r.IsSubdomain {
		p.header("Subdomain A/AAAA:")
		p.printIPResults(r.SubdomainIPs, false)
		fmt.Fprintln(p.w)
	}

	fmt.Fprintf(p.w, "%s\n\n", p.style(styleTitle, "DNS for "+p.hostname(r.Domain)))

	p.header("A record(s):")
	for _, ip := range r.ARecords {
		fmt.Fprintln(p.w, p.ipaddr(ip))
	}
	fmt.Fprintln(p.w)

	if r.SOA != nil {
		p.header("SOA:")
		fmt.Fprintf(p.w,
			" serial=%d tech=%s mname=%s\n refresh=%d retry=%d expire=%d minimum=%d\n\n",
			r.SOA.Serial, r.SOA.Mbox, r.SOA.NS,
			r.SOA.Refresh, r.SOA.Retry, r.SOA.Expire, r.SOA.Minimum,
		)
	}

	p.header("Nameservers:")
	for _, ns := range r.Nameservers {
		fmt.Fprintln(p.w, p.hostname(ns.Host))
		p.printIPResults(ns.IPs, false)
	}
	fmt.Fprintln(p.w)

	p.header("MX:")
	for _, mx := range r.MXRecords {
		fmt.Fprintf(p.w, " Host %s preference %d\n", p.hostname(mx.Host), mx.Preference)
		p.printIPResults(mx.IPs, true)
	}
	fmt.Fprintln(p.w)

	if len(r.TXTRecords) > 0 {
		p.header("TXT:")
		for _, v := range r.TXTRecords {
			fmt.Fprintln(p.w, p.txtval(v))
		}
		fmt.Fprintln(p.w)
	}

	if len(r.SPFRecords) > 0 {
		p.header("SPF:")
		for _, v := range r.SPFRecords {
			fmt.Fprintln(p.w, p.txtval(v))
		}
		fmt.Fprintln(p.w)
	}

	if len(r.DMARCRecords) > 0 {
		p.header("DMARC:")
		for _, v := range r.DMARCRecords {
			fmt.Fprintln(p.w, p.txtval(v))
		}
		fmt.Fprintln(p.w)
	}

	p.header("CAA:")
	if r.NoCAA {
		fmt.Fprintln(p.w, p.style(styleError, " There are no CAA records defined."))
	}
	for _, v := range r.CAARecords {
		fmt.Fprintln(p.w, p.txtval(v))
	}
}

func (p *Printer) printCoreRecords(r *model.Report) {
	p.header("Core Records:")
	fmt.Fprintln(p.w, " Domain:", p.hostname(r.Domain))
	p.printCoreList("Nameservers", p.renderNameserverLines(r), len(r.Nameservers))
	fmt.Fprintln(p.w, " A/AAAA:", p.renderARecords(r))
	p.printCoreList("MX", p.renderMXLines(r), len(r.MXRecords))
	fmt.Fprintln(p.w, " SPF:", p.healthStatus(len(r.SPFRecords) > 0))
	fmt.Fprintln(p.w, " DMARC:", p.healthStatus(len(r.DMARCRecords) > 0))
	fmt.Fprintln(p.w, " CAA:", p.healthStatus(len(r.CAARecords) > 0 && !r.NoCAA))
	p.printCoreList("TXT", p.renderTXTLines(r), len(r.TXTRecords)+len(r.SPFRecords)+len(r.DMARCRecords))
}

func (p *Printer) healthStatus(ok bool) string {
	if ok {
		return p.okLabel("OK")
	}
	return p.warnLabel("MISSING")
}

// printCoreList renders one labeled Core Records block. An empty list prints
// " label: (none)"; when total is 1 the single line prints inline as
// " label: line"; otherwise the lines print under the label, each indented.
// When total exceeds len(lines) the list was truncated and a
// "... (N total records)" summary is appended.
func (p *Printer) printCoreList(label string, lines []string, total int) {
	if len(lines) == 0 {
		fmt.Fprintf(p.w, " %s: (none)\n", label)
		return
	}
	if total <= 1 {
		fmt.Fprintf(p.w, " %s: %s\n", label, lines[0])
		return
	}
	fmt.Fprintf(p.w, " %s:\n", label)
	for _, line := range lines {
		fmt.Fprintf(p.w, "  %s\n", line)
	}
	if total > len(lines) {
		fmt.Fprintf(p.w, "  ... (%d total records)\n", total)
	}
}

func (p *Printer) renderNameserverLines(r *model.Report) []string {
	lines := make([]string, 0, len(r.Nameservers))
	for _, ns := range r.Nameservers {
		ips := make([]string, 0, len(ns.IPs))
		for _, ip := range ns.IPs {
			ips = append(ips, p.ipaddr(ip.IP))
		}
		if len(ips) == 0 {
			lines = append(lines, fmt.Sprintf("%s: (none)", p.hostname(ns.Host)))
			continue
		}
		lines = append(lines, fmt.Sprintf("%s: %s", p.hostname(ns.Host), strings.Join(ips, ", ")))
	}
	return lines
}

func (p *Printer) renderARecords(r *model.Report) string {
	if len(r.ARecords) == 0 {
		return "(none)"
	}
	parts := make([]string, 0, len(r.ARecords))
	for _, ip := range r.ARecords {
		parts = append(parts, p.ipaddr(ip))
	}
	return strings.Join(parts, ", ")
}

func (p *Printer) renderMXLines(r *model.Report) []string {
	lines := make([]string, 0, len(r.MXRecords))
	for _, mx := range r.MXRecords {
		lines = append(lines, fmt.Sprintf("%s (pref %d)", p.hostname(mx.Host), mx.Preference))
	}
	return lines
}

// renderTXTLines returns the combined TXT/SPF/DMARC values for the Core Records
// block, capped at 3 entries. The full count is tracked separately by the
// caller so printCoreList can note how many records were elided.
func (p *Printer) renderTXTLines(r *model.Report) []string {
	items := make([]string, 0, len(r.TXTRecords)+len(r.SPFRecords)+len(r.DMARCRecords))
	for _, txt := range r.TXTRecords {
		items = append(items, p.txtval(txt))
	}
	for _, spf := range r.SPFRecords {
		items = append(items, p.txtval(spf))
	}
	for _, dmarc := range r.DMARCRecords {
		items = append(items, p.txtval(dmarc))
	}
	if len(items) > 3 {
		items = items[:3]
	}
	return items
}

func (p *Printer) printIPResults(items []model.IPResult, withPTR bool) {
	for _, item := range items {
		fmt.Fprint(p.w, "  ", p.ipaddr(item.IP))
		if withPTR {
			for _, ptr := range item.PTR {
				fmt.Fprint(p.w, " PTR:", p.hostname(ptr))
			}
		}
		fmt.Fprintln(p.w)
	}
}

func PrintComparison(primaryResolver, secondaryResolver string, primary, secondary *model.Report) {
	p := NewPrinterWithTheme(os.Stdout, defaultUseColor, defaultThemeName)
	p.header("Resolver Comparison:")
	fmt.Fprintf(p.w, " Primary resolver: %s\n", primaryResolver)
	fmt.Fprintf(p.w, " Secondary resolver: %s\n", secondaryResolver)
	fmt.Fprintln(p.w, " Domain:", p.hostname(primary.Domain))
	fmt.Fprintln(p.w, " A/AAAA equal:", p.equalStatus(equalStringSets(primary.ARecords, secondary.ARecords)))
	fmt.Fprintln(p.w, " NS equal:", p.equalStatus(equalHostSets(primary.Nameservers, secondary.Nameservers)))
	fmt.Fprintln(p.w, " MX equal:", p.equalStatus(equalMXSets(primary.MXRecords, secondary.MXRecords)))
	fmt.Fprintln(p.w, " TXT equal:", p.equalStatus(equalStringSets(primary.TXTRecords, secondary.TXTRecords) && equalStringSets(primary.SPFRecords, secondary.SPFRecords) && equalStringSets(primary.DMARCRecords, secondary.DMARCRecords)))
	fmt.Fprintln(p.w)
}

func (p *Printer) equalStatus(equal bool) string {
	if equal {
		return p.okLabel("MATCH")
	}
	return p.warnLabel("DIFF")
}

func equalStringSets(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func equalHostSets(a, b []model.HostIPs) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Host != b[i].Host || len(a[i].IPs) != len(b[i].IPs) {
			return false
		}
		for j := range a[i].IPs {
			if a[i].IPs[j].IP != b[i].IPs[j].IP {
				return false
			}
		}
	}
	return true
}

func equalMXSets(a, b []model.MXHost) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Host != b[i].Host || a[i].Preference != b[i].Preference || len(a[i].IPs) != len(b[i].IPs) {
			return false
		}
		for j := range a[i].IPs {
			if a[i].IPs[j].IP != b[i].IPs[j].IP {
				return false
			}
		}
	}
	return true
}
