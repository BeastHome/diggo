package output

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"diggo/internal/model"
)

func TestPrintReport_FullReportGolden(t *testing.T) {
	report := &model.Report{
		Domain:      "example.com",
		IsSubdomain: true,
		RDAP: &model.RDAPInfo{
			Domain:     "example.com",
			Handle:     "H-1",
			Warn30Days: true,
			Events: []model.RDAPEvent{
				{Action: "expiration", Date: "2030-01-01T00:00:00Z"},
			},
		},
		SubdomainIPs: []model.IPResult{{IP: "9.9.9.9"}},
		ARecords:     []string{"1.1.1.1"},
		SOA: &model.SOAInfo{
			Serial:  123,
			Mbox:    "tech.example.com.",
			NS:      "ns1.example.com.",
			Refresh: 10,
			Retry:   20,
			Expire:  30,
			Minimum: 40,
		},
		Nameservers: []model.HostIPs{{
			Host: "ns1.example.com.",
			IPs:  []model.IPResult{{IP: "2.2.2.2"}},
		}},
		MXRecords: []model.MXHost{{
			Host:       "mx1.example.com.",
			Preference: 10,
			IPs: []model.IPResult{{
				IP:  "3.3.3.3",
				PTR: []string{"ptr1.example.com.", "ptr2.example.com."},
			}},
		}},
		TXTRecords:   []string{"site-verification=abc123"},
		SPFRecords:   []string{"v=spf1 include:_spf.example.com ~all"},
		DMARCRecords: []string{"v=DMARC1; p=none"},
		CAARecords:   []string{"issue letsencrypt.org"},
	}

	got := capturePrintReport(t, report, false)
	assertGolden(t, "full_report.golden", got)
}

func TestPrintReport_FullReportColorGolden(t *testing.T) {
	report := &model.Report{
		Domain:      "example.com",
		IsSubdomain: true,
		RDAP: &model.RDAPInfo{
			Domain:     "example.com",
			Handle:     "H-1",
			Warn30Days: true,
			Events: []model.RDAPEvent{
				{Action: "expiration", Date: "2030-01-01T00:00:00Z"},
			},
		},
		SubdomainIPs: []model.IPResult{{IP: "9.9.9.9"}},
		ARecords:     []string{"1.1.1.1"},
		SOA: &model.SOAInfo{
			Serial:  123,
			Mbox:    "tech.example.com.",
			NS:      "ns1.example.com.",
			Refresh: 10,
			Retry:   20,
			Expire:  30,
			Minimum: 40,
		},
		Nameservers: []model.HostIPs{{
			Host: "ns1.example.com.",
			IPs:  []model.IPResult{{IP: "2.2.2.2"}},
		}},
		MXRecords: []model.MXHost{{
			Host:       "mx1.example.com.",
			Preference: 10,
			IPs: []model.IPResult{{
				IP:  "3.3.3.3",
				PTR: []string{"ptr1.example.com.", "ptr2.example.com."},
			}},
		}},
		TXTRecords:   []string{"site-verification=abc123"},
		SPFRecords:   []string{"v=spf1 include:_spf.example.com ~all"},
		DMARCRecords: []string{"v=DMARC1; p=none"},
		CAARecords:   []string{"issue letsencrypt.org"},
	}

	got := capturePrintReport(t, report, true)
	assertGoldenEscaped(t, "full_report_color.golden", got)
}

func TestPrintReport_RDAPErrorGolden(t *testing.T) {
	report := &model.Report{
		Domain:    "example.com",
		RDAPError: true,
		NoCAA:     true,
	}

	got := capturePrintReport(t, report, false)
	assertGolden(t, "rdap_error.golden", got)
}

func TestPrintReport_CoreNameserversStacked(t *testing.T) {
	report := &model.Report{
		Domain: "example.com",
		Nameservers: []model.HostIPs{
			{Host: "ns1.example.com."},
			{Host: "ns2.example.com."},
		},
	}

	got := capturePrintReport(t, report, false)
	if !strings.Contains(got, " Nameservers:\n  ns1.example.com.: (none)\n  ns2.example.com.: (none)") {
		t.Fatalf("expected stacked nameserver lines in core block, got:\n%s", got)
	}
}

func TestPrintReport_CoreNameserverIPsStacked(t *testing.T) {
	report := &model.Report{
		Domain: "example.com",
		Nameservers: []model.HostIPs{
			{Host: "ns1.example.com.", IPs: []model.IPResult{{IP: "1.1.1.1"}}},
			{Host: "ns2.example.com.", IPs: []model.IPResult{{IP: "2.2.2.2"}}},
		},
	}

	got := capturePrintReport(t, report, false)
	if !strings.Contains(got, " Nameservers:\n  ns1.example.com.: 1.1.1.1\n  ns2.example.com.: 2.2.2.2") {
		t.Fatalf("expected stacked nameserver IP mappings in core block, got:\n%s", got)
	}
}

func TestPrintReport_CoreMXStackedWhenMultiple(t *testing.T) {
	report := &model.Report{
		Domain: "example.com",
		MXRecords: []model.MXHost{
			{Host: "mx1.example.com.", Preference: 10},
			{Host: "mx2.example.com.", Preference: 20},
		},
	}

	got := capturePrintReport(t, report, false)
	if !strings.Contains(got, " MX:\n  mx1.example.com. (pref 10)\n  mx2.example.com. (pref 20)") {
		t.Fatalf("expected stacked MX lines in core block, got:\n%s", got)
	}
}

func capturePrintReport(t *testing.T, report *model.Report, withColor bool) string {
	t.Helper()

	var buf bytes.Buffer
	printer := NewPrinter(&buf, withColor)
	printer.PrintFull(report)

	return buf.String()
}

func assertGolden(t *testing.T, fileName, got string) {
	t.Helper()
	goldenPath := filepath.Join("testdata", fileName)
	wantBytes, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("failed to read golden file %s: %v", goldenPath, err)
	}
	want := string(wantBytes)

	if normalizeOutput(got) != normalizeOutput(want) {
		t.Fatalf("golden mismatch for %s\n--- want ---\n%s\n--- got ---\n%s", goldenPath, want, got)
	}
}

func assertGoldenEscaped(t *testing.T, fileName, got string) {
	t.Helper()
	goldenPath := filepath.Join("testdata", fileName)
	wantBytes, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("failed to read golden file %s: %v", goldenPath, err)
	}
	want := string(wantBytes)
	gotEscaped := escapeANSI(got)

	if normalizeOutput(gotEscaped) != normalizeOutput(want) {
		t.Fatalf("golden mismatch for %s\n--- want ---\n%s\n--- got ---\n%s", goldenPath, want, gotEscaped)
	}
}

func normalizeOutput(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	return strings.TrimRight(s, "\n")
}

func escapeANSI(s string) string {
	return strings.ReplaceAll(s, "\x1b", "<ESC>")
}
