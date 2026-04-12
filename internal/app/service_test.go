package app

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"diggo/internal/model"

	"github.com/miekg/dns"
)

type dnsResponse struct {
	msg *dns.Msg
	err error
}

type fakeDNS struct {
	mu        sync.Mutex
	responses map[string]dnsResponse
	calls     []string
}

func (f *fakeDNS) Query(ctx context.Context, name string, qtype uint16) (*dns.Msg, error) {
	if err := ctxErr(ctx); err != nil {
		return nil, err
	}

	key := dnsKey(name, qtype)

	f.mu.Lock()
	f.calls = append(f.calls, key)
	resp, ok := f.responses[key]
	f.mu.Unlock()

	if !ok {
		return nil, fmt.Errorf("unexpected dns query: %s", key)
	}
	return resp.msg, resp.err
}

type fakeRDAP struct {
	result *model.RDAPInfo
	err    error
	delay  time.Duration
	calls  int
}

func (f *fakeRDAP) LookupDomain(ctx context.Context, _ string) (*model.RDAPInfo, error) {
	f.calls++
	if f.delay > 0 {
		select {
		case <-time.After(f.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if f.err != nil {
		return nil, f.err
	}
	return f.result, nil
}

func ctxErr(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	return ctx.Err()
}

func TestBuildReport_PopulatesExpectedFields(t *testing.T) {
	reverseMXIP, err := dns.ReverseAddr("4.4.4.4")
	if err != nil {
		t.Fatalf("failed to build reverse addr: %v", err)
	}

	dnsMock := &fakeDNS{responses: map[string]dnsResponse{
		dnsKey("mail.example.com", dns.TypeA): {
			msg: msgWithAnswers(&dns.A{A: net.ParseIP("2.2.2.2")}),
		},
		dnsKey("mail.example.com", dns.TypeAAAA): {
			msg: msgWithAnswers(),
		},
		dnsKey("example.com", dns.TypeA): {
			msg: msgWithAnswers(&dns.A{A: net.ParseIP("1.1.1.1")}),
		},
		dnsKey("example.com", dns.TypeSOA): {
			msg: msgWithAnswers(&dns.SOA{Serial: 123, Mbox: "tech.example.com.", Ns: "ns1.example.com.", Refresh: 10, Retry: 20, Expire: 30, Minttl: 40}),
		},
		dnsKey("example.com", dns.TypeNS): {
			msg: msgWithAnswers(&dns.NS{Ns: "ns1.example.com."}),
		},
		dnsKey("example.com", dns.TypeMX): {
			msg: msgWithAnswers(&dns.MX{Mx: "mx1.example.com.", Preference: 10}),
		},
		dnsKey("example.com", dns.TypeTXT): {
			msg: msgWithAnswers(
				&dns.TXT{Txt: []string{"v=spf1 include:_spf.example.com ~all"}},
				&dns.TXT{Txt: []string{"site-verification=abc123"}},
			),
		},
		dnsKey("_dmarc.example.com", dns.TypeTXT): {
			msg: msgWithAnswers(&dns.TXT{Txt: []string{"v=DMARC1; p=none"}}),
		},
		dnsKey("example.com", dns.TypeCAA): {
			msg: msgWithAnswers(&dns.CAA{Tag: "issue", Value: "letsencrypt.org"}),
		},
		dnsKey("ns1.example.com.", dns.TypeA): {
			msg: msgWithAnswers(&dns.A{A: net.ParseIP("3.3.3.3")}),
		},
		dnsKey("ns1.example.com.", dns.TypeAAAA): {
			msg: msgWithAnswers(),
		},
		dnsKey("mx1.example.com.", dns.TypeA): {
			msg: msgWithAnswers(&dns.A{A: net.ParseIP("4.4.4.4")}),
		},
		dnsKey("mx1.example.com.", dns.TypeAAAA): {
			msg: msgWithAnswers(),
		},
		dnsKey(reverseMXIP, dns.TypePTR): {
			msg: msgWithAnswers(&dns.PTR{Ptr: "ptr.mx1.example.com."}),
		},
	}}

	rdapMock := &fakeRDAP{result: &model.RDAPInfo{Domain: "example.com", Handle: "H-123"}}
	svc := NewService(dnsMock, rdapMock)

	report, err := svc.BuildReport(context.Background(), "mail.example.com", false)
	if err != nil {
		t.Fatalf("BuildReport returned error: %v", err)
	}

	if !report.IsSubdomain {
		t.Fatalf("expected input to be treated as subdomain")
	}
	if report.Domain != "example.com" {
		t.Fatalf("unexpected normalized domain: %s", report.Domain)
	}
	if rdapMock.calls != 1 {
		t.Fatalf("expected rdap lookup once, got %d", rdapMock.calls)
	}
	if report.RDAP == nil || report.RDAP.Domain != "example.com" {
		t.Fatalf("expected rdap result to be populated")
	}
	if len(report.SubdomainIPs) != 1 || report.SubdomainIPs[0].IP != "2.2.2.2" {
		t.Fatalf("unexpected subdomain IPs: %+v", report.SubdomainIPs)
	}
	if len(report.ARecords) != 1 || report.ARecords[0] != "1.1.1.1" {
		t.Fatalf("unexpected A records: %+v", report.ARecords)
	}
	if report.SOA == nil || report.SOA.Serial != 123 {
		t.Fatalf("unexpected SOA data: %+v", report.SOA)
	}
	if len(report.Nameservers) != 1 || report.Nameservers[0].Host != "ns1.example.com." {
		t.Fatalf("unexpected NS records: %+v", report.Nameservers)
	}
	if len(report.Nameservers[0].IPs) != 1 || report.Nameservers[0].IPs[0].IP != "3.3.3.3" {
		t.Fatalf("unexpected NS host IPs: %+v", report.Nameservers[0].IPs)
	}
	if len(report.MXRecords) != 1 || report.MXRecords[0].Host != "mx1.example.com." {
		t.Fatalf("unexpected MX records: %+v", report.MXRecords)
	}
	if len(report.MXRecords[0].IPs) != 1 || report.MXRecords[0].IPs[0].IP != "4.4.4.4" {
		t.Fatalf("unexpected MX host IPs: %+v", report.MXRecords[0].IPs)
	}
	if len(report.MXRecords[0].IPs[0].PTR) != 1 || report.MXRecords[0].IPs[0].PTR[0] != "ptr.mx1.example.com." {
		t.Fatalf("unexpected MX PTR records: %+v", report.MXRecords[0].IPs[0].PTR)
	}
	if len(report.SPFRecords) != 1 || len(report.DMARCRecords) != 1 || len(report.TXTRecords) != 1 {
		t.Fatalf("expected SPF/DMARC/TXT split, got spf=%d dmarc=%d txt=%d", len(report.SPFRecords), len(report.DMARCRecords), len(report.TXTRecords))
	}
	if report.NoCAA {
		t.Fatalf("expected NoCAA flag to be false when CAA records exist")
	}
	if len(report.CAARecords) != 1 {
		t.Fatalf("expected one CAA record, got %+v", report.CAARecords)
	}
}

func TestBuildReport_SkipsRDAPWhenDisabled(t *testing.T) {
	dnsMock := &fakeDNS{responses: map[string]dnsResponse{
		dnsKey("example.com", dns.TypeA):          {msg: msgWithAnswers()},
		dnsKey("example.com", dns.TypeSOA):        {msg: msgWithAnswers()},
		dnsKey("example.com", dns.TypeNS):         {msg: msgWithAnswers()},
		dnsKey("example.com", dns.TypeMX):         {msg: msgWithAnswers()},
		dnsKey("example.com", dns.TypeTXT):        {msg: msgWithAnswers()},
		dnsKey("_dmarc.example.com", dns.TypeTXT): {msg: msgWithAnswers()},
		dnsKey("example.com", dns.TypeCAA):        {msg: msgWithAnswers()},
	}}
	rdapMock := &fakeRDAP{}
	svc := NewService(dnsMock, rdapMock)

	report, err := svc.BuildReport(context.Background(), "example.com", true)
	if err != nil {
		t.Fatalf("BuildReport returned error: %v", err)
	}

	if rdapMock.calls != 0 {
		t.Fatalf("expected no rdap calls, got %d", rdapMock.calls)
	}
	if report.RDAP != nil || report.RDAPError {
		t.Fatalf("expected no rdap fields when disabled, got rdap=%+v err=%v", report.RDAP, report.RDAPError)
	}
}

func TestBuildReport_SetsRDAPErrorOnFailure(t *testing.T) {
	dnsMock := &fakeDNS{responses: map[string]dnsResponse{
		dnsKey("example.com", dns.TypeA):          {msg: msgWithAnswers()},
		dnsKey("example.com", dns.TypeSOA):        {msg: msgWithAnswers()},
		dnsKey("example.com", dns.TypeNS):         {msg: msgWithAnswers()},
		dnsKey("example.com", dns.TypeMX):         {msg: msgWithAnswers()},
		dnsKey("example.com", dns.TypeTXT):        {msg: msgWithAnswers()},
		dnsKey("_dmarc.example.com", dns.TypeTXT): {msg: msgWithAnswers()},
		dnsKey("example.com", dns.TypeCAA):        {msg: msgWithAnswers()},
	}}
	rdapMock := &fakeRDAP{err: errors.New("network down")}
	svc := NewService(dnsMock, rdapMock)

	report, err := svc.BuildReport(context.Background(), "example.com", false)
	if err != nil {
		t.Fatalf("BuildReport returned error: %v", err)
	}
	if !report.RDAPError {
		t.Fatalf("expected RDAPError=true on rdap failure")
	}
	if report.RDAP != nil {
		t.Fatalf("expected RDAP=nil on rdap failure")
	}
}

func TestBuildReport_ResolvesDNSBeforeSlowRDAP(t *testing.T) {
	dnsMock := &fakeDNS{responses: map[string]dnsResponse{
		dnsKey("example.com", dns.TypeA):          {msg: msgWithAnswers(&dns.A{A: net.ParseIP("1.1.1.1")})},
		dnsKey("example.com", dns.TypeSOA):        {msg: msgWithAnswers()},
		dnsKey("example.com", dns.TypeNS):         {msg: msgWithAnswers()},
		dnsKey("example.com", dns.TypeMX):         {msg: msgWithAnswers()},
		dnsKey("example.com", dns.TypeTXT):        {msg: msgWithAnswers(&dns.TXT{Txt: []string{"v=spf1 -all"}})},
		dnsKey("_dmarc.example.com", dns.TypeTXT): {msg: msgWithAnswers(&dns.TXT{Txt: []string{"v=DMARC1; p=none"}})},
		dnsKey("example.com", dns.TypeCAA):        {msg: msgWithAnswers()},
	}}
	rdapMock := &fakeRDAP{delay: 200 * time.Millisecond}
	svc := NewService(dnsMock, rdapMock)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	report, err := svc.BuildReport(ctx, "example.com", false)
	if err != nil {
		t.Fatalf("BuildReport returned error: %v", err)
	}

	if len(report.ARecords) != 1 || report.ARecords[0] != "1.1.1.1" {
		t.Fatalf("expected A records to be resolved before RDAP timeout, got %+v", report.ARecords)
	}
	if len(report.SPFRecords) != 1 {
		t.Fatalf("expected SPF record to be resolved before RDAP timeout, got %+v", report.SPFRecords)
	}
	if len(report.DMARCRecords) != 1 {
		t.Fatalf("expected DMARC record to be resolved before RDAP timeout, got %+v", report.DMARCRecords)
	}
	if !report.RDAPError {
		t.Fatalf("expected RDAPError=true when RDAP exceeds context deadline")
	}
}

func TestSplitDomain(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		want      string
		wantIsSub bool
	}{
		{name: "root domain", input: "example.com", want: "example.com", wantIsSub: false},
		{name: "subdomain", input: "mail.example.com", want: "example.com", wantIsSub: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotDomain, gotIsSub := splitDomain(tc.input)
			if gotDomain != tc.want || gotIsSub != tc.wantIsSub {
				t.Fatalf("splitDomain(%q) = (%q,%v), want (%q,%v)", tc.input, gotDomain, gotIsSub, tc.want, tc.wantIsSub)
			}
		})
	}
}

func TestBuildReport_NormalizesAndUsesDMARCSubdomainQuery(t *testing.T) {
	dnsMock := &fakeDNS{responses: map[string]dnsResponse{
		dnsKey("example.com", dns.TypeA): {
			msg: msgWithAnswers(
				&dns.A{A: net.ParseIP("2.2.2.2")},
				&dns.A{A: net.ParseIP("1.1.1.1")},
				&dns.A{A: net.ParseIP("2.2.2.2")},
			),
		},
		dnsKey("example.com", dns.TypeSOA): {msg: msgWithAnswers()},
		dnsKey("example.com", dns.TypeNS): {
			msg: msgWithAnswers(
				&dns.NS{Ns: "ns2.example.com."},
				&dns.NS{Ns: "ns1.example.com."},
			),
		},
		dnsKey("ns1.example.com.", dns.TypeA):    {msg: msgWithAnswers(&dns.A{A: net.ParseIP("3.3.3.3")})},
		dnsKey("ns1.example.com.", dns.TypeAAAA): {msg: msgWithAnswers()},
		dnsKey("ns2.example.com.", dns.TypeA):    {msg: msgWithAnswers(&dns.A{A: net.ParseIP("4.4.4.4")})},
		dnsKey("ns2.example.com.", dns.TypeAAAA): {msg: msgWithAnswers()},
		dnsKey("example.com", dns.TypeMX):        {msg: msgWithAnswers()},
		dnsKey("example.com", dns.TypeTXT): {
			msg: msgWithAnswers(
				&dns.TXT{Txt: []string{"z-last"}},
				&dns.TXT{Txt: []string{"a-first"}},
				&dns.TXT{Txt: []string{"a-first"}},
			),
		},
		dnsKey("_dmarc.example.com", dns.TypeTXT): {
			msg: msgWithAnswers(
				&dns.TXT{Txt: []string{"v=DMARC1; p=none"}},
				&dns.TXT{Txt: []string{"v=DMARC1; p=none"}},
			),
		},
		dnsKey("example.com", dns.TypeCAA): {msg: msgWithAnswers()},
	}}

	svc := NewService(dnsMock, &fakeRDAP{})
	report, err := svc.BuildReport(context.Background(), "example.com", true)
	if err != nil {
		t.Fatalf("BuildReport returned error: %v", err)
	}

	if len(report.ARecords) != 2 || report.ARecords[0] != "1.1.1.1" || report.ARecords[1] != "2.2.2.2" {
		t.Fatalf("expected sorted/deduped A records, got %+v", report.ARecords)
	}
	if len(report.TXTRecords) != 2 || report.TXTRecords[0] != "a-first" || report.TXTRecords[1] != "z-last" {
		t.Fatalf("expected sorted/deduped TXT records, got %+v", report.TXTRecords)
	}
	if len(report.DMARCRecords) != 1 || report.DMARCRecords[0] != "v=DMARC1; p=none" {
		t.Fatalf("expected deduped DMARC records, got %+v", report.DMARCRecords)
	}
	if len(report.Nameservers) != 2 || report.Nameservers[0].Host != "ns1.example.com." || report.Nameservers[1].Host != "ns2.example.com." {
		t.Fatalf("expected sorted nameservers, got %+v", report.Nameservers)
	}

	seenDMARC := false
	for _, call := range dnsMock.calls {
		if call == dnsKey("_dmarc.example.com", dns.TypeTXT) {
			seenDMARC = true
			break
		}
	}
	if !seenDMARC {
		t.Fatalf("expected explicit _dmarc.example.com TXT query")
	}
}

func msgWithAnswers(rr ...dns.RR) *dns.Msg {
	return &dns.Msg{Answer: rr}
}

func dnsKey(name string, qtype uint16) string {
	return fmt.Sprintf("%s|%d", name, qtype)
}
