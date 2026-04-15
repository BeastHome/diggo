package app

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"diggo/internal/model"

	"github.com/miekg/dns"
)

type DNSResolver interface {
	Query(ctx context.Context, name string, qtype uint16) (*dns.Msg, error)
}

type RDAPResolver interface {
	LookupDomain(ctx context.Context, domain string) (*model.RDAPInfo, error)
}

type Service struct {
	dns  DNSResolver
	rdap RDAPResolver
}

func NewService(dnsClient DNSResolver, rdapClient RDAPResolver) *Service {
	return &Service{dns: dnsClient, rdap: rdapClient}
}

func (s *Service) BuildReport(ctx context.Context, input string, noRDAP bool) (*model.Report, error) {
	domain, isSub := splitDomain(input)
	r := &model.Report{
		InputDomain: input,
		Domain:      domain,
		IsSubdomain: isSub,
		GeneratedAt: time.Now(),
	}

	if isSub {
		r.SubdomainIPs = s.lookupHostIPs(ctx, input, false)
	}

	s.fetchDomainRecords(ctx, r)

	if !noRDAP {
		rdapInfo, err := s.rdap.LookupDomain(ctx, domain)
		if err != nil {
			r.RDAPError = true
		} else {
			r.RDAP = rdapInfo
		}
	}

	s.normalizeReport(r)
	return r, nil
}

func (s *Service) fetchDomainRecords(ctx context.Context, r *model.Report) {
	type result struct {
		kind string
		msg  *dns.Msg
		err  error
	}

	queries := []struct {
		kind  string
		name  string
		qtype uint16
	}{
		{kind: "a", name: r.Domain, qtype: dns.TypeA},
		{kind: "soa", name: r.Domain, qtype: dns.TypeSOA},
		{kind: "ns", name: r.Domain, qtype: dns.TypeNS},
		{kind: "mx", name: r.Domain, qtype: dns.TypeMX},
		{kind: "txt", name: r.Domain, qtype: dns.TypeTXT},
		{kind: "dmarc", name: "_dmarc." + r.Domain, qtype: dns.TypeTXT},
		{kind: "caa", name: r.Domain, qtype: dns.TypeCAA},
	}

	const maxConcurrentDNS = 3

	ch := make(chan result, len(queries))
	sem := make(chan struct{}, maxConcurrentDNS)
	var wg sync.WaitGroup

	for _, q := range queries {
		q := q
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			msg, err := s.dns.Query(ctx, q.name, q.qtype)
			<-sem
			ch <- result{kind: q.kind, msg: msg, err: err}
		}()
	}

	wg.Wait()
	close(ch)

	for item := range ch {
		if item.err != nil || item.msg == nil {
			continue
		}
		s.consume(ctx, item.kind, item.msg, r)
	}
}

func (s *Service) consume(ctx context.Context, kind string, msg *dns.Msg, r *model.Report) {
	switch kind {
	case "a":
		for _, answer := range msg.Answer {
			if v, ok := answer.(*dns.A); ok {
				r.ARecords = append(r.ARecords, v.A.String())
			}
		}
	case "soa":
		for _, answer := range msg.Answer {
			if v, ok := answer.(*dns.SOA); ok {
				r.SOA = &model.SOAInfo{
					Serial:  v.Serial,
					Mbox:    v.Mbox,
					NS:      v.Ns,
					Refresh: v.Refresh,
					Retry:   v.Retry,
					Expire:  v.Expire,
					Minimum: v.Minttl,
				}
				break
			}
		}
	case "ns":
		for _, answer := range msg.Answer {
			if v, ok := answer.(*dns.NS); ok {
				r.Nameservers = append(r.Nameservers, model.HostIPs{
					Host: v.Ns,
					IPs:  s.lookupHostIPs(ctx, v.Ns, false),
				})
			}
		}
	case "mx":
		for _, answer := range msg.Answer {
			if v, ok := answer.(*dns.MX); ok {
				r.MXRecords = append(r.MXRecords, model.MXHost{
					Host:       v.Mx,
					Preference: v.Preference,
					IPs:        s.lookupHostIPs(ctx, v.Mx, true),
				})
			}
		}
	case "txt":
		for _, answer := range msg.Answer {
			if v, ok := answer.(*dns.TXT); ok {
				joined := strings.Join(v.Txt, " ")
				switch {
				case strings.HasPrefix(joined, "v=spf1"):
					r.SPFRecords = append(r.SPFRecords, joined)
				default:
					r.TXTRecords = append(r.TXTRecords, joined)
				}
			}
		}
	case "dmarc":
		for _, answer := range msg.Answer {
			if v, ok := answer.(*dns.TXT); ok {
				joined := strings.Join(v.Txt, " ")
				if strings.HasPrefix(joined, "v=DMARC1") {
					r.DMARCRecords = append(r.DMARCRecords, joined)
				}
			}
		}
	case "caa":
		if len(msg.Answer) == 0 {
			r.NoCAA = true
			return
		}
		for _, answer := range msg.Answer {
			if v, ok := answer.(*dns.CAA); ok {
				r.CAARecords = append(r.CAARecords, fmt.Sprintf("%s %s", v.Tag, v.Value))
			}
		}
	}
}

func (s *Service) lookupHostIPs(ctx context.Context, host string, withPTR bool) []model.IPResult {
	results := make([]model.IPResult, 0)
	for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
		msg, err := s.dns.Query(ctx, host, qtype)
		if err != nil || msg == nil {
			continue
		}
		for _, answer := range msg.Answer {
			switch v := answer.(type) {
			case *dns.A:
				ip := v.A.String()
				item := model.IPResult{IP: ip}
				if withPTR {
					item.PTR = s.lookupPTR(ctx, ip)
				}
				results = append(results, item)
			case *dns.AAAA:
				ip := v.AAAA.String()
				item := model.IPResult{IP: ip}
				if withPTR {
					item.PTR = s.lookupPTR(ctx, ip)
				}
				results = append(results, item)
			}
		}
	}
	return results
}

func (s *Service) lookupPTR(ctx context.Context, ip string) []string {
	ptrName, err := dns.ReverseAddr(ip)
	if err != nil {
		return nil
	}
	msg, err := s.dns.Query(ctx, ptrName, dns.TypePTR)
	if err != nil || msg == nil {
		return nil
	}
	ptrs := make([]string, 0)
	for _, answer := range msg.Answer {
		if v, ok := answer.(*dns.PTR); ok {
			ptrs = append(ptrs, v.Ptr)
		}
	}
	return ptrs
}

func splitDomain(name string) (string, bool) {
	parts := strings.Split(name, ".")
	if len(parts) <= 2 {
		return name, false
	}
	return strings.Join(parts[len(parts)-2:], "."), true
}

func (s *Service) normalizeReport(r *model.Report) {
	r.ARecords = sortAndDedupeStrings(r.ARecords)
	r.TXTRecords = sortAndDedupeStrings(r.TXTRecords)
	r.SPFRecords = sortAndDedupeStrings(r.SPFRecords)
	r.DMARCRecords = sortAndDedupeStrings(r.DMARCRecords)
	r.CAARecords = sortAndDedupeStrings(r.CAARecords)
	r.SubdomainIPs = normalizeIPResults(r.SubdomainIPs)

	for i := range r.Nameservers {
		r.Nameservers[i].IPs = normalizeIPResults(r.Nameservers[i].IPs)
	}
	sort.Slice(r.Nameservers, func(i, j int) bool {
		return r.Nameservers[i].Host < r.Nameservers[j].Host
	})
	r.Nameservers = dedupeHostIPs(r.Nameservers)

	for i := range r.MXRecords {
		r.MXRecords[i].IPs = normalizeIPResults(r.MXRecords[i].IPs)
	}
	sort.Slice(r.MXRecords, func(i, j int) bool {
		if r.MXRecords[i].Preference == r.MXRecords[j].Preference {
			return r.MXRecords[i].Host < r.MXRecords[j].Host
		}
		return r.MXRecords[i].Preference < r.MXRecords[j].Preference
	})
	r.MXRecords = dedupeMX(r.MXRecords)
}

func sortAndDedupeStrings(items []string) []string {
	if len(items) == 0 {
		return items
	}
	sorted := append([]string(nil), items...)
	sort.Strings(sorted)
	out := sorted[:1]
	for i := 1; i < len(sorted); i++ {
		if sorted[i] != sorted[i-1] {
			out = append(out, sorted[i])
		}
	}
	return out
}

func normalizeIPResults(items []model.IPResult) []model.IPResult {
	if len(items) == 0 {
		return items
	}
	norm := make([]model.IPResult, 0, len(items))
	for _, item := range items {
		item.PTR = sortAndDedupeStrings(item.PTR)
		norm = append(norm, item)
	}
	sort.Slice(norm, func(i, j int) bool { return norm[i].IP < norm[j].IP })
	out := norm[:1]
	for i := 1; i < len(norm); i++ {
		if norm[i].IP == norm[i-1].IP && strings.Join(norm[i].PTR, "|") == strings.Join(norm[i-1].PTR, "|") {
			continue
		}
		out = append(out, norm[i])
	}
	return out
}

func dedupeHostIPs(items []model.HostIPs) []model.HostIPs {
	if len(items) == 0 {
		return items
	}
	out := items[:1]
	for i := 1; i < len(items); i++ {
		prev := out[len(out)-1]
		curr := items[i]
		if curr.Host == prev.Host {
			merged := append(prev.IPs, curr.IPs...)
			out[len(out)-1].IPs = normalizeIPResults(merged)
			continue
		}
		out = append(out, curr)
	}
	return out
}

func dedupeMX(items []model.MXHost) []model.MXHost {
	if len(items) == 0 {
		return items
	}
	out := items[:1]
	for i := 1; i < len(items); i++ {
		prev := out[len(out)-1]
		curr := items[i]
		if curr.Host == prev.Host && curr.Preference == prev.Preference {
			merged := append(prev.IPs, curr.IPs...)
			out[len(out)-1].IPs = normalizeIPResults(merged)
			continue
		}
		out = append(out, curr)
	}
	return out
}
