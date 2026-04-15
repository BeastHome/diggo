package dnsx

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestClientQuery_RetriesOnServerFailureThenSucceeds(t *testing.T) {
	client := NewClient("1.1.1.1:53", time.Second)
	var calls int
	client.udpQuery = func(_ context.Context, _ *dns.Msg, _ string) (*dns.Msg, time.Duration, error) {
		calls++
		if calls < 3 {
			return &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeServerFailure}}, 0, nil
		}
		return &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess}}, 0, nil
	}

	resp, err := client.Query(context.Background(), "example.com", dns.TypeTXT)
	if err != nil {
		t.Fatalf("Query returned error: %v", err)
	}
	if calls != 3 {
		t.Fatalf("expected 3 attempts, got %d", calls)
	}
	if resp == nil || resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("expected successful response after retries, got %+v", resp)
	}
}

func TestClientQuery_DoesNotRetryOnNXDomain(t *testing.T) {
	client := NewClient("1.1.1.1:53", time.Second)
	var calls int
	client.udpQuery = func(_ context.Context, _ *dns.Msg, _ string) (*dns.Msg, time.Duration, error) {
		calls++
		return &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeNameError}}, 0, nil
	}

	resp, err := client.Query(context.Background(), "nope.example", dns.TypeA)
	if err != nil {
		t.Fatalf("Query returned error: %v", err)
	}
	if calls != 1 {
		t.Fatalf("expected 1 attempt for NXDOMAIN, got %d", calls)
	}
	if resp == nil || resp.Rcode != dns.RcodeNameError {
		t.Fatalf("expected NXDOMAIN response, got %+v", resp)
	}
}

func TestClientQuery_RetriesOnTransportErrorThenSucceeds(t *testing.T) {
	client := NewClient("1.1.1.1:53", time.Second)
	var calls int
	client.udpQuery = func(_ context.Context, _ *dns.Msg, _ string) (*dns.Msg, time.Duration, error) {
		calls++
		if calls < 3 {
			return nil, 0, errors.New("temporary transport error")
		}
		return &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess}}, 0, nil
	}

	resp, err := client.Query(context.Background(), "example.com", dns.TypeA)
	if err != nil {
		t.Fatalf("Query returned error: %v", err)
	}
	if calls != 3 {
		t.Fatalf("expected 3 attempts, got %d", calls)
	}
	if resp == nil || resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("expected success response, got %+v", resp)
	}
}

func TestClientQuery_UsesTCPWhenUDPTruncated(t *testing.T) {
	client := NewClient("1.1.1.1:53", time.Second)
	var udpCalls, tcpCalls int
	client.udpQuery = func(_ context.Context, _ *dns.Msg, _ string) (*dns.Msg, time.Duration, error) {
		udpCalls++
		return &dns.Msg{MsgHdr: dns.MsgHdr{Truncated: true}}, 0, nil
	}
	client.tcpQuery = func(_ context.Context, _ *dns.Msg, _ string) (*dns.Msg, time.Duration, error) {
		tcpCalls++
		return &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess}}, 0, nil
	}

	resp, err := client.Query(context.Background(), "example.com", dns.TypeMX)
	if err != nil {
		t.Fatalf("Query returned error: %v", err)
	}
	if udpCalls != 1 || tcpCalls != 1 {
		t.Fatalf("expected one UDP and one TCP call, got udp=%d tcp=%d", udpCalls, tcpCalls)
	}
	if resp == nil || resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("expected successful TCP response, got %+v", resp)
	}
}

func TestClientQuery_PreferTCPSucceedsWithoutUDP(t *testing.T) {
	client := NewClient("1.1.1.1:53", time.Second)
	client.PreferTCP = true
	var udpCalls, tcpCalls int
	client.udpQuery = func(_ context.Context, _ *dns.Msg, _ string) (*dns.Msg, time.Duration, error) {
		udpCalls++
		return &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess}}, 0, nil
	}
	client.tcpQuery = func(_ context.Context, _ *dns.Msg, _ string) (*dns.Msg, time.Duration, error) {
		tcpCalls++
		return &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess}}, 0, nil
	}

	resp, err := client.Query(context.Background(), "example.com", dns.TypeA)
	if err != nil {
		t.Fatalf("Query returned error: %v", err)
	}
	if tcpCalls != 1 {
		t.Fatalf("expected exactly 1 TCP call, got %d", tcpCalls)
	}
	if udpCalls != 0 {
		t.Fatalf("expected 0 UDP calls when TCP succeeded, got %d", udpCalls)
	}
	if resp == nil || resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("expected successful response, got %+v", resp)
	}
}

func TestClientQuery_PreferTCPFallsBackToUDPOnTransportError(t *testing.T) {
	client := NewClient("1.1.1.1:53", time.Second)
	client.PreferTCP = true
	var udpCalls, tcpCalls int
	client.tcpQuery = func(_ context.Context, _ *dns.Msg, _ string) (*dns.Msg, time.Duration, error) {
		tcpCalls++
		return nil, 0, errors.New("tcp: connection refused")
	}
	client.udpQuery = func(_ context.Context, _ *dns.Msg, _ string) (*dns.Msg, time.Duration, error) {
		udpCalls++
		return &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess}}, 0, nil
	}

	resp, err := client.Query(context.Background(), "example.com", dns.TypeA)
	if err != nil {
		t.Fatalf("Query returned error: %v", err)
	}
	if udpCalls == 0 {
		t.Fatalf("expected UDP fallback when TCP transport fails")
	}
	if resp == nil || resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("expected successful UDP response, got %+v", resp)
	}
}
