package dnsx

import (
	"context"
	"time"

	"github.com/miekg/dns"
)

type Client struct {
	resolver string
	udp      dns.Client
	tcp      dns.Client
}

func NewClient(resolver string, timeout time.Duration) *Client {
	return &Client{
		resolver: resolver,
		udp:      dns.Client{Net: "udp", Timeout: timeout},
		tcp:      dns.Client{Net: "tcp", Timeout: timeout},
	}
}

func (c *Client) Query(ctx context.Context, name string, qtype uint16) (*dns.Msg, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)

	r, _, err := c.udp.ExchangeContext(ctx, m, c.resolver)
	if err != nil {
		return nil, err
	}
	if r != nil && r.Truncated {
		return c.retryTCP(ctx, m)
	}
	return r, nil
}

func (c *Client) retryTCP(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	r, _, err := c.tcp.ExchangeContext(ctx, msg, c.resolver)
	if err != nil {
		return nil, err
	}
	return r, nil
}
