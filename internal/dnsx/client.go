package dnsx

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/miekg/dns"
)

const (
	maxQueryAttempts = 3
	retryBaseDelay   = 120 * time.Millisecond
)

type Client struct {
	resolver  string
	PreferTCP bool
	udp       dns.Client
	tcp       dns.Client
	udpQuery  func(ctx context.Context, msg *dns.Msg, resolver string) (*dns.Msg, time.Duration, error)
	tcpQuery  func(ctx context.Context, msg *dns.Msg, resolver string) (*dns.Msg, time.Duration, error)
}

func NewClient(resolver string, timeout time.Duration) *Client {
	c := &Client{
		resolver: resolver,
		udp:      dns.Client{Net: "udp", Timeout: timeout},
		tcp:      dns.Client{Net: "tcp", Timeout: timeout},
	}
	c.udpQuery = c.udp.ExchangeContext
	c.tcpQuery = c.tcp.ExchangeContext
	return c
}

func (c *Client) Query(ctx context.Context, name string, qtype uint16) (*dns.Msg, error) {
	var lastErr error
	for attempt := 1; attempt <= maxQueryAttempts; attempt++ {
		msg := new(dns.Msg)
		msg.SetQuestion(dns.Fqdn(name), qtype)

		if c.PreferTCP {
			r, _, err := c.tcpQuery(ctx, msg, c.resolver)
			if err != nil {
				if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
					return nil, err
				}
				lastErr = err
				// TCP failed at transport level — fall through to UDP this attempt
			} else if r != nil {
				if shouldRetry(nil, r, attempt, ctx) {
					lastErr = fmt.Errorf("dns rcode: %s", dns.RcodeToString[r.Rcode])
					if waitErr := sleepWithContext(ctx, backoffDelay(attempt)); waitErr != nil {
						return nil, waitErr
					}
					continue
				}
				return r, nil
			}
			// TCP returned nil or transport error — fall through to UDP
		}

		r, _, err := c.udpQuery(ctx, msg, c.resolver)
		if err != nil {
			lastErr = err
			if !shouldRetry(err, nil, attempt, ctx) {
				return nil, err
			}
			if waitErr := sleepWithContext(ctx, backoffDelay(attempt)); waitErr != nil {
				return nil, waitErr
			}
			continue
		}

		if r == nil {
			lastErr = errors.New("dns query returned nil response")
			if !shouldRetry(lastErr, nil, attempt, ctx) {
				return nil, lastErr
			}
			if waitErr := sleepWithContext(ctx, backoffDelay(attempt)); waitErr != nil {
				return nil, waitErr
			}
			continue
		}

		if r.Truncated {
			tcpResp, err := c.retryTCP(ctx, msg)
			if err != nil {
				lastErr = err
				if !shouldRetry(err, nil, attempt, ctx) {
					return nil, err
				}
				if waitErr := sleepWithContext(ctx, backoffDelay(attempt)); waitErr != nil {
					return nil, waitErr
				}
				continue
			}
			if tcpResp == nil {
				lastErr = errors.New("dns tcp retry returned nil response")
				if !shouldRetry(lastErr, nil, attempt, ctx) {
					return nil, lastErr
				}
				if waitErr := sleepWithContext(ctx, backoffDelay(attempt)); waitErr != nil {
					return nil, waitErr
				}
				continue
			}
			if shouldRetry(nil, tcpResp, attempt, ctx) {
				if waitErr := sleepWithContext(ctx, backoffDelay(attempt)); waitErr != nil {
					return nil, waitErr
				}
				continue
			}
			return tcpResp, nil
		}

		if shouldRetry(nil, r, attempt, ctx) {
			if waitErr := sleepWithContext(ctx, backoffDelay(attempt)); waitErr != nil {
				return nil, waitErr
			}
			continue
		}
		return r, nil
	}

	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("dns query failed after retries: %s type=%d", name, qtype)
}

func (c *Client) retryTCP(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	r, _, err := c.tcpQuery(ctx, msg, c.resolver)
	if err != nil {
		return nil, err
	}
	return r, nil
}

func shouldRetry(err error, resp *dns.Msg, attempt int, ctx context.Context) bool {
	if attempt >= maxQueryAttempts {
		return false
	}
	if ctx != nil && ctx.Err() != nil {
		return false
	}
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return false
		}
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			return true
		}
		return true
	}
	if resp == nil {
		return true
	}
	return resp.Rcode == dns.RcodeServerFailure || resp.Rcode == dns.RcodeRefused
}

func backoffDelay(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	return time.Duration(attempt) * retryBaseDelay
}

func sleepWithContext(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
