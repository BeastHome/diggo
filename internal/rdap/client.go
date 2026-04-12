package rdap

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"diggo/internal/model"
)

const defaultBaseURL = "https://rdap.org"

type Client struct {
	httpClient *http.Client
	baseURL    string
}

type rdapEvent struct {
	Action string `json:"eventAction"`
	Date   string `json:"eventDate"`
}

type rdapResp struct {
	LDHName string      `json:"ldhName"`
	Handle  string      `json:"handle"`
	Events  []rdapEvent `json:"events"`
}

func NewClient(timeout time.Duration) *Client {
	return &Client{
		httpClient: &http.Client{Timeout: timeout},
		baseURL:    defaultBaseURL,
	}
}

func (c *Client) LookupDomain(ctx context.Context, domain string) (*model.RDAPInfo, error) {
	url := fmt.Sprintf("%s/domain/%s", c.baseURL, domain)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("rdap lookup failed: status %d", resp.StatusCode)
	}

	var payload rdapResp
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, err
	}

	out := &model.RDAPInfo{
		Domain: payload.LDHName,
		Handle: payload.Handle,
		Events: make([]model.RDAPEvent, 0, len(payload.Events)),
	}

	for _, ev := range payload.Events {
		out.Events = append(out.Events, model.RDAPEvent{Action: ev.Action, Date: ev.Date})
		if ev.Action != "expiration" {
			continue
		}
		t, err := time.Parse(time.RFC3339, ev.Date)
		if err != nil {
			continue
		}
		until := time.Until(t)
		if until < 0 {
			out.Expired = true
			continue
		}
		if until < 30*24*time.Hour {
			out.Warn30Days = true
		}
	}

	return out, nil
}
