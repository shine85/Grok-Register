package cpa

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type ManagementConfig struct {
	BaseURL string
	Key     string
	Timeout time.Duration
}

type DeviceAuth struct {
	URL      string
	State    string
	UserCode string
}

type ManagementClient struct {
	baseURL string
	key     string
	client  *http.Client
}

func NewManagementClient(cfg ManagementConfig) *ManagementClient {
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return &ManagementClient{
		baseURL: NormalizeManagementBase(cfg.BaseURL),
		key:     strings.TrimSpace(cfg.Key),
		client: &http.Client{
			Timeout:   timeout,
			Transport: &http.Transport{Proxy: nil},
		},
	}
}

func (c *ManagementClient) Enabled() bool {
	return c != nil && c.baseURL != "" && c.key != ""
}

func (c *ManagementClient) StartXAIAuth(ctx context.Context) (DeviceAuth, error) {
	var response struct {
		Status string `json:"status"`
		URL    string `json:"url"`
		State  string `json:"state"`
		Error  string `json:"error"`
	}
	if err := c.getJSON(ctx, "/xai-auth-url", nil, &response); err != nil {
		return DeviceAuth{}, err
	}
	if response.Status != "ok" {
		return DeviceAuth{}, fmt.Errorf("CPA xAI auth start failed: %s", responseError(response.Error, response.Status))
	}
	authURL := strings.TrimSpace(response.URL)
	state := strings.TrimSpace(response.State)
	if authURL == "" || state == "" {
		return DeviceAuth{}, fmt.Errorf("CPA xAI auth start returned incomplete response")
	}
	parsed, err := url.Parse(authURL)
	if err != nil {
		return DeviceAuth{}, fmt.Errorf("parse CPA verification URL: %w", err)
	}
	userCode := strings.TrimSpace(parsed.Query().Get("user_code"))
	if userCode == "" {
		return DeviceAuth{}, fmt.Errorf("CPA verification URL missing user_code")
	}
	return DeviceAuth{URL: authURL, State: state, UserCode: userCode}, nil
}

func (c *ManagementClient) WaitAuth(ctx context.Context, state string, interval, timeout time.Duration) error {
	state = strings.TrimSpace(state)
	if state == "" {
		return fmt.Errorf("CPA auth state is empty")
	}
	if interval <= 0 {
		interval = 2 * time.Second
	}
	if timeout <= 0 {
		timeout = 10 * time.Minute
	}
	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	for {
		var response struct {
			Status string `json:"status"`
			Error  string `json:"error"`
		}
		query := url.Values{"state": {state}}
		if err := c.getJSON(waitCtx, "/get-auth-status", query, &response); err != nil {
			return err
		}
		switch strings.ToLower(strings.TrimSpace(response.Status)) {
		case "ok":
			return nil
		case "error":
			return fmt.Errorf("CPA xAI auth failed: %s", responseError(response.Error, response.Status))
		case "wait", "":
		default:
			return fmt.Errorf("CPA xAI auth returned unknown status %q", response.Status)
		}

		timer := time.NewTimer(interval)
		select {
		case <-waitCtx.Done():
			timer.Stop()
			return fmt.Errorf("wait for CPA xAI auth: %w", waitCtx.Err())
		case <-timer.C:
		}
	}
}

func (c *ManagementClient) getJSON(ctx context.Context, path string, query url.Values, dst any) error {
	if !c.Enabled() {
		return fmt.Errorf("CPA management client is not configured")
	}
	endpoint := strings.TrimRight(c.baseURL, "/") + path
	if len(query) > 0 {
		endpoint += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.key)
	req.Header.Set("X-Management-Key", c.key)
	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("CPA management request %s: %w", path, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("read CPA management response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("CPA management request %s status=%d body=%q", path, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	if err := json.Unmarshal(body, dst); err != nil {
		return fmt.Errorf("decode CPA management response %s: %w", path, err)
	}
	return nil
}

func responseError(message, status string) string {
	if message = strings.TrimSpace(message); message != "" {
		return message
	}
	if status = strings.TrimSpace(status); status != "" {
		return status
	}
	return "unknown error"
}
