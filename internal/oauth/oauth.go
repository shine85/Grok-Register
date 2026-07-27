package oauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"sync"
	"time"

	http "github.com/bogdanfinn/fhttp"
	tls_client "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"

	"github.com/grok-free-register/grok-reg/internal/clearance"
)

// ErrRateLimited is returned when auth.x.ai redirects with error=rate_limited.
var ErrRateLimited = errors.New("rate_limited")

const (
	DiscoveryURL = "https://auth.x.ai/.well-known/openid-configuration"
	ClientID     = "b1a00492-073a-47ea-816f-4c329264a828"
	Scope        = "openid profile email offline_access grok-cli:access api:access"
	VerifyURL    = "https://auth.x.ai/oauth2/device/verify"
	ApproveURL   = "https://auth.x.ai/oauth2/device/approve"
	// accounts.x.ai mirrors (current browser device UX hosts here)
	VerifyURLAccounts  = "https://accounts.x.ai/oauth2/device/verify"
	ApproveURLAccounts = "https://accounts.x.ai/oauth2/device/approve"
	DefaultUA    = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36"
)

type DeviceFlow struct {
	DeviceCode      string
	UserCode        string
	VerificationURL string
	ExpiresIn       int
	Interval        float64
	TokenEndpoint   string
}

type Credential struct {
	AccessToken   string
	RefreshToken  string
	IDToken       string
	TokenType     string
	ExpiresIn     int
	ExpiresAt     string
	LastRefresh   string
	Subject       string
	TokenEndpoint string
	Email         string
}

type Client struct {
	http  tls_client.HttpClient
	ua    string
	clear *clearance.Manager
	logf  func(string, ...any)

	// rate limit gate
	mu         sync.Mutex
	trippedAt  time.Time
	nextProbe  time.Time
	cooldown   time.Duration
	baseCool   time.Duration
	trips      int
	probeToken int
	probeSeq   int

	// OIDC discovery cache (device + token endpoints)
	discMu   sync.Mutex
	deviceEP string
	tokenEP  string
	discAt   time.Time
}

func NewClient(proxy string, cm *clearance.Manager, baseCooldown time.Duration) (*Client, error) {
	if baseCooldown <= 0 {
		baseCooldown = 60 * time.Second
	}
	// Chrome TLS impersonation — plain net/http was enough to start device
	// flow, but accounts.x.ai verify/approve often accepted the POST shape
	// without actually binding consent (authorization_pending forever).
	jar := tls_client.NewCookieJar()
	opts := []tls_client.HttpClientOption{
		tls_client.WithTimeoutSeconds(25),
		tls_client.WithClientProfile(profiles.Chrome_131),
		tls_client.WithRandomTLSExtensionOrder(),
		tls_client.WithCookieJar(jar),
		// Manual redirect control — ConfirmHTTP follows hops and merges cookies.
		tls_client.WithNotFollowRedirects(),
	}
	if strings.TrimSpace(proxy) != "" {
		opts = append(opts, tls_client.WithProxyUrl(strings.TrimSpace(proxy)))
	}
	cli, err := tls_client.NewHttpClient(tls_client.NewNoopLogger(), opts...)
	if err != nil {
		return nil, err
	}
	c := &Client{
		http:     cli,
		ua:       DefaultUA,
		clear:    cm,
		baseCool: baseCooldown,
		cooldown: baseCooldown,
	}
	if cm != nil {
		c.ua = cm.UserAgent()
	}
	return c, nil
}

// SetLogger attaches optional progress logs (e.g. pipeline logx).
func (c *Client) SetLogger(fn func(string, ...any)) {
	if c == nil {
		return
	}
	c.logf = fn
}

func (c *Client) log(format string, args ...any) {
	if c == nil || c.logf == nil {
		return
	}
	c.logf(format, args...)
}

func (c *Client) WaitRateLimit(ctx context.Context) error {
	for {
		c.mu.Lock()
		if c.trippedAt.IsZero() {
			c.mu.Unlock()
			return nil
		}
		now := time.Now()
		if now.Before(c.nextProbe) {
			wait := time.Until(c.nextProbe)
			c.mu.Unlock()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(wait):
				continue
			}
		}
		// allow one probe
		c.probeSeq++
		c.probeToken = c.probeSeq
		c.mu.Unlock()
		return nil
	}
}

func (c *Client) TripRateLimit() {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	if c.trippedAt.IsZero() {
		c.trippedAt = now
		c.trips = 1
	} else {
		c.trips++
	}
	// growth 1.5^n capped 300s
	cool := float64(c.baseCool) * pow15(c.trips-1)
	if cool > float64(300*time.Second) {
		cool = float64(300 * time.Second)
	}
	c.cooldown = time.Duration(cool)
	c.nextProbe = now.Add(c.cooldown)
}

func (c *Client) ClearRateLimit() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.trippedAt = time.Time{}
	c.nextProbe = time.Time{}
	c.trips = 0
	c.cooldown = c.baseCool
}

func pow15(n int) float64 {
	v := 1.0
	for i := 0; i < n; i++ {
		v *= 1.5
	}
	return v
}

func (c *Client) StartDeviceFlow(ctx context.Context) (DeviceFlow, error) {
	devEP, tokEP, err := c.discover(ctx)
	if err != nil {
		return DeviceFlow{}, err
	}
	form := url.Values{}
	form.Set("client_id", ClientID)
	form.Set("scope", Scope)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, devEP, strings.NewReader(form.Encode()))
	if err != nil {
		return DeviceFlow{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", c.ua)
	resp, err := c.http.Do(req)
	if err != nil {
		return DeviceFlow{}, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode/100 != 2 {
		if resp.StatusCode == 429 {
			c.TripRateLimit()
			return DeviceFlow{}, fmt.Errorf("%w: device authorization status=429", ErrRateLimited)
		}
		return DeviceFlow{}, fmt.Errorf("device authorization rejected status=%d", resp.StatusCode)
	}
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		return DeviceFlow{}, err
	}
	dc, _ := doc["device_code"].(string)
	uc, _ := doc["user_code"].(string)
	baseURL, _ := doc["verification_uri"].(string)
	if baseURL == "" {
		baseURL, _ = doc["verification_url"].(string)
	}
	exp, _ := doc["expires_in"].(float64)
	interval, _ := doc["interval"].(float64)
	if interval <= 0 {
		interval = 5
	}
	vurl, _ := doc["verification_uri_complete"].(string)
	if vurl == "" {
		sep := "?"
		if strings.Contains(baseURL, "?") {
			sep = "&"
		}
		vurl = baseURL + sep + "user_code=" + url.QueryEscape(uc)
	}
	return DeviceFlow{
		DeviceCode:      dc,
		UserCode:        uc,
		VerificationURL: vurl,
		ExpiresIn:       int(exp),
		Interval:        interval,
		TokenEndpoint:   tokEP,
	}, nil
}

func (c *Client) discover(ctx context.Context) (deviceEP, tokenEP string, err error) {
	c.discMu.Lock()
	if c.deviceEP != "" && c.tokenEP != "" && time.Since(c.discAt) < 30*time.Minute {
		d, t := c.deviceEP, c.tokenEP
		c.discMu.Unlock()
		return d, t, nil
	}
	c.discMu.Unlock()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, DiscoveryURL, nil)
	if err != nil {
		return "", "", err
	}
	req.Header.Set("User-Agent", c.ua)
	resp, err := c.http.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode/100 != 2 {
		return "", "", fmt.Errorf("discovery rejected")
	}
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		return "", "", err
	}
	deviceEP, _ = doc["device_authorization_endpoint"].(string)
	tokenEP, _ = doc["token_endpoint"].(string)
	if deviceEP == "" || tokenEP == "" {
		return "", "", fmt.Errorf("discovery missing endpoints")
	}
	c.discMu.Lock()
	c.deviceEP, c.tokenEP, c.discAt = deviceEP, tokenEP, time.Now()
	c.discMu.Unlock()
	return deviceEP, tokenEP, nil
}

// principalFromSSO extracts user id from session SSO JWT for device approve form.
func jwtClaim(token, key string) string {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return ""
	}
	payload := parts[1]
	switch len(payload) % 4 {
	case 2:
		payload += "=="
	case 3:
		payload += "="
	}
	raw, err := base64.URLEncoding.DecodeString(payload)
	if err != nil {
		raw, err = base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			return ""
		}
	}
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return ""
	}
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

func principalFromSSO(sso string) string {
	for _, key := range []string{"sub", "user_id", "userId", "uid", "id", "principal_id", "principalId"} {
		if v := jwtClaim(sso, key); v != "" {
			return v
		}
	}
	// nested claims common on some x.ai session tokens
	parts := strings.Split(sso, ".")
	if len(parts) != 3 {
		return ""
	}
	payload := parts[1]
	switch len(payload) % 4 {
	case 2:
		payload += "=="
	case 3:
		payload += "="
	}
	raw, err := base64.URLEncoding.DecodeString(payload)
	if err != nil {
		raw, err = base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			return ""
		}
	}
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return ""
	}
	for _, nest := range []string{"user", "account", "identity", "profile"} {
		if sub, ok := m[nest].(map[string]any); ok {
			for _, key := range []string{"sub", "id", "user_id", "userId", "uid"} {
				if v, ok := sub[key].(string); ok && v != "" {
					return v
				}
			}
		}
	}
	return ""
}

func isDeviceDone(loc string) bool {
	if loc == "" {
		return false
	}
	u, err := url.Parse(loc)
	if err != nil {
		return strings.Contains(loc, "/oauth2/device/done")
	}
	p := u.Path
	return strings.Contains(p, "/oauth2/device/done") || strings.HasSuffix(p, "/device/done")
}

func isSignInRedirect(loc string) bool {
	low := strings.ToLower(loc)
	return strings.Contains(low, "/sign-in") ||
		strings.Contains(low, "/login") ||
		strings.Contains(low, "signin") ||
		strings.Contains(low, "login_required")
}

func isRedirect(code int) bool {
	return code == 301 || code == 302 || code == 303 || code == 307 || code == 308
}

func absURL(baseHost, loc string) string {
	if loc == "" {
		return ""
	}
	if strings.HasPrefix(loc, "http://") || strings.HasPrefix(loc, "https://") {
		return loc
	}
	if strings.HasPrefix(loc, "/") {
		return baseHost + loc
	}
	return loc
}

func authorizedBody(body string) bool {
	low := strings.ToLower(body)
	// Keep phrases tight — consent pages often contain loose "authorize" wording.
	return strings.Contains(low, "device authorized") ||
		strings.Contains(low, "device is authorized") ||
		strings.Contains(low, "you have authorized this device") ||
		strings.Contains(low, "you have successfully authorized") ||
		strings.Contains(body, "设备已授权") ||
		strings.Contains(body, "已成功授权")
}

// ConfirmHTTP posts verify + approve with SSO cookie (no browser).
// Success only when device is actually marked authorized (done path / body text),
// and a token probe does not immediately return invalid_grant.
func (c *Client) ConfirmHTTP(ctx context.Context, sso string, flow DeviceFlow) error {
	c.log("confirm start user_code=%s", strings.TrimSpace(flow.UserCode))
	sso = strings.TrimSpace(sso)
	if sso == "" {
		return fmt.Errorf("login_required")
	}
	cookie := "sso=" + sso
	userCode := strings.TrimSpace(flow.UserCode)
	if userCode == "" {
		return fmt.Errorf("user_code empty")
	}

	// Bind bare SSO into accounts/auth session cookies first.
	cookie = c.warmSSOSession(ctx, cookie)

	// Warm verification page (accounts.x.ai or auth.x.ai complete URL).
	referer := strings.TrimSpace(flow.VerificationURL)
	if referer == "" {
		referer = "https://accounts.x.ai/oauth2/device?user_code=" + url.QueryEscape(userCode)
	}
	if st, body, _, ck, err := c.doGETCookie(ctx, referer, cookie, true); err == nil {
		cookie = ck
		c.log("verify page warm status=%d url=%s body~%q", st, trimLoc(referer), trimLoc(strings.ReplaceAll(body, "\n", " ")))
		if isSignInRedirect(referer) || pageNeedsLogin(body) {
			// keep going — verify POST may still bind with sso cookie
			c.log("verify page suggests login wall; will try verify with sso cookie")
		}
	} else {
		c.log("verify page warm fail: %v", err)
	}

	verifyURLs := []string{VerifyURLAccounts, VerifyURL}
	approveURLs := []string{ApproveURLAccounts, ApproveURL}
	// Prefer host matching verification URL.
	if strings.Contains(referer, "auth.x.ai") {
		verifyURLs = []string{VerifyURL, VerifyURLAccounts}
		approveURLs = []string{ApproveURL, ApproveURLAccounts}
	}

	var (
		consentRef string
		lastVerify error
	)
	form := url.Values{"user_code": {userCode}}
	for _, vURL := range verifyURLs {
		c.log("verify POST %s", vURL)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, vURL, strings.NewReader(form.Encode()))
		if err != nil {
			lastVerify = err
			continue
		}
		c.setFormHeaders(req, referer, cookie)
		if strings.Contains(vURL, "auth.x.ai") {
			req.Header.Set("Origin", "https://auth.x.ai")
		} else {
			req.Header.Set("Origin", "https://accounts.x.ai")
		}
		resp, err := c.http.Do(req)
		if err != nil {
			lastVerify = err
			continue
		}
		loc := resp.Header.Get("Location")
		vbody, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		_ = resp.Body.Close()
		cookie = mergeSetCookies(cookie, resp.Header)
		c.log("verify resp status=%d loc=%s", resp.StatusCode, trimLoc(loc))
		if err := locationError(loc); err != nil {
			if errors.Is(err, ErrRateLimited) {
				c.TripRateLimit()
				return err
			}
			lastVerify = err
			continue
		}
		if resp.StatusCode == 403 {
			lastVerify = fmt.Errorf("challenge")
			continue
		}
		if isSignInRedirect(loc) {
			lastVerify = fmt.Errorf("sso_rejected verify→sign-in host=%s", vURL)
			continue
		}
		// Only treat explicit done as success at verify stage (skip approve).
		if isDeviceDone(loc) {
			return c.ensureDeviceAuthorized(ctx, flow)
		}
		if !isRedirect(resp.StatusCode) && loc == "" {
			preview := strings.TrimSpace(string(vbody))
			if len(preview) > 120 {
				preview = preview[:120]
			}
			lastVerify = fmt.Errorf("device_verify_failed status=%d body=%q", resp.StatusCode, preview)
			continue
		}
		// Build consent URL for approve.
		base := "https://accounts.x.ai"
		if strings.Contains(vURL, "auth.x.ai") {
			base = "https://auth.x.ai"
		}
		consentRef = absURL(base, loc)
		if consentRef == "" {
			consentRef = base + "/oauth2/device/consent?user_code=" + url.QueryEscape(userCode)
		}
		if isSignInRedirect(consentRef) {
			lastVerify = fmt.Errorf("sso_rejected verify→%s", consentRef)
			continue
		}
		lastVerify = nil
		break
	}
	if lastVerify != nil && consentRef == "" {
		return lastVerify
	}
	if consentRef == "" {
		consentRef = "https://accounts.x.ai/oauth2/device/consent?user_code=" + url.QueryEscape(userCode)
	}

	aform := url.Values{
		"user_code":      {userCode},
		"action":         {"allow"},
		"principal_type": {"User"},
		"principal_id":   {""},
	}
	if pid := principalFromSSO(sso); pid != "" {
		aform.Set("principal_id", pid)
	}
	if fields, htmlCookie := c.loadConsentForm(ctx, consentRef, cookie); len(fields) > 0 {
		cookie = htmlCookie
		for k, vs := range fields {
			if k == "action" {
				continue
			}
			if len(vs) > 0 && vs[0] != "" {
				aform.Set(k, vs[0])
			}
		}
		aform.Set("action", "allow")
		if aform.Get("user_code") == "" {
			aform.Set("user_code", userCode)
		}
		if aform.Get("principal_type") == "" {
			aform.Set("principal_type", "User")
		}
	}

	var lastApprove error
	pid := aform.Get("principal_id")
	forms := []url.Values{aform}
	for _, action := range []string{"allow", "accept"} {
		f := url.Values{
			"user_code":      {userCode},
			"action":         {action},
			"principal_type": {"User"},
			"principal_id":   {pid},
		}
		// Keep any csrf/state captured from consent HTML on the primary form.
		for _, k := range []string{"csrf", "csrf_token", "_csrf", "authenticity_token", "state", "nonce"} {
			if v := aform.Get(k); v != "" {
				f.Set(k, v)
			}
		}
		forms = append(forms, f)
	}
	for _, aURL := range approveURLs {
		for fi, form := range forms {
			c.log("approve POST %s form=%d action=%s", aURL, fi, form.Get("action"))
			req2, err := http.NewRequestWithContext(ctx, http.MethodPost, aURL, strings.NewReader(form.Encode()))
			if err != nil {
				lastApprove = err
				continue
			}
			c.setFormHeaders(req2, consentRef, cookie)
			if strings.Contains(aURL, "auth.x.ai") {
				req2.Header.Set("Origin", "https://auth.x.ai")
			} else {
				req2.Header.Set("Origin", "https://accounts.x.ai")
			}
			resp2, err := c.http.Do(req2)
			if err != nil {
				lastApprove = err
				continue
			}
			aloc := resp2.Header.Get("Location")
			body, _ := io.ReadAll(io.LimitReader(resp2.Body, 1<<20))
			_ = resp2.Body.Close()
			cookie = mergeSetCookies(cookie, resp2.Header)
			c.log("approve resp status=%d loc=%s body~%q", resp2.StatusCode, trimLoc(aloc), trimLoc(strings.ReplaceAll(string(body), "\n", " ")))
			if err := locationError(aloc); err != nil {
				if errors.Is(err, ErrRateLimited) {
					c.TripRateLimit()
					return fmt.Errorf("device_approve: %w", err)
				}
				lastApprove = fmt.Errorf("device_approve: %w", err)
				continue
			}
			if isSignInRedirect(aloc) {
				lastApprove = fmt.Errorf("sso_rejected approve→sign-in")
				continue
			}
			if resp2.StatusCode == 403 {
				lastApprove = fmt.Errorf("challenge")
				continue
			}
			if strings.Contains(strings.ToLower(string(body)), "invalid action") {
				lastApprove = fmt.Errorf("consent_invalid_action")
				continue
			}

			// Follow approve redirect (done / consent residual) to pick up cookies.
			if isRedirect(resp2.StatusCode) && aloc != "" {
				next := absURL("https://accounts.x.ai", aloc)
				if strings.Contains(aloc, "auth.x.ai") || strings.Contains(aURL, "auth.x.ai") {
					next = absURL("https://auth.x.ai", aloc)
				}
				if isSignInRedirect(next) {
					lastApprove = fmt.Errorf("sso_rejected approve-redirect→sign-in")
					continue
				}
				if st, b, ckErr := c.getWithCookie(ctx, next, cookie); ckErr == nil {
					_ = st
					_ = b
				}
			}

			// Token endpoint is the only source of truth — HTML "success" lies.
			looksGood := authorizedBody(string(body)) || isDeviceDone(aloc) ||
				isRedirect(resp2.StatusCode) || resp2.StatusCode/100 == 2
			if !looksGood {
				preview := strings.TrimSpace(string(body))
				if len(preview) > 160 {
					preview = preview[:160]
				}
				lastApprove = fmt.Errorf("unknown_page status=%d loc=%q body=%q", resp2.StatusCode, aloc, preview)
				continue
			}
			if err := c.ensureDeviceAuthorized(ctx, flow); err == nil {
				c.ClearRateLimit()
				c.log("approve accepted by token endpoint form=%d action=%s", fi, form.Get("action"))
				return nil
			} else {
				lastApprove = err
				c.log("approve not yet bound form=%d action=%s err=%v", fi, form.Get("action"), err)
				continue
			}
		}
	}
	if lastApprove != nil {
		return lastApprove
	}
	return fmt.Errorf("device_approve_failed")
}

// ensureDeviceAuthorized probes the token endpoint after approve.
// Real consent usually yields a token within a few seconds. Lingering
// authorization_pending means the HTML "success" was a false positive.
func (c *Client) ensureDeviceAuthorized(ctx context.Context, flow DeviceFlow) error {
	if strings.TrimSpace(flow.DeviceCode) == "" || strings.TrimSpace(flow.TokenEndpoint) == "" {
		// External device flows (CPA-managed) have no local device_code to probe.
		return nil
	}
	// Brief settle — IdP sometimes needs a beat after approve redirect.
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(500 * time.Millisecond):
	}

	// RFC 8628: honor interval; on slow_down increase by 5s. Keep total short so
	// Exchange can retry a fresh device code instead of looking hung.
	deadline := time.Now().Add(8 * time.Second)
	interval := 5 * time.Second
	if flow.Interval > 0 {
		interval = time.Duration(flow.Interval * float64(time.Second))
		if interval < 3*time.Second {
			interval = 3 * time.Second
		}
	}
	var lastCode, lastDesc string
	attempt := 0
	for {
		attempt++
		form := url.Values{}
		form.Set("client_id", ClientID)
		form.Set("device_code", flow.DeviceCode)
		form.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, flow.TokenEndpoint, strings.NewReader(form.Encode()))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("User-Agent", c.ua)
		resp, err := c.http.Do(req)
		if err != nil {
			return err
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		_ = resp.Body.Close()
		var doc map[string]any
		_ = json.Unmarshal(body, &doc)
		if resp.StatusCode/100 == 2 {
			c.log("token probe ok attempt=%d (token already issued)", attempt)
			return nil
		}
		errCode, _ := doc["error"].(string)
		errDesc, _ := doc["error_description"].(string)
		lastCode, lastDesc = errCode, errDesc
		c.log("token probe attempt=%d status=%d error=%s desc=%s next_wait=%s", attempt, resp.StatusCode, errCode, errDesc, interval)
		switch errCode {
		case "authorization_pending":
			// keep waiting briefly
		case "slow_down":
			interval += 5 * time.Second
		case "invalid_grant", "access_denied":
			if errDesc != "" {
				return fmt.Errorf("confirm_not_accepted: %s (%s)", errCode, errDesc)
			}
			return fmt.Errorf("confirm_not_accepted: %s", errCode)
		case "expired_token":
			return fmt.Errorf("confirm_not_accepted: expired_token")
		default:
			// Unknown — one more wait then fail.
		}
		if !time.Now().Add(interval).Before(deadline) {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(interval):
		}
	}
	if lastDesc != "" {
		return fmt.Errorf("confirm_not_accepted: still %s after approve (%s)", lastCodeOr(lastCode, "authorization_pending"), lastDesc)
	}
	return fmt.Errorf("confirm_not_accepted: still %s after approve", lastCodeOr(lastCode, "authorization_pending"))
}

func lastCodeOr(code, fallback string) string {
	if strings.TrimSpace(code) == "" {
		return fallback
	}
	return code
}

// ConfirmVerificationURL authorizes a device flow created by another process,
// such as CLIProxyAPI, while keeping the token exchange in that process.
func (c *Client) ConfirmVerificationURL(ctx context.Context, sso, verificationURL string) error {
	verificationURL = strings.TrimSpace(verificationURL)
	parsed, err := url.Parse(verificationURL)
	if err != nil {
		return fmt.Errorf("parse verification URL: %w", err)
	}
	userCode := strings.TrimSpace(parsed.Query().Get("user_code"))
	if userCode == "" {
		return fmt.Errorf("verification URL missing user_code")
	}
	return c.ConfirmHTTP(ctx, sso, DeviceFlow{
		UserCode:        userCode,
		VerificationURL: verificationURL,
	})
}

func mergeSetCookies(cookie string, h http.Header) string {
	// Keep existing; append new name=value from Set-Cookie (simple).
	out := cookie
	for _, sc := range h.Values("Set-Cookie") {
		part := strings.SplitN(sc, ";", 2)[0]
		if !strings.Contains(part, "=") {
			continue
		}
		name := strings.SplitN(part, "=", 2)[0]
		// replace existing name=
		found := false
		segs := strings.Split(out, "; ")
		for i, s := range segs {
			if strings.HasPrefix(s, name+"=") {
				segs[i] = part
				found = true
			}
		}
		if found {
			out = strings.Join(segs, "; ")
		} else if out == "" {
			out = part
		} else {
			out = out + "; " + part
		}
	}
	return out
}

func (c *Client) getWithCookie(ctx context.Context, rawURL, cookie string) (int, string, error) {
	st, body, _, _, err := c.doGETCookie(ctx, rawURL, cookie, false)
	return st, body, err
}

// doGETCookie GETs a URL with Cookie header.
// follow=true walks redirect hops (307/302/…) while merging Set-Cookie — required
// because accounts.x.ai binds the bare sso= JWT into a real session across hops.
func (c *Client) doGETCookie(ctx context.Context, rawURL, cookie string, follow bool) (int, string, http.Header, string, error) {
	current := rawURL
	var (
		st   int
		body string
		hdr  http.Header
	)
	for hop := 0; hop < 10; hop++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, current, nil)
		if err != nil {
			return 0, "", nil, cookie, err
		}
		req.Header.Set("User-Agent", c.ua)
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
		req.Header.Set("Accept-Language", "en-US,en;q=0.9")
		req.Header.Set("Cookie", cookie) // SSO only — no clearance jar on OAuth pages
		req.Header.Set("Sec-Fetch-Site", "same-site")
		req.Header.Set("Sec-Fetch-Mode", "navigate")
		req.Header.Set("Sec-Fetch-Dest", "document")
		req.Header.Set("Upgrade-Insecure-Requests", "1")
		resp, err := c.http.Do(req)
		if err != nil {
			return 0, "", nil, cookie, err
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
		_ = resp.Body.Close()
		st = resp.StatusCode
		body = string(b)
		hdr = resp.Header
		cookie = mergeSetCookies(cookie, resp.Header)
		loc := strings.TrimSpace(resp.Header.Get("Location"))
		if !follow || !isRedirect(resp.StatusCode) || loc == "" {
			return st, body, hdr, cookie, nil
		}
		next := absURL(baseOf(current), loc)
		c.log("get hop %d %d → %s", hop+1, resp.StatusCode, trimLoc(next))
		if isSignInRedirect(next) {
			// Still follow — valid sso should bounce through sign-in into a session.
		}
		current = next
	}
	return st, body, hdr, cookie, nil
}

func baseOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "https://accounts.x.ai"
	}
	return u.Scheme + "://" + u.Host
}

// warmSSOSession follows accounts/auth hops so the IdP binds bare SSO into session cookies.
func (c *Client) warmSSOSession(ctx context.Context, cookie string) string {
	pages := []string{
		"https://accounts.x.ai/",
		"https://accounts.x.ai/sign-in",
		"https://auth.x.ai/sign-in",
	}
	for _, p := range pages {
		st, _, _, ck, err := c.doGETCookie(ctx, p, cookie, true)
		if err != nil {
			c.log("sso warm fail url=%s err=%v", p, err)
			continue
		}
		cookie = ck
		c.log("sso warm ok url=%s status=%d", p, st)
	}
	return cookie
}

// loadConsentForm GETs consent page and extracts form fields (principal_id, csrf, etc.).
func (c *Client) loadConsentForm(ctx context.Context, consentURL, cookie string) (url.Values, string) {
	st, html, _, ck, err := c.doGETCookie(ctx, consentURL, cookie, true)
	if err != nil || st >= 400 {
		return nil, cookie
	}
	cookie = ck
	fields := parseHTMLFormFields(html)
	c.log("consent form fields=%d keys=%v", len(fields), fieldKeys(fields))
	return fields, cookie
}

func fieldKeys(v url.Values) []string {
	out := make([]string, 0, len(v))
	for k := range v {
		out = append(out, k)
	}
	if len(out) > 12 {
		return out[:12]
	}
	return out
}

func pageNeedsLogin(body string) bool {
	low := strings.ToLower(body)
	return strings.Contains(low, "sign in") ||
		strings.Contains(low, "log in") ||
		strings.Contains(low, "/sign-in") ||
		strings.Contains(body, "登录")
}

func parseHTMLFormFields(html string) url.Values {
	out := url.Values{}
	// input ... name="..." ... value="..." (order may vary)
	lower := html
	// naive scan for name= and value= pairs on input tags
	for i := 0; i < len(html); {
		idx := strings.Index(strings.ToLower(lower[i:]), "<input")
		if idx < 0 {
			break
		}
		i += idx
		end := strings.Index(lower[i:], ">")
		if end < 0 {
			break
		}
		tag := html[i : i+end]
		i += end + 1
		name := attrValue(tag, "name")
		if name == "" {
			continue
		}
		val := attrValue(tag, "value")
		out.Set(name, val)
	}
	return out
}

func attrValue(tag, attr string) string {
	// attr="..." or attr='...'
	low := strings.ToLower(tag)
	key := strings.ToLower(attr) + "="
	j := strings.Index(low, key)
	if j < 0 {
		return ""
	}
	rest := tag[j+len(key):]
	if rest == "" {
		return ""
	}
	q := rest[0]
	if q == '"' || q == '\'' {
		rest = rest[1:]
		k := strings.IndexByte(rest, q)
		if k < 0 {
			return ""
		}
		return rest[:k]
	}
	// unquoted
	k := strings.IndexAny(rest, " \t>/")
	if k < 0 {
		return rest
	}
	return rest[:k]
}

func locationError(loc string) error {
	if loc == "" {
		return nil
	}
	u, err := url.Parse(loc)
	if err != nil {
		return nil
	}
	e := u.Query().Get("error")
	if e == "" {
		return nil
	}
	if e == "rate_limited" {
		return ErrRateLimited
	}
	return fmt.Errorf("%s", e)
}

func (c *Client) setFormHeaders(req *http.Request, referer, cookie string) {
	req.Header.Set("User-Agent", c.ua)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Origin", "https://accounts.x.ai")
	req.Header.Set("Referer", referer)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// OAuth device verify/approve: ONLY session SSO. Do NOT append FlareSolverr/CF
	// clearance cookies — they can poison auth.x.ai and yield invalid_grant Access denied.
	req.Header.Set("Cookie", cookie)
	req.Header.Set("Sec-Fetch-Site", "same-site")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-User", "?1")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
}

func (c *Client) PollToken(ctx context.Context, flow DeviceFlow) (Credential, error) {
	// Default: honor device ExpiresIn (capped). Exchange uses pollTokenLimited after confirm.
	return c.pollTokenLimited(ctx, flow, 0)
}

// pollTokenLimited polls the token endpoint until success, fatal error, or maxWait.
// maxWait<=0 means use flow.ExpiresIn (capped at 3m) so a single attempt cannot hang 15m+.
func (c *Client) pollTokenLimited(ctx context.Context, flow DeviceFlow, maxWait time.Duration) (Credential, error) {
	exp := time.Duration(flow.ExpiresIn) * time.Second
	if flow.ExpiresIn <= 0 {
		exp = 3 * time.Minute
	}
	if exp > 3*time.Minute {
		exp = 3 * time.Minute
	}
	deadline := time.Now().Add(exp)
	if maxWait > 0 {
		d2 := time.Now().Add(maxWait)
		if d2.Before(deadline) {
			deadline = d2
		}
	}
	interval := time.Duration(flow.Interval * float64(time.Second))
	if interval < time.Second {
		interval = 5 * time.Second
	}
	c.log("poll token start max=%s interval=%s user_code=%s", time.Until(deadline).Round(time.Second), interval, strings.TrimSpace(flow.UserCode))
	n := 0
	var lastCode, lastDesc string
	for time.Now().Before(deadline) {
		n++
		form := url.Values{}
		form.Set("client_id", ClientID)
		form.Set("device_code", flow.DeviceCode)
		form.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, flow.TokenEndpoint, strings.NewReader(form.Encode()))
		if err != nil {
			return Credential{}, err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("User-Agent", c.ua)
		resp, err := c.http.Do(req)
		if err != nil {
			return Credential{}, err
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		_ = resp.Body.Close()
		var doc map[string]any
		_ = json.Unmarshal(body, &doc)
		if resp.StatusCode/100 == 2 {
			c.log("poll token ok attempt=%d", n)
			return credentialFrom(doc, flow.TokenEndpoint)
		}
		errCode, _ := doc["error"].(string)
		errDesc, _ := doc["error_description"].(string)
		lastCode, lastDesc = errCode, errDesc
		if n == 1 || n%3 == 0 {
			c.log("poll token attempt=%d error=%s desc=%s left=%s", n, errCode, errDesc, time.Until(deadline).Round(time.Second))
		}
		switch errCode {
		case "authorization_pending":
			// continue
		case "slow_down":
			interval += time.Second
		case "access_denied":
			return Credential{}, fmt.Errorf("oauth_denied")
		case "expired_token":
			return Credential{}, fmt.Errorf("oauth_expired")
		case "invalid_grant":
			if errDesc != "" {
				return Credential{}, fmt.Errorf("oauth_rejected: invalid_grant (%s) — device not authorized on auth.x.ai", errDesc)
			}
			return Credential{}, fmt.Errorf("oauth_rejected: invalid_grant — device not authorized on auth.x.ai")
		default:
			if errCode != "" {
				if errDesc != "" {
					return Credential{}, fmt.Errorf("oauth_rejected: %s (%s)", errCode, errDesc)
				}
				return Credential{}, fmt.Errorf("oauth_rejected: %s", errCode)
			}
			return Credential{}, fmt.Errorf("oauth_rejected status=%d body=%s", resp.StatusCode, truncateBody(body, 120))
		}
		select {
		case <-ctx.Done():
			return Credential{}, ctx.Err()
		case <-time.After(interval):
		}
	}
	if lastDesc != "" {
		return Credential{}, fmt.Errorf("oauth_pending_timeout: %s (%s)", lastCodeOr(lastCode, "authorization_pending"), lastDesc)
	}
	return Credential{}, fmt.Errorf("oauth_pending_timeout: %s", lastCodeOr(lastCode, "authorization_pending"))
}

func (c *Client) Refresh(ctx context.Context, refreshToken string) (Credential, error) {
	refreshToken = strings.TrimSpace(refreshToken)
	if refreshToken == "" {
		return Credential{}, fmt.Errorf("refresh_token empty")
	}
	if err := c.WaitRateLimit(ctx); err != nil {
		return Credential{}, err
	}
	_, tokenEP, err := c.discover(ctx)
	if err != nil {
		return Credential{}, err
	}
	form := url.Values{}
	form.Set("client_id", ClientID)
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshToken)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEP, strings.NewReader(form.Encode()))
	if err != nil {
		return Credential{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", c.ua)
	resp, err := c.http.Do(req)
	if err != nil {
		return Credential{}, err
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	_ = resp.Body.Close()
	var doc map[string]any
	_ = json.Unmarshal(body, &doc)
	if resp.StatusCode/100 == 2 {
		cred, err := credentialFrom(doc, tokenEP)
		if err != nil {
			return Credential{}, err
		}
		// Some IdPs omit rotating refresh_token; keep old.
		if cred.RefreshToken == "" {
			cred.RefreshToken = refreshToken
		}
		return cred, nil
	}
	errCode, _ := doc["error"].(string)
	errDesc, _ := doc["error_description"].(string)
	if errCode == "" {
		return Credential{}, fmt.Errorf("refresh_rejected status=%d body=%s", resp.StatusCode, truncateBody(body, 120))
	}
	if errDesc != "" {
		return Credential{}, fmt.Errorf("refresh_rejected: %s (%s)", errCode, errDesc)
	}
	return Credential{}, fmt.Errorf("refresh_rejected: %s", errCode)
}

// Exchange is convenience: start flow + confirm HTTP + poll.
// On rate_limited / device 429 / invalid_grant / confirm_not_accepted / pending_timeout,
// retry with a fresh device code. Post-confirm poll is capped so one attempt cannot hang
// for the full device ExpiresIn (often 15m) and look "stuck" after → OAuth.
func (c *Client) Exchange(ctx context.Context, sso string) (Credential, error) {
	var last error
	// Fresh SSO sessions sometimes need a short settle before device approve sticks.
	c.log("exchange settle 1.5s (fresh SSO)")
	select {
	case <-ctx.Done():
		return Credential{}, ctx.Err()
	case <-time.After(1500 * time.Millisecond):
	}
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			backoff := time.Duration(attempt) * 2 * time.Second
			c.log("exchange retry %d/3 backoff=%s last=%v", attempt+1, backoff, last)
			select {
			case <-ctx.Done():
				return Credential{}, ctx.Err()
			case <-time.After(backoff):
			}
		} else {
			c.log("exchange attempt 1/3 start device flow")
		}
		if err := c.WaitRateLimit(ctx); err != nil {
			return Credential{}, err
		}
		flow, err := c.StartDeviceFlow(ctx)
		if err != nil {
			last = err
			c.log("device flow start fail: %v", err)
			if errors.Is(err, ErrRateLimited) || strings.Contains(err.Error(), "status=429") {
				continue
			}
			if attempt < 2 {
				continue
			}
			return Credential{}, err
		}
		c.log("device flow ok user_code=%s verify=%s expires_in=%d", flow.UserCode, trimLoc(flow.VerificationURL), flow.ExpiresIn)
		if err := c.ConfirmHTTP(ctx, sso, flow); err != nil {
			last = err
			c.log("confirm fail: %v", err)
			if errors.Is(err, ErrRateLimited) ||
				strings.Contains(err.Error(), "challenge") ||
				strings.Contains(err.Error(), "unknown_page") ||
				strings.Contains(err.Error(), "device_verify") ||
				strings.Contains(err.Error(), "device_approve") ||
				strings.Contains(err.Error(), "confirm_not_accepted") ||
				strings.Contains(err.Error(), "sso_rejected") {
				continue
			}
			if attempt < 2 {
				continue
			}
			return Credential{}, err
		}
		// Confirm looked good — only wait briefly for token propagation.
		c.log("confirm ok, polling token (max 45s)…")
		cred, err := c.pollTokenLimited(ctx, flow, 45*time.Second)
		if err != nil {
			last = err
			c.log("poll token fail: %v", err)
			if strings.Contains(err.Error(), "invalid_grant") ||
				strings.Contains(err.Error(), "access_denied") ||
				strings.Contains(err.Error(), "oauth_denied") ||
				strings.Contains(err.Error(), "oauth_pending_timeout") ||
				strings.Contains(err.Error(), "confirm_not_accepted") {
				continue
			}
			if attempt < 2 {
				continue
			}
			return Credential{}, err
		}
		c.log("exchange ok expires_in=%d", cred.ExpiresIn)
		return cred, nil
	}
	if last == nil {
		last = fmt.Errorf("oauth_failed")
	}
	return Credential{}, last
}

func credentialFrom(doc map[string]any, endpoint string) (Credential, error) {
	at, _ := doc["access_token"].(string)
	rt, _ := doc["refresh_token"].(string)
	if at == "" || rt == "" {
		return Credential{}, fmt.Errorf("oauth_rejected: missing tokens")
	}
	id, _ := doc["id_token"].(string)
	tt, _ := doc["token_type"].(string)
	expF, _ := doc["expires_in"].(float64)
	exp := int(expF)
	if exp <= 0 {
		exp = 3600
	}
	now := time.Now().UTC()
	sub := jwtClaim(id, "sub")
	if sub == "" {
		sub = jwtClaim(at, "sub")
	}
	email := jwtClaim(id, "email")
	if email == "" {
		email = jwtClaim(at, "email")
	}
	return Credential{
		AccessToken:   at,
		RefreshToken:  rt,
		IDToken:       id,
		TokenType:     tt,
		ExpiresIn:     exp,
		ExpiresAt:     now.Add(time.Duration(exp) * time.Second).Format(time.RFC3339),
		LastRefresh:   now.Format(time.RFC3339),
		Subject:       sub,
		TokenEndpoint: endpoint,
		Email:         email,
	}, nil
}

func truncateBody(b []byte, n int) string {
	s := strings.TrimSpace(string(b))
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func trimLoc(s string) string {
	if len(s) <= 120 {
		return s
	}
	return s[:120] + "…"
}
