package oauth

import (
	"bytes"
	"encoding/json"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"

	"github.com/grok-free-register/grok-reg/internal/browser"
)

// ConfirmBrowser drives the accounts.x.ai device SPA.
// Primary: Playwright+CloakBrowser script (same stack as turnstile).
// Fallback: chromedp against the same Chrome binary.
// Pure HTTP form posts only 307 to /account and never bind the device_code.
func (c *Client) ConfirmBrowser(ctx context.Context, sso string, flow DeviceFlow) error {
	c.log("browser confirm enter user_code=%s", strings.TrimSpace(flow.UserCode))
	sso = strings.TrimSpace(sso)
	if sso == "" {
		return fmt.Errorf("login_required")
	}
	userCode := strings.TrimSpace(flow.UserCode)
	verifyURL := strings.TrimSpace(flow.VerificationURL)
	if verifyURL == "" {
		if userCode == "" {
			return fmt.Errorf("user_code empty")
		}
		verifyURL = "https://accounts.x.ai/oauth2/device?user_code=" + userCode
	}

	// 1) Playwright script (preferred in Docker).
	if err := c.confirmViaPlaywright(ctx, sso, verifyURL, flow); err == nil {
		// Script may have already exchanged device_code (TOKEN_JSON).
		if strings.TrimSpace(c.lastTokenJSON) != "" {
			c.log("browser confirm ok via device_auth TOKEN_JSON")
			c.ClearRateLimit()
			return nil
		}
		if code, perr := c.probeTokenOnce(ctx, flow); perr == nil && code == "" {
			c.log("browser confirm ok via playwright+token")
			c.ClearRateLimit()
			return nil
		} else if perr != nil {
			c.log("playwright UI/API ok but token hard err: %v", perr)
			return perr
		} else {
			c.log("playwright UI/API ok, token soft=%s 閳?settle probe", code)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(3 * time.Second):
			}
			if code2, perr2 := c.probeTokenOnce(ctx, flow); perr2 == nil && code2 == "" {
				c.ClearRateLimit()
				return nil
			} else if perr2 != nil {
				return perr2
			}
			c.log("playwright token still soft after settle; trying chromedp")
		}
	} else {
		c.log("playwright device_auth fail: %v", err)
		// Hard token/deny failures must NOT fall through to chromedp —
		// a second approve pass poisons the same device_code.
		errS := strings.ToLower(err.Error())
		if strings.Contains(errS, "invalid_grant") ||
			strings.Contains(errS, "access denied") ||
			strings.Contains(errS, "access_denied") ||
			strings.Contains(errS, "oauth_denied") ||
			strings.Contains(errS, "clicked deny") ||
			strings.Contains(errS, "ui_denied") ||
			strings.Contains(errS, "login_required") {
			return err
		}
	}

	// 2) chromedp fallback only for infra/timeouts, not grant denials
	return c.confirmViaChromedp(ctx, sso, verifyURL, flow)
}

func (c *Client) confirmViaPlaywright(ctx context.Context, sso, verifyURL string, flow DeviceFlow) error {
	userCode := strings.TrimSpace(flow.UserCode)
	py := findDeviceAuthPython()
	script := findDeviceAuthScript()
	if py == "" {
		return fmt.Errorf("device_auth python not found (GROK_PYTHON)")
	}
	if script == "" {
		return fmt.Errorf("device_auth.py not found (GROK_DEVICE_AUTH_SCRIPT)")
	}
	mode := strings.TrimSpace(os.Getenv("OAUTH_BROWSER_MODE"))
	if mode == "" {
		mode = "headless"
	}
	args := []string{
		script,
		"--url", verifyURL,
		"--sso", sso,
		"--timeout", "70",
		"--mode", mode,
	}
	if userCode != "" {
		args = append(args, "--user-code", userCode)
	}
	if dc := strings.TrimSpace(flow.DeviceCode); dc != "" {
		args = append(args, "--device-code", dc)
	}
	tokURL := strings.TrimSpace(flow.TokenEndpoint)
	if tokURL == "" {
		tokURL = "https://auth.x.ai/oauth2/token"
	}
	args = append(args, "--token-url", tokURL)
	args = append(args, "--client-id", ClientID)
	if strings.TrimSpace(c.proxy) != "" {
		args = append(args, "--proxy", strings.TrimSpace(c.proxy))
	}
	if chrome := browser.FindChrome(); chrome != "" {
		args = append(args, "--chrome", chrome)
	}

	bin := py
	binArgs := args
	if strings.EqualFold(mode, "offscreen") &&
		strings.TrimSpace(os.Getenv("DISPLAY")) == "" &&
		strings.TrimSpace(os.Getenv("WAYLAND_DISPLAY")) == "" {
		if xvfb, err := exec.LookPath("xvfb-run"); err == nil {
			bin = xvfb
			binArgs = append([]string{"-a", py}, args...)
		}
	}

	c.log("browser playwright py=%s script=%s mode=%s user_code=%s", bin, script, mode, userCode)
	runCtx, cancel := context.WithTimeout(ctx, 80*time.Second)
	defer cancel()
	cmd := exec.CommandContext(runCtx, bin, binArgs...)
	cmd.Env = os.Environ()
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	out := strings.TrimSpace(stdout.String())
	errText := strings.TrimSpace(stderr.String())
	if errText != "" {
		for _, line := range strings.Split(errText, "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			if len(line) > 240 {
				line = line[:240] + "..."
			}
			c.log("device_auth | %s", line)
		}
	}
	lowErr := strings.ToLower(errText + " " + out)
	if strings.Contains(lowErr, "form:btn:deny") ||
		strings.Contains(lowErr, "deny_click_aborted") ||
		strings.Contains(lowErr, "last_click='form:btn:deny") ||
		strings.Contains(lowErr, "last_click=\"form:btn:deny") {
		return fmt.Errorf("device_auth clicked Deny (refusing fake success)")
	}
	// Always harvest TOKEN_JSON even on non-zero exit (partial success paths).
	for _, line := range strings.Split(out+"\n"+errText, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "TOKEN_JSON:") {
			raw := strings.TrimSpace(strings.TrimPrefix(line, "TOKEN_JSON:"))
			var doc map[string]any
			if json.Unmarshal([]byte(raw), &doc) == nil {
				if at, _ := doc["access_token"].(string); strings.TrimSpace(at) != "" {
					c.log("device_auth returned access_token len=%d", len(at))
					c.mu.Lock()
					c.lastTokenJSON = raw
					c.mu.Unlock()
				}
			}
		}
	}
	if strings.TrimSpace(c.lastTokenJSON) != "" {
		// Token already in hand — treat as success even if process exit was weird.
		return nil
	}
	if err != nil {
		if errText == "" {
			errText = err.Error()
		}
		lowCombo := strings.ToLower(errText + " " + out)
		if strings.Contains(lowCombo, "ui_done_no_token") || strings.Contains(lowCombo, "api_bound_no_token") {
			return fmt.Errorf("invalid_grant (Access denied) — UI allowed but token rejected")
		}
		return fmt.Errorf("device_auth: %s", trimLoc(errText))
	}
	if !strings.Contains(strings.ToLower(out), "ok") {
		lowCombo := strings.ToLower(out + " " + errText)
		if strings.Contains(lowCombo, "ui_done_no_token") || strings.Contains(lowCombo, "api_bound_no_token") {
			return fmt.Errorf("invalid_grant (Access denied) — UI allowed but token rejected")
		}
		return fmt.Errorf("device_auth: no ok in stdout (%s)", trimLoc(out+" "+errText))
	}
	if !strings.Contains(errText, "v7-hydrate-token") &&
		!strings.Contains(errText, "v6-explicit-approve") &&
		!strings.Contains(errText, "v5-no-reapprove") &&
		!strings.Contains(errText, "v4-no-deny") {
		c.log("device_auth warning: script missing v7 banner (stale image?)")
	}
	if strings.Contains(errText, "ui_done_no_token") || strings.Contains(errText, "api_bound_no_token") {
		c.log("device_auth UI done but token missing — will probe/fail hard")
	}
	if strings.Contains(errText, "approve_req ") {
		// surface last approve body line for operators
		for _, line := range strings.Split(errText, "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "approve_req ") {
				c.log("device_auth | %s", line)
			}
		}
	}
	// TOKEN_JSON already harvested above when present.
	return nil
}

// DeviceAuthPython/Script expose resolved paths for startup logs.
func DeviceAuthPython() string { return findDeviceAuthPython() }
func DeviceAuthScript() string { return findDeviceAuthScript() }

func findDeviceAuthPython() string {
	for _, name := range []string{
		os.Getenv("GROK_PYTHON"),
		"/opt/cloakbrowser-venv/bin/python",
		"python3",
		"python",
	} {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if path, err := exec.LookPath(name); err == nil {
			return path
		}
		if strings.Contains(name, string(os.PathSeparator)) || strings.Contains(name, "/") {
			if st, err := os.Stat(name); err == nil && !st.IsDir() {
				return name
			}
		}
	}
	return ""
}

func findDeviceAuthScript() string {
	if p := strings.TrimSpace(os.Getenv("GROK_DEVICE_AUTH_SCRIPT")); p != "" {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	var candidates []string
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		candidates = append(candidates,
			filepath.Join(dir, "scripts", "device_auth.py"),
			filepath.Join(dir, "device_auth.py"),
			filepath.Join(dir, "..", "scripts", "device_auth.py"),
		)
	}
	if wd, err := os.Getwd(); err == nil {
		candidates = append(candidates, filepath.Join(wd, "scripts", "device_auth.py"))
	}
	candidates = append(candidates,
		"/usr/local/share/grok-reg/device_auth.py",
		"/opt/Grok-Register/scripts/device_auth.py",
	)
	for _, p := range candidates {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	return ""
}

func (c *Client) confirmViaChromedp(ctx context.Context, sso, verifyURL string, flow DeviceFlow) error {
	execPath := browser.FindChrome()
	if execPath == "" {
		return fmt.Errorf("chrome/chromium not found for device confirm; set CHROME_PATH")
	}

	hard := 75 * time.Second
	ctx, cancel := context.WithTimeout(ctx, hard)
	defer cancel()

	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-dev-shm-usage", true),
		chromedp.Flag("disable-blink-features", "AutomationControlled"),
		chromedp.Flag("no-first-run", true),
		chromedp.Flag("no-default-browser-check", true),
		chromedp.WindowSize(1024, 768),
		chromedp.UserAgent(c.ua),
		chromedp.ExecPath(execPath),
	)
	if strings.TrimSpace(c.proxy) != "" {
		opts = append(opts, chromedp.ProxyServer(strings.TrimSpace(c.proxy)))
	}

	allocCtx, allocCancel := chromedp.NewExecAllocator(ctx, opts...)
	defer allocCancel()
	tabCtx, tabCancel := chromedp.NewContext(allocCtx)
	defer tabCancel()

	userCode := strings.TrimSpace(flow.UserCode)
	principal := principalFromSSO(sso)
	c.log("browser chromedp start chrome=%s user_code=%s principal=%s url=%s",
		execPath, userCode, trimLoc(principal), trimLoc(verifyURL))
	stealth := "Object.defineProperty(navigator,\"webdriver\",{get:()=>undefined})"

	if err := chromedp.Run(tabCtx,
		network.Enable(),
		chromedp.ActionFunc(func(ctx context.Context) error {
			_, err := page.AddScriptToEvaluateOnNewDocument(stealth).Do(ctx)
			return err
		}),
		chromedp.Navigate("https://accounts.x.ai/"),
		chromedp.WaitReady("body", chromedp.ByQuery),
		chromedp.ActionFunc(func(ctx context.Context) error {
			return setSSOCookies(ctx, sso)
		}),
		chromedp.Navigate(verifyURL),
		chromedp.WaitReady("body", chromedp.ByQuery),
	); err != nil {
		return fmt.Errorf("browser_navigate: %w", err)
	}

	// Best-effort fill user_code input if the SPA shows one.
	if userCode != "" {
		var filled string
		_ = chromedp.Run(tabCtx, chromedp.Evaluate(fmt.Sprintf(`(function(code){
  var inputs = Array.from(document.querySelectorAll("input"));
  for (var i=0;i<inputs.length;i++){
    var el = inputs[i];
    var name = ((el.getAttribute("name")||"")+" "+(el.id||"")+" "+(el.placeholder||"")).toLowerCase();
    if (name.indexOf("code")>=0 || name.indexOf("user")>=0 || inputs.length===1) {
      try { el.focus(); el.value=code;
        el.dispatchEvent(new Event("input",{bubbles:true}));
        el.dispatchEvent(new Event("change",{bubbles:true}));
        return "filled"; } catch(e) {}
    }
  }
  return "";
})(%q)`, userCode), &filled))
		if filled != "" {
			c.log("browser filled user_code input")
		}
	}

	deadline := time.Now().Add(60 * time.Second)
	var lastClick string
	var lastURL string
	probeEvery := 5 * time.Second
	nextProbe := time.Now().Add(2 * time.Second)
	nextAPI := time.Now()
	apiAttempts := 0
	bodyJS := "(document.body && (document.body.innerText||\"\") || \"\").slice(0,240)"

	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		var href, bodySample, clicked string
		if err := chromedp.Run(tabCtx,
			chromedp.Location(&href),
			chromedp.Evaluate(deviceClickJS, &clicked),
			chromedp.Evaluate(bodyJS, &bodySample),
		); err != nil {
			return fmt.Errorf("browser_tick: %w", err)
		}
		lastURL = href
		if clicked != "" {
			lastClick = clicked
			c.log("browser click %q url=%s", clicked, trimLoc(href))
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(2 * time.Second):
			}
			_ = chromedp.Run(tabCtx, chromedp.Location(&href))
			lastURL = href
		}

		// In-page verify+approve with real browser cookies (the binding step).
		if userCode != "" && apiAttempts < 6 && time.Now().After(nextAPI) {
			apiAttempts++
			nextAPI = time.Now().Add(4 * time.Second)
			var raw string
			js := fmt.Sprintf(`(async function(){
  var userCode = %q;
  var principalId = %q;
  var hosts = ["https://accounts.x.ai","https://auth.x.ai"];
  var out = [];
  var headers = {"Content-Type":"application/x-www-form-urlencoded","Accept":"text/html,application/json"};
  for (var hi=0; hi<hosts.length; hi++){
    var host = hosts[hi];
    try {
      var vresp = await fetch(host+"/oauth2/device/verify", {
        method:"POST", credentials:"include", headers:headers,
        body:"user_code="+encodeURIComponent(userCode), redirect:"follow"
      });
      var vtext = await vresp.text();
      out.push({step:"verify", host:host, status:vresp.status, url:(vresp.url||"").slice(0,120), body:(vtext||"").replace(/\s+/g," ").slice(0,80)});
    } catch(e) { out.push({step:"verify", host:host, error:String(e).slice(0,80)}); }
    var actions = ["allow","accept"];
    for (var ai=0; ai<actions.length; ai++){
      try {
        var params = new URLSearchParams();
        params.set("user_code", userCode);
        params.set("action", actions[ai]);
        params.set("principal_type", "User");
        if (principalId) params.set("principal_id", principalId);
        var aresp = await fetch(host+"/oauth2/device/approve", {
          method:"POST", credentials:"include", headers:headers,
          body: params.toString(), redirect:"follow"
        });
        var atext = await aresp.text();
        out.push({step:"approve", host:host, action:actions[ai], status:aresp.status, url:(aresp.url||"").slice(0,120), body:(atext||"").replace(/\s+/g," ").slice(0,80)});
      } catch(e) { out.push({step:"approve", host:host, action:actions[ai], error:String(e).slice(0,80)}); }
    }
  }
  return JSON.stringify(out);
})()`, userCode, principal)
			if err := chromedp.Run(tabCtx, chromedp.Evaluate(js, &raw)); err == nil && raw != "" {
				c.log("browser api_auth[%d] %s", apiAttempts, trimLoc(raw))
				// Immediate token probe after API attempt.
				if code, err := c.probeTokenOnce(ctx, flow); err == nil && code == "" {
					c.log("browser confirm ok via in-page api+token")
					c.ClearRateLimit()
					return nil
				} else if err != nil {
					return err
				}
			} else if err != nil {
				c.log("browser api_auth err: %v", err)
			}
		}

		if isDeviceDone(href) || authorizedBody(bodySample) {
			c.log("browser UI success url=%s", trimLoc(href))
			if code, err := c.probeTokenOnce(ctx, flow); err == nil && code == "" {
				c.ClearRateLimit()
				return nil
			} else if err != nil {
				return err
			}
		}

		if time.Now().After(nextProbe) {
			code, err := c.probeTokenOnce(ctx, flow)
			if err == nil && code == "" {
				c.log("browser confirm ok via token probe url=%s last_click=%q", trimLoc(lastURL), lastClick)
				c.ClearRateLimit()
				return nil
			}
			if err != nil {
				return err
			}
			c.log("browser token soft=%s url=%s last_click=%q", code, trimLoc(lastURL), lastClick)
			if strings.Contains(lastURL, "/device/approve") || strings.Contains(lastURL, "/device/consent") {
				var again string
				_ = chromedp.Run(tabCtx, chromedp.Evaluate(deviceClickJS, &again))
				if again != "" {
					c.log("browser re-submit %q on %s", again, trimLoc(lastURL))
				}
			}
			if code == "slow_down" {
				nextProbe = time.Now().Add(8 * time.Second)
			} else {
				nextProbe = time.Now().Add(probeEvery)
			}
		}

		if isSignInRedirect(href) || (strings.Contains(href, "/account") && !strings.Contains(href, "device")) {
			c.log("browser session page=%s; re-open device url", trimLoc(href))
			_ = chromedp.Run(tabCtx, chromedp.Navigate(verifyURL), chromedp.WaitReady("body", chromedp.ByQuery))
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(1500 * time.Millisecond):
		}
	}

	if code, err := c.probeTokenOnce(ctx, flow); err == nil && code == "" {
		c.ClearRateLimit()
		return nil
	}
	return fmt.Errorf("browser_confirm_timeout url=%s last_click=%q", trimLoc(lastURL), lastClick)
}

func setSSOCookies(ctx context.Context, sso string) error {
	targets := []struct {
		name, domain, url string
	}{
		{"sso", ".x.ai", "https://accounts.x.ai/"},
		{"sso", "accounts.x.ai", "https://accounts.x.ai/"},
		{"sso", "auth.x.ai", "https://auth.x.ai/"},
		{"sso", ".x.ai", "https://auth.x.ai/"},
	}
	for _, t := range targets {
		expr := network.SetCookie(t.name, sso).
			WithURL(t.url).
			WithDomain(t.domain).
			WithPath("/").
			WithSecure(true)
		_ = expr.Do(ctx)
	}
	return nil
}

// deviceClickJS clicks Continue / Allow / Authorize style controls on the device SPA.
const deviceClickJS = `(function(){
  const href = (location.href || "").toLowerCase();
  function visible(el){
    if (!el || el.disabled || el.getAttribute("aria-disabled")==="true") return false;
    const style = window.getComputedStyle(el);
    return !(style && (style.display==="none" || style.visibility==="hidden"));
  }
  function labelOf(el){
    return ((el.innerText || el.textContent || el.value || el.getAttribute("aria-label") || el.getAttribute("name") || "")+"").trim();
  }
  function isDeny(label){
    const low = (label || "").toLowerCase();
    const bad = ["deny","cancel","reject","decline","revoke"];
    for (var i=0;i<bad.length;i++){ if (low===bad[i] || low.indexOf(bad[i])>=0) return true; }
    return false;
  }
  function isAllow(label){
    const low = (label || "").toLowerCase();
    const good = ["allow","authorize","approve","accept","grant"];
    for (var i=0;i<good.length;i++){ if (low===good[i] || low.indexOf(good[i])>=0) return true; }
    return false;
  }
  function isContinue(label){
    const low = (label || "").toLowerCase();
    const good = ["continue","confirm","next","proceed"];
    for (var i=0;i<good.length;i++){ if (low===good[i] || low.indexOf(good[i])>=0) return true; }
    return false;
  }
  function ensureActionAllow(f){
    var actionInput = f.querySelector('[name=action], [name=Action]');
    if (!actionInput) {
      actionInput = document.createElement('input');
      actionInput.type = 'hidden';
      actionInput.name = 'action';
      f.appendChild(actionInput);
    }
    actionInput.value = 'allow';
  }
  function pickButton(f){
    var nodes = Array.from(f.querySelectorAll('button, input[type=submit], input[type=button]'));
    var allowBtn = null, contBtn = null;
    for (var i=0;i<nodes.length;i++){
      var el = nodes[i];
      if (!visible(el)) continue;
      var lab = labelOf(el);
      if (isDeny(lab)) continue;
      if (isAllow(lab)) { allowBtn = el; break; }
      if (isContinue(lab) && !contBtn) contBtn = el;
    }
    return allowBtn || contBtn || null;
  }
  function submitForm(f, tag){
    try {
      if (!f) return "";
      ensureActionAllow(f);
      var btn = pickButton(f);
      if (btn) { btn.click(); return tag + ":btn:" + labelOf(btn).slice(0,40); }
      f.submit();
      return tag + ":submit-allow:" + (f.getAttribute("action") || location.pathname).slice(0,60);
    } catch (e) { return ""; }
  }
  var onConsent = href.indexOf("consent")>=0 || href.indexOf("approve")>=0;
  var nodes = Array.from(document.querySelectorAll("button[type=submit], input[type=submit], button, [role=button], input[type=button], a"));
  if (onConsent) {
    for (var j=0;j<nodes.length;j++){
      var el = nodes[j];
      if (!visible(el)) continue;
      var label = labelOf(el);
      if (!label || isDeny(label) || !isAllow(label)) continue;
      var pf = el.closest && el.closest("form");
      if (pf) { var rs = submitForm(pf, "allow-form"); if (rs) return rs; }
      try { el.click(); return "allow:"+label.slice(0,40); } catch (e) {}
    }
  }
  var forms = Array.from(document.querySelectorAll("form"));
  for (var i=0;i<forms.length;i++) {
    var f = forms[i];
    var action = ((f.getAttribute("action") || "") + " " + href).toLowerCase();
    if (action.indexOf("approve")>=0 || action.indexOf("consent")>=0 || action.indexOf("device")>=0 || action.indexOf("verify")>=0 || forms.length===1) {
      var r = submitForm(f, "form");
      if (r) return r;
    }
  }
  var priority = [];
  for (var n=0;n<nodes.length;n++){
    var el2 = nodes[n];
    if (!visible(el2)) continue;
    var lab2 = labelOf(el2);
    if (!lab2 || isDeny(lab2)) continue;
    if (isAllow(lab2)) priority.push({el:el2, lab:lab2, p:0});
    else if (isContinue(lab2)) priority.push({el:el2, lab:lab2, p:1});
  }
  priority.sort(function(a,b){ return a.p - b.p; });
  for (var k=0;k<priority.length;k++){
    var item = priority[k];
    var parentForm = item.el.closest && item.el.closest("form");
    if (parentForm && item.p === 0) {
      var rs2 = submitForm(parentForm, "allow-form");
      if (rs2) return rs2;
    }
    try { item.el.click(); return item.lab.slice(0,60); } catch (e) {}
  }
  return "";
})()`
