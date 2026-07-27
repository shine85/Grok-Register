package oauth

import (
	"bytes"
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
	if err := c.confirmViaPlaywright(ctx, sso, verifyURL); err == nil {
		if code, perr := c.probeTokenOnce(ctx, flow); perr == nil && code == "" {
			c.log("browser confirm ok via playwright+token")
			c.ClearRateLimit()
			return nil
		} else if perr != nil {
			c.log("playwright UI ok but token hard err: %v", perr)
			return perr
		} else {
			c.log("playwright UI ok, token soft=%s — settle probe", code)
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
	}

	// 2) chromedp fallback
	return c.confirmViaChromedp(ctx, sso, verifyURL, flow)
}

func (c *Client) confirmViaPlaywright(ctx context.Context, sso, verifyURL string) error {
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

	c.log("browser playwright py=%s script=%s mode=%s", bin, script, mode)
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
		for _, line := range strings.Split(errText, "
") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			if len(line) > 220 {
				line = line[:220] + "…"
			}
			c.log("device_auth | %s", line)
		}
	}
	if err != nil {
		if errText == "" {
			errText = err.Error()
		}
		return fmt.Errorf("device_auth: %s", trimLoc(errText))
	}
	if !strings.Contains(strings.ToLower(out), "ok") {
		return fmt.Errorf("device_auth: no ok in stdout (%s)", trimLoc(out+" "+errText))
	}
	return nil
}

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

	c.log("browser chromedp start chrome=%s url=%s", execPath, trimLoc(verifyURL))
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

	deadline := time.Now().Add(60 * time.Second)
	var lastClick string
	var lastURL string
	probeEvery := 5 * time.Second
	nextProbe := time.Now().Add(2 * time.Second)
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
  const needles = [
    "allow","authorize","approve","accept","continue","confirm",
    "允许","授权","批准","继续","确认","同意"
  ];
  const nodes = Array.from(document.querySelectorAll(
    "button, [role=button], input[type=submit], input[type=button], a"
  ));
  for (const el of nodes) {
    if (el.disabled || el.getAttribute("aria-disabled")==="true") continue;
    const style = window.getComputedStyle(el);
    if (style && (style.display==="none" || style.visibility==="hidden")) continue;
    const label = ((el.innerText || el.textContent || el.value || el.getAttribute("aria-label") || "")+"").trim();
    if (!label) continue;
    const low = label.toLowerCase();
    for (const n of needles) {
      if (low === n || low.includes(n)) {
        try { el.click(); return label.slice(0,60); } catch (e) {}
      }
    }
  }
  const primary = document.querySelector(
    "button[type=submit], button.bg-primary, button[data-testid*=allow], button[data-testid*=authorize]"
  );
  if (primary) {
    try {
      const label = ((primary.innerText || primary.textContent || "")+"").trim().slice(0,60);
      primary.click();
      return label || "primary";
    } catch (e) {}
  }
  return "";
})()`
