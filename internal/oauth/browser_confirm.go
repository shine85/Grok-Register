package oauth

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"

	"github.com/grok-free-register/grok-reg/internal/browser"
)

// ConfirmBrowser drives the accounts.x.ai device SPA with a real Chromium.
// HTTP form posts only bounce to /account because verify/approve UX is client-side JS.
func (c *Client) ConfirmBrowser(ctx context.Context, sso string, flow DeviceFlow) error {
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

	c.log("browser confirm start chrome=%s user_code=%s url=%s", execPath, userCode, trimLoc(verifyURL))

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

	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		var href, bodySample, clicked string
		bodyJS := "(document.body && (document.body.innerText||\"\") || \"\").slice(0,240)"
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
			c.log("browser UI success url=%s — probing token", trimLoc(href))
			if code, err := c.probeTokenOnce(ctx, flow); err == nil && code == "" {
				c.ClearRateLimit()
				return nil
			} else if err != nil {
				c.log("browser UI success hard token err: %v", err)
				return err
			} else {
				c.log("browser UI success token soft=%s", code)
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
				c.log("browser token hard err: %v", err)
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
