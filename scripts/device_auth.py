#!/usr/bin/env python3
"""Authorize an xAI OAuth device code via Playwright + CloakBrowser.

The accounts.x.ai /oauth2/device page is a JS SPA — pure HTTP form posts only
bounce to /account and never bind the device_code. This script injects the
session SSO cookie and clicks Continue/Allow like a real browser.

Usage:
  device_auth.py --url VERIFY_URL --sso JWT [--proxy URL] [--chrome PATH]
                 [--timeout 70] [--mode headless|offscreen]

Exit 0 and print "ok" on UI success. Errors on stderr, non-zero exit otherwise.
"""
from __future__ import annotations

import argparse
import asyncio
import glob
import os
import sys
import time


def find_chrome() -> str:
    env = (os.environ.get("CHROME_PATH") or "").strip()
    if env and os.path.exists(env):
        return env
    homes = []
    h = os.path.expanduser("~")
    if h:
        homes.append(h)
    homes.extend(["/root", "/home/charles"])
    matches: list[str] = []
    for home in homes:
        base = os.path.join(home, ".cloakbrowser")
        matches.extend(glob.glob(os.path.join(base, "chromium-*/chrome")))
        matches.extend(
            glob.glob(
                os.path.join(
                    base,
                    "chromium-*/Chromium.app/Contents/MacOS/Chromium",
                )
            )
        )
    if matches:
        return sorted(matches)[-1]
    for p in (
        "/usr/bin/google-chrome",
        "/usr/bin/google-chrome-stable",
        "/usr/bin/chromium",
        "/usr/bin/chromium-browser",
    ):
        if os.path.exists(p):
            return p
    return ""


def has_display() -> bool:
    return bool(
        (os.environ.get("DISPLAY") or "").strip()
        or (os.environ.get("WAYLAND_DISPLAY") or "").strip()
    )


def resolve_mode(mode: str) -> tuple[str, bool]:
    mode = (mode or "headless").strip().lower()
    if mode in ("", "auto"):
        mode = "headless"
    if mode == "offscreen":
        if has_display():
            return "offscreen", False
        return "headless-no-display", True
    return "headless", True


def launch_args(label: str) -> list[str]:
    args = [
        "--no-sandbox",
        "--disable-blink-features=AutomationControlled",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-infobars",
        "--disable-dev-shm-usage",
    ]
    if label == "offscreen":
        args.extend(["--window-position=-2400,-2400", "--window-size=1280,800"])
    return args


CLICK_JS = r"""
() => {
  const href = (location.href || "").toLowerCase();
  function visible(el){
    if (!el || el.disabled || el.getAttribute("aria-disabled")==="true") return false;
    const style = window.getComputedStyle(el);
    return !(style && (style.display==="none" || style.visibility==="hidden"));
  }
  function labelOf(el){
    return ((el.innerText || el.textContent || el.value || el.getAttribute("aria-label") || "")+"").trim();
  }
  function submitForm(f, tag){
    try {
      if (!f) return "";
      var actionInput = f.querySelector('[name=action], [name=Action]');
      if (!actionInput) {
        actionInput = document.createElement('input');
        actionInput.type = 'hidden';
        actionInput.name = 'action';
        f.appendChild(actionInput);
      }
      if (!actionInput.value) actionInput.value = 'allow';
      var btn = f.querySelector('button[type=submit], input[type=submit], button');
      if (btn && visible(btn)) { btn.click(); return tag + ":btn:" + labelOf(btn).slice(0,40); }
      f.submit();
      return tag + ":submit:" + (f.getAttribute("action") || location.pathname).slice(0,60);
    } catch (e) { return ""; }
  }
  var forms = Array.from(document.querySelectorAll("form"));
  for (var i=0;i<forms.length;i++) {
    var f = forms[i];
    var action = ((f.getAttribute("action") || "") + " " + href).toLowerCase();
    if (action.indexOf("approve")>=0 || action.indexOf("consent")>=0 || action.indexOf("device")>=0 || forms.length===1) {
      var r = submitForm(f, "form");
      if (r) return r;
    }
  }
  var needles = ["allow","authorize","approve","accept","continue","confirm","允许","授权","批准","继续","确认","同意"];
  var nodes = Array.from(document.querySelectorAll("button[type=submit], input[type=submit], button, [role=button], input[type=button], a"));
  for (var j=0;j<nodes.length;j++) {
    var el = nodes[j];
    if (!visible(el)) continue;
    var label = labelOf(el);
    if (!label) continue;
    var low = label.toLowerCase();
    var hit = false;
    for (var k=0;k<needles.length;k++) {
      if (low === needles[k] || low.indexOf(needles[k])>=0) { hit = true; break; }
    }
    if (!hit) continue;
    var parentForm = el.closest && el.closest("form");
    if (parentForm && (low.indexOf("allow")>=0 || low.indexOf("authorize")>=0 || low.indexOf("approve")>=0 || low.indexOf("accept")>=0 || low.indexOf("允许")>=0 || low.indexOf("授权")>=0 || low.indexOf("批准")>=0)) {
      var rs = submitForm(parentForm, "allow-form");
      if (rs) return rs;
    }
    try { el.click(); return label.slice(0,60); } catch (e) {}
  }
  var primary = document.querySelector("button[type=submit], button.bg-primary, button[data-testid*=allow], button[data-testid*=authorize]");
  if (primary && visible(primary)) {
    var pf = primary.closest && primary.closest("form");
    if (pf) {
      var r2 = submitForm(pf, "primary-form");
      if (r2) return r2;
    }
    try { primary.click(); return labelOf(primary).slice(0,60) || "primary"; } catch (e) {}
  }
  return "";
}
"""

STATUS_JS = r"""
() => {
  const href = location.href || "";
  const text = ((document.body && document.body.innerText) || "").slice(0, 500).toLowerCase();
  const done = href.includes("/oauth2/device/done") || href.includes("/device/done");
  const on_approve = href.includes("/oauth2/device/approve") || href.includes("/device/approve");
  const on_consent = href.includes("/consent") || href.includes("user_code=");
  const authed =
    text.includes("device authorized") ||
    text.includes("device is authorized") ||
    text.includes("you have authorized") ||
    text.includes("successfully authorized") ||
    text.includes("设备已授权") ||
    text.includes("已成功授权");
  const login =
    href.includes("/sign-in") ||
    href.includes("/login") ||
    (text.includes("sign in") && text.includes("password"));
  return { href, done, authed, login, on_approve, on_consent, sample: text.slice(0, 160) };
}
"""


async def run(url: str, sso: str, proxy: str, chrome: str, timeout: float, mode: str) -> int:
    try:
        from playwright.async_api import async_playwright
    except Exception as e:
        print(f"playwright import failed: {e}", file=sys.stderr)
        return 1

    if not chrome:
        chrome = find_chrome()
    if not chrome:
        print("chrome/chromium not found (cloakbrowser/CHROME_PATH)", file=sys.stderr)
        return 1

    label, headless = resolve_mode(mode)
    print(f"device_auth chrome={chrome} mode={label} headless={headless} url={url[:120]}", file=sys.stderr)

    launch: dict = {
        "executable_path": chrome,
        "headless": headless,
        "args": launch_args(label),
    }
    if proxy:
        launch["proxy"] = {"server": proxy}

    deadline = time.time() + max(15.0, timeout)
    async with async_playwright() as pw:
        browser = await pw.chromium.launch(**launch)
        try:
            context = await browser.new_context(
                viewport={"width": 1280, "height": 800},
                user_agent=(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/146.0.0.0 Safari/537.36"
                ),
            )
            await context.add_init_script(
                "Object.defineProperty(navigator,'webdriver',{get:()=>undefined})"
            )
            # Playwright: cookie must have EITHER url OR (domain+path), not both.
            clean = []
            for curl in (
                "https://accounts.x.ai/",
                "https://auth.x.ai/",
                "https://x.ai/",
                "https://accounts.x.ai/oauth2/device",
            ):
                clean.append(
                    {
                        "name": "sso",
                        "value": sso,
                        "url": curl,
                        "secure": True,
                    }
                )
            await context.add_cookies(clean)

            page = await context.new_page()
            await page.goto("https://accounts.x.ai/", wait_until="domcontentloaded", timeout=30000)
            await page.goto(url, wait_until="domcontentloaded", timeout=30000)

            last_click = ""
            ticks = 0
            while time.time() < deadline:
                ticks += 1
                try:
                    clicked = await page.evaluate(CLICK_JS)
                except Exception as e:
                    print(f"click eval err: {e}", file=sys.stderr)
                    clicked = ""
                if clicked:
                    last_click = clicked
                    print(f"click[{ticks}] {clicked!r}", file=sys.stderr)
                    try:
                        await page.wait_for_load_state("domcontentloaded", timeout=5000)
                    except Exception:
                        pass
                    await asyncio.sleep(0.8)

                try:
                    st = await page.evaluate(STATUS_JS)
                except Exception as e:
                    print(f"status eval err: {e}", file=sys.stderr)
                    st = {}

                href = (st or {}).get("href") or page.url or ""
                if (st or {}).get("done") or (st or {}).get("authed"):
                    print(f"ui_success href={href[:160]} last_click={last_click!r}", file=sys.stderr)
                    print("ok")
                    return 0

                if (st or {}).get("login") or ("/account" in href and "device" not in href):
                    print(f"session_page href={href[:160]} — re-open device url", file=sys.stderr)
                    try:
                        await page.goto(url, wait_until="domcontentloaded", timeout=30000)
                    except Exception as e:
                        print(f"reopen err: {e}", file=sys.stderr)

                if ticks % 5 == 0:
                    sample = ((st or {}).get("sample") or "")[:120]
                    print(f"tick[{ticks}] href={href[:120]} sample={sample!r}", file=sys.stderr)

                await asyncio.sleep(1.5)

            try:
                st = await page.evaluate(STATUS_JS)
                if (st or {}).get("done") or (st or {}).get("authed"):
                    print("ok")
                    return 0
                print(
                    f"timeout href={(st or {}).get('href', page.url)!r} last_click={last_click!r} sample={(st or {}).get('sample', '')!r}",
                    file=sys.stderr,
                )
            except Exception as e:
                print(f"timeout final status err: {e} last_click={last_click!r}", file=sys.stderr)
            return 1
        finally:
            await browser.close()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True)
    ap.add_argument("--sso", required=True)
    ap.add_argument("--proxy", default="")
    ap.add_argument("--chrome", default="")
    ap.add_argument("--timeout", type=float, default=70)
    ap.add_argument("--mode", default=os.environ.get("OAUTH_BROWSER_MODE", "headless"))
    args = ap.parse_args()
    url = (args.url or "").strip()
    sso = (args.sso or "").strip()
    if not url or not sso:
        print("url and sso required", file=sys.stderr)
        return 1
    try:
        return asyncio.run(
            run(
                url=url,
                sso=sso,
                proxy=(args.proxy or "").strip(),
                chrome=(args.chrome or "").strip(),
                timeout=float(args.timeout),
                mode=(args.mode or "headless"),
            )
        )
    except Exception as e:
        print(f"device_auth crashed: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
