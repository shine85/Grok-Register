#!/usr/bin/env python3
"""Authorize an xAI OAuth device code via Playwright + CloakBrowser.

accounts.x.ai /oauth2/device is a JS SPA. Bare HTTP form posts with only the
SSO cookie bounce to /account and never bind device_code. This script:

  1) injects the SSO cookie into a real Chromium session
  2) warms accounts.x.ai so the SPA establishes session cookies
  3) opens the verification URL and clicks Continue / Allow
  4) additionally POSTs /oauth2/device/verify + /approve from inside the page
     (credentials:include) — this is what actually binds the device_code

Usage:
  device_auth.py --url VERIFY_URL --sso JWT [--user-code CODE] [--proxy URL]
                 [--chrome PATH] [--timeout 70] [--mode headless|offscreen]

Exit 0 and print "ok" on success. Errors on stderr, non-zero exit otherwise.
"""
from __future__ import annotations

import argparse
import asyncio
import base64
import glob
import json
import os
import sys
import time
from urllib.parse import parse_qs, urlparse


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


def b64url_json(segment: str) -> dict:
    raw = segment or ""
    pad = "=" * ((4 - len(raw) % 4) % 4)
    try:
        data = base64.urlsafe_b64decode(raw + pad)
        return json.loads(data.decode("utf-8", errors="ignore") or "{}")
    except Exception:
        return {}


def principal_from_sso(sso: str) -> str:
    parts = (sso or "").split(".")
    if len(parts) != 3:
        return ""
    claims = b64url_json(parts[1])
    for key in (
        "sub",
        "user_id",
        "userId",
        "uid",
        "id",
        "principal_id",
        "principalId",
    ):
        v = claims.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    for nest in ("user", "account", "identity", "profile"):
        sub = claims.get(nest)
        if isinstance(sub, dict):
            for key in ("sub", "id", "user_id", "userId", "uid"):
                v = sub.get(key)
                if isinstance(v, str) and v.strip():
                    return v.strip()
    return ""


def user_code_from_url(url: str) -> str:
    try:
        q = parse_qs(urlparse(url).query or "")
        vals = q.get("user_code") or q.get("userCode") or []
        if vals and str(vals[0]).strip():
            return str(vals[0]).strip()
    except Exception:
        pass
    return ""


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

FILL_CODE_JS = r"""
(code) => {
  if (!code) return "";
  const inputs = Array.from(document.querySelectorAll('input[type=text], input[name*=code i], input[id*=code i], input[autocomplete], input'));
  for (const el of inputs) {
    const name = ((el.getAttribute("name") || "") + " " + (el.getAttribute("id") || "") + " " + (el.getAttribute("placeholder") || "")).toLowerCase();
    if (name.includes("user") || name.includes("code") || name.includes("device") || inputs.length === 1) {
      try {
        el.focus();
        el.value = code;
        el.dispatchEvent(new Event("input", { bubbles: true }));
        el.dispatchEvent(new Event("change", { bubbles: true }));
        return "filled:" + (el.getAttribute("name") || el.getAttribute("id") || "input");
      } catch (e) {}
    }
  }
  return "";
}
"""

# In-page fetch with the browser's real session cookies. This is the binding step
# that pure Go HTTP (bare sso=) could not complete.
API_AUTH_JS = r"""
async ({ userCode, principalId }) => {
  const hosts = ["https://accounts.x.ai", "https://auth.x.ai"];
  const out = [];
  const headers = {
    "Content-Type": "application/x-www-form-urlencoded",
    "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
  };
  for (const host of hosts) {
    try {
      const vbody = "user_code=" + encodeURIComponent(userCode || "");
      const vresp = await fetch(host + "/oauth2/device/verify", {
        method: "POST",
        credentials: "include",
        headers,
        body: vbody,
        redirect: "follow",
      });
      const vtext = await vresp.text();
      out.push({
        step: "verify",
        host,
        status: vresp.status,
        url: (vresp.url || "").slice(0, 160),
        body: (vtext || "").replace(/\s+/g, " ").slice(0, 120),
      });
    } catch (e) {
      out.push({ step: "verify", host, error: String(e).slice(0, 120) });
    }
    for (const action of ["allow", "accept"]) {
      try {
        const params = new URLSearchParams();
        params.set("user_code", userCode || "");
        params.set("action", action);
        params.set("principal_type", "User");
        if (principalId) params.set("principal_id", principalId);
        const aresp = await fetch(host + "/oauth2/device/approve", {
          method: "POST",
          credentials: "include",
          headers,
          body: params.toString(),
          redirect: "follow",
        });
        const atext = await aresp.text();
        const low = (atext || "").toLowerCase();
        const okish =
          aresp.status >= 200 && aresp.status < 400 &&
          (low.includes("authorized") ||
           low.includes("device") ||
           (aresp.url || "").includes("done") ||
           (aresp.url || "").includes("device") ||
           aresp.status === 204 ||
           aresp.status === 200 ||
           aresp.status === 302 ||
           aresp.status === 303 ||
           aresp.status === 307);
        out.push({
          step: "approve",
          host,
          action,
          status: aresp.status,
          url: (aresp.url || "").slice(0, 160),
          body: (atext || "").replace(/\s+/g, " ").slice(0, 120),
          okish: !!okish,
        });
      } catch (e) {
        out.push({ step: "approve", host, action, error: String(e).slice(0, 120) });
      }
    }
  }
  return out;
}
"""


async def run(
    url: str,
    sso: str,
    proxy: str,
    chrome: str,
    timeout: float,
    mode: str,
    user_code: str,
) -> int:
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

    user_code = (user_code or user_code_from_url(url) or "").strip()
    principal = principal_from_sso(sso)
    label, headless = resolve_mode(mode)
    print(
        f"device_auth chrome={chrome} mode={label} headless={headless} "
        f"user_code={user_code or '-'} principal={principal[:18] or '-'} url={url[:120]}",
        file=sys.stderr,
    )

    launch: dict = {
        "executable_path": chrome,
        "headless": headless,
        "args": launch_args(label),
    }
    if proxy:
        launch["proxy"] = {"server": proxy}

    deadline = time.time() + max(20.0, timeout)
    api_done = False
    last_click = ""
    last_api = ""

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
            # Playwright cookie rule: url OR (domain+path), never both.
            cookies = []
            for curl in (
                "https://accounts.x.ai/",
                "https://auth.x.ai/",
                "https://x.ai/",
                "https://accounts.x.ai/oauth2/device",
                "https://auth.x.ai/oauth2/device",
            ):
                cookies.append(
                    {
                        "name": "sso",
                        "value": sso,
                        "url": curl,
                        "secure": True,
                    }
                )
            await context.add_cookies(cookies)

            # Capture approve/verify network for diagnostics + success signal.
            hit_paths: list[str] = []

            def on_response(resp) -> None:
                try:
                    u = resp.url or ""
                    if "/oauth2/device/" in u:
                        hit_paths.append(f"{resp.status}:{u[:140]}")
                except Exception:
                    pass

            context.on("response", on_response)

            page = await context.new_page()
            print("device_auth warm accounts.x.ai", file=sys.stderr)
            try:
                await page.goto(
                    "https://accounts.x.ai/",
                    wait_until="domcontentloaded",
                    timeout=30000,
                )
            except Exception as e:
                print(f"warm err: {e}", file=sys.stderr)
            await asyncio.sleep(0.6)

            print(f"device_auth open verify url={url[:140]}", file=sys.stderr)
            try:
                await page.goto(url, wait_until="domcontentloaded", timeout=30000)
            except Exception as e:
                print(f"goto verify err: {e}", file=sys.stderr)
            await asyncio.sleep(0.8)

            # Fill user_code if the SPA shows an input.
            if user_code:
                try:
                    filled = await page.evaluate(FILL_CODE_JS, user_code)
                    if filled:
                        print(f"device_auth {filled}", file=sys.stderr)
                except Exception as e:
                    print(f"fill code err: {e}", file=sys.stderr)

            ticks = 0
            api_attempts = 0
            while time.time() < deadline:
                ticks += 1

                # UI click pass
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

                # In-page API authorize every few ticks (and once early).
                if user_code and (ticks in (1, 2, 3) or ticks % 4 == 0) and api_attempts < 6:
                    api_attempts += 1
                    try:
                        results = await page.evaluate(
                            API_AUTH_JS,
                            {"userCode": user_code, "principalId": principal},
                        )
                        last_api = json.dumps(results, ensure_ascii=False)[:300]
                        print(f"api_auth[{api_attempts}] {last_api}", file=sys.stderr)
                        for row in results or []:
                            if not isinstance(row, dict):
                                continue
                            if row.get("step") == "approve" and row.get("okish"):
                                api_done = True
                            body = str(row.get("body") or "").lower()
                            url_hit = str(row.get("url") or "").lower()
                            if "authorized" in body or "/device/done" in url_hit or "device authorized" in body:
                                api_done = True
                    except Exception as e:
                        print(f"api_auth err: {e}", file=sys.stderr)

                # UI status
                try:
                    st = await page.evaluate(STATUS_JS)
                except Exception as e:
                    print(f"status eval err: {e}", file=sys.stderr)
                    st = {}

                href = (st or {}).get("href") or page.url or ""
                if (st or {}).get("done") or (st or {}).get("authed") or api_done:
                    print(
                        f"ui_success href={href[:160]} last_click={last_click!r} api_done={api_done}",
                        file=sys.stderr,
                    )
                    if hit_paths:
                        print(f"net_hits {hit_paths[-6:]}", file=sys.stderr)
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
                    remain = max(0, int(deadline - time.time()))
                    print(
                        f"tick[{ticks}] remain={remain}s href={href[:120]} "
                        f"sample={sample!r} last_click={last_click!r}",
                        file=sys.stderr,
                    )

                await asyncio.sleep(1.2)

            # Final chance: one more API auth + status
            if user_code:
                try:
                    results = await page.evaluate(
                        API_AUTH_JS,
                        {"userCode": user_code, "principalId": principal},
                    )
                    print(f"api_auth[final] {json.dumps(results, ensure_ascii=False)[:300]}", file=sys.stderr)
                    for row in results or []:
                        if isinstance(row, dict) and row.get("step") == "approve" and row.get("okish"):
                            api_done = True
                except Exception as e:
                    print(f"api_auth final err: {e}", file=sys.stderr)

            try:
                st = await page.evaluate(STATUS_JS)
                if (st or {}).get("done") or (st or {}).get("authed") or api_done:
                    print("ok")
                    return 0
                print(
                    f"timeout href={(st or {}).get('href', page.url)!r} "
                    f"last_click={last_click!r} api_done={api_done} "
                    f"sample={(st or {}).get('sample', '')!r}",
                    file=sys.stderr,
                )
            except Exception as e:
                print(
                    f"timeout final status err: {e} last_click={last_click!r} api_done={api_done}",
                    file=sys.stderr,
                )
            if hit_paths:
                print(f"net_hits {hit_paths[-8:]}", file=sys.stderr)
            # If we saw approve network 2xx/3xx, still report ok and let Go token-probe decide.
            good_net = any(
                h.startswith(("200:", "201:", "202:", "204:", "302:", "303:", "307:"))
                and "approve" in h
                for h in hit_paths
            )
            if good_net or api_done:
                print("ok")
                return 0
            return 1
        finally:
            await browser.close()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True)
    ap.add_argument("--sso", required=True)
    ap.add_argument("--user-code", default="")
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
                user_code=(args.user_code or "").strip(),
            )
        )
    except Exception as e:
        print(f"device_auth crashed: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
