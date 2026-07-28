#!/usr/bin/env python3
"""Authorize an xAI OAuth device code via Playwright + CloakBrowser.

Never clicks Deny/Cancel. Prefers Allow over Continue. Binds device via
in-page verify/approve after a real browser SSO session.
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
        matches.extend(glob.glob(os.path.join(base, "chromium-*/Chromium.app/Contents/MacOS/Chromium")))
    if matches:
        return sorted(matches)[-1]
    for p in ("/usr/bin/google-chrome", "/usr/bin/google-chrome-stable", "/usr/bin/chromium", "/usr/bin/chromium-browser"):
        if os.path.exists(p):
            return p
    return ""


def has_display() -> bool:
    return bool((os.environ.get("DISPLAY") or "").strip() or (os.environ.get("WAYLAND_DISPLAY") or "").strip())


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
    args = ["--no-sandbox", "--disable-blink-features=AutomationControlled", "--no-first-run",
            "--no-default-browser-check", "--disable-infobars", "--disable-dev-shm-usage"]
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


def _as_str(v) -> str:
    if v is None:
        return ""
    if isinstance(v, str):
        return v.strip()
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        return str(v)
    return ""


def principal_from_sso(sso: str) -> str:
    parts = (sso or "").split(".")
    if len(parts) != 3:
        return ""
    claims = b64url_json(parts[1])
    keys = ("sub", "user_id", "userId", "uid", "id", "principal_id", "principalId",
            "account_id", "accountId", "user_uuid", "userUuid")
    for key in keys:
        s = _as_str(claims.get(key))
        if s:
            return s
    for nest in ("user", "account", "identity", "profile", "data", "payload"):
        sub = claims.get(nest)
        if isinstance(sub, dict):
            for key in keys:
                s = _as_str(sub.get(key))
                if s:
                    return s
    for k, v in claims.items():
        lk = str(k).lower()
        if "sub" in lk or "userid" in lk or "user_id" in lk or "principal" in lk:
            s = _as_str(v)
            if s and len(s) >= 6:
                return s
    return ""


def claim_keys(sso: str) -> str:
    parts = (sso or "").split(".")
    if len(parts) != 3:
        return ""
    claims = b64url_json(parts[1])
    return ",".join(list(claims.keys())[:20])


def user_code_from_url(url: str) -> str:
    try:
        q = parse_qs(urlparse(url).query or "")
        vals = q.get("user_code") or q.get("userCode") or []
        if vals and str(vals[0]).strip():
            return str(vals[0]).strip()
    except Exception:
        pass
    return ""


def click_was_deny(last_click: str) -> bool:
    low = (last_click or "").lower()
    return any(x in low for x in ("deny", "cancel", "reject", "decline", "拒绝", "取消"))

CLICK_JS = r"""
() => {
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
    const bad = ["deny","cancel","reject","decline","revoke","disagree","拒绝","取消","否","不同意"];
    for (let i=0;i<bad.length;i++){ if (low === bad[i] || low.indexOf(bad[i]) >= 0) return true; }
    return false;
  }
  function isAllow(label){
    const low = (label || "").toLowerCase();
    const good = ["allow","authorize","approve","accept","grant","允许","授权","批准","同意"];
    for (let i=0;i<good.length;i++){ if (low === good[i] || low.indexOf(good[i]) >= 0) return true; }
    return false;
  }
  function isContinue(label){
    const low = (label || "").toLowerCase();
    const good = ["continue","confirm","next","proceed","继续","确认","下一步"];
    for (let i=0;i<good.length;i++){ if (low === good[i] || low.indexOf(good[i]) >= 0) return true; }
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
      try { el.click(); return "allow:" + label.slice(0,40); } catch (e) {}
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
}
"""

STATUS_JS = r"""
() => {
  const href = location.href || "";
  const text = ((document.body && document.body.innerText) || "").slice(0, 800).toLowerCase();
  const done = href.includes("/oauth2/device/done") || href.includes("/device/done");
  const on_approve = href.includes("/oauth2/device/approve") || href.includes("/device/approve");
  const on_consent = href.includes("/consent") || href.includes("/device/consent");
  const denied =
    text.includes("access denied") || text.includes("request denied") ||
    text.includes("authorization denied") || text.includes("you denied") ||
    text.includes("has been denied") || text.includes("已拒绝") || text.includes("拒绝授权");
  const authed = !denied && (
    text.includes("device authorized") || text.includes("device is authorized") ||
    text.includes("you have authorized") || text.includes("successfully authorized") ||
    text.includes("authorization successful") || text.includes("设备已授权") || text.includes("已成功授权")
  );
  const login = href.includes("/sign-in") || href.includes("/login") ||
    (text.includes("sign in") && text.includes("password"));
  return { href, done, authed, denied, login, on_approve, on_consent, sample: text.slice(0, 160) };
}
"""

FILL_CODE_JS = r"""
(code) => {
  if (!code) return "";
  const inputs = Array.from(document.querySelectorAll("input"));
  for (const el of inputs) {
    const name = ((el.getAttribute("name") || "") + " " + (el.getAttribute("id") || "") + " " + (el.getAttribute("placeholder") || "")).toLowerCase();
    const type = (el.getAttribute("type") || "text").toLowerCase();
    if (type === "hidden" || type === "password" || type === "email" || type === "submit") continue;
    if (name.includes("user") || name.includes("code") || name.includes("device") || inputs.length <= 3) {
      try {
        el.focus(); el.value = code;
        el.dispatchEvent(new Event("input", { bubbles: true }));
        el.dispatchEvent(new Event("change", { bubbles: true }));
        return "filled:" + (el.getAttribute("name") || el.getAttribute("id") || "input");
      } catch (e) {}
    }
  }
  return "";
}
"""

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
      const vresp = await fetch(host + "/oauth2/device/verify", {
        method: "POST", credentials: "include", headers,
        body: "user_code=" + encodeURIComponent(userCode || ""), redirect: "follow",
      });
      const vtext = await vresp.text();
      const vurl = (vresp.url || "");
      out.push({
        step: "verify", host, status: vresp.status, url: vurl.slice(0, 160),
        body: (vtext || "").replace(/\s+/g, " ").slice(0, 120),
        okish: vurl.includes("consent") || vurl.includes("approve") || vurl.includes("/device"),
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
          method: "POST", credentials: "include", headers,
          body: params.toString(), redirect: "follow",
        });
        const atext = await aresp.text();
        const low = (atext || "").toLowerCase();
        const aurl = (aresp.url || "");
        const denied = low.includes("access denied") || low.includes("you denied") || low.includes("invalid action");
        const okish = !denied && aresp.status >= 200 && aresp.status < 400 && (
          aurl.includes("/device/done") || aurl.includes("done") ||
          low.includes("device authorized") || low.includes("you have authorized") ||
          low.includes("successfully authorized")
        );
        out.push({
          step: "approve", host, action, status: aresp.status, url: aurl.slice(0, 160),
          body: (atext || "").replace(/\s+/g, " ").slice(0, 120), okish: !!okish,
        });
      } catch (e) {
        out.push({ step: "approve", host, action, error: String(e).slice(0, 120) });
      }
    }
  }
  return out;
}
"""

async def run(url: str, sso: str, proxy: str, chrome: str, timeout: float, mode: str, user_code: str) -> int:
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
    keys = claim_keys(sso)
    label, headless = resolve_mode(mode)
    print(
        f"device_auth chrome={chrome} mode={label} headless={headless} "
        f"user_code={user_code or '-'} principal={principal[:24] or '-'} "
        f"claims={keys or '-'} url={url[:120]}",
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
    api_bound = False
    last_click = ""
    hit_paths: list[str] = []

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
            cookies = []
            for curl in (
                "https://accounts.x.ai/",
                "https://auth.x.ai/",
                "https://x.ai/",
                "https://accounts.x.ai/oauth2/device",
                "https://auth.x.ai/oauth2/device",
            ):
                cookies.append({"name": "sso", "value": sso, "url": curl, "secure": True})
            await context.add_cookies(cookies)

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
                await page.goto("https://accounts.x.ai/", wait_until="domcontentloaded", timeout=30000)
            except Exception as e:
                print(f"warm err: {e}", file=sys.stderr)
            await asyncio.sleep(0.8)

            print(f"device_auth open verify url={url[:140]}", file=sys.stderr)
            try:
                await page.goto(url, wait_until="domcontentloaded", timeout=30000)
            except Exception as e:
                print(f"goto verify err: {e}", file=sys.stderr)
            await asyncio.sleep(0.8)

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

                try:
                    clicked = await page.evaluate(CLICK_JS)
                except Exception as e:
                    print(f"click eval err: {e}", file=sys.stderr)
                    clicked = ""
                if clicked:
                    last_click = clicked
                    print(f"click[{ticks}] {clicked!r}", file=sys.stderr)
                    if click_was_deny(clicked):
                        print(f"deny_click_aborted {clicked!r}", file=sys.stderr)
                        return 1
                    try:
                        await page.wait_for_load_state("domcontentloaded", timeout=5000)
                    except Exception:
                        pass
                    await asyncio.sleep(1.0)

                href_now = page.url or ""
                on_device_stage = any(x in href_now for x in ("/consent", "/approve", "/device/done", "user_code="))
                if user_code and on_device_stage and api_attempts < 5 and (ticks in (2, 3, 5) or ticks % 5 == 0):
                    api_attempts += 1
                    try:
                        results = await page.evaluate(API_AUTH_JS, {"userCode": user_code, "principalId": principal})
                        print(f"api_auth[{api_attempts}] {json.dumps(results, ensure_ascii=False)[:320]}", file=sys.stderr)
                        for row in results or []:
                            if isinstance(row, dict) and row.get("step") == "approve" and row.get("okish"):
                                api_bound = True
                    except Exception as e:
                        print(f"api_auth err: {e}", file=sys.stderr)

                try:
                    st = await page.evaluate(STATUS_JS)
                except Exception as e:
                    print(f"status eval err: {e}", file=sys.stderr)
                    st = {}

                href = (st or {}).get("href") or page.url or ""
                if (st or {}).get("denied") or click_was_deny(last_click):
                    print(f"denied href={href[:160]} last_click={last_click!r}", file=sys.stderr)
                    return 1

                done = bool((st or {}).get("done") or (st or {}).get("authed"))
                on_consent = bool((st or {}).get("on_consent"))
                if done or api_bound:
                    if on_consent and not done and not api_bound:
                        print(f"on_consent waiting allow href={href[:120]}", file=sys.stderr)
                    else:
                        print(f"ui_success href={href[:160]} last_click={last_click!r} api_bound={api_bound}", file=sys.stderr)
                        if hit_paths:
                            print(f"net_hits {hit_paths[-8:]}", file=sys.stderr)
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
                        f"tick[{ticks}] remain={remain}s href={href[:120]} sample={sample!r} last_click={last_click!r}",
                        file=sys.stderr,
                    )
                await asyncio.sleep(1.2)

            try:
                st = await page.evaluate(STATUS_JS)
                if ((st or {}).get("done") or (st or {}).get("authed") or api_bound) and not click_was_deny(last_click):
                    print("ok")
                    return 0
                print(
                    f"timeout href={(st or {}).get('href', page.url)!r} last_click={last_click!r} "
                    f"api_bound={api_bound} sample={(st or {}).get('sample', '')!r}",
                    file=sys.stderr,
                )
            except Exception as e:
                print(f"timeout final status err: {e} last_click={last_click!r}", file=sys.stderr)
            if hit_paths:
                print(f"net_hits {hit_paths[-8:]}", file=sys.stderr)
            good_net = any(("done" in h) and h.startswith(("200:", "303:", "302:")) for h in hit_paths)
            if good_net and api_bound and not click_was_deny(last_click):
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