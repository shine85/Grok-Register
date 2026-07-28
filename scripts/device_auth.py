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

DEVICE_AUTH_VERSION = "v7-hydrate-token"


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


def is_cookie_banner_label(label: str) -> bool:
    low = (label or "").strip().lower()
    if not low:
        return False
    if "cookie" in low:
        return True
    if "accept all" in low or "reject all" in low:
        return True
    return False


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
    const good = ["allow","authorize","approve","grant","允许","授权","批准","同意"];
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
    actionInput.value = 'accept';
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
  const text = ((document.body && document.body.innerText) || "").slice(0, 1200).toLowerCase();
  let errQ = "";
  try { errQ = (new URL(href)).searchParams.get("error") || ""; } catch (e) {}
  const done = href.includes("/oauth2/device/done") || href.includes("/device/done");
  const on_approve = href.includes("/oauth2/device/approve") || href.includes("/device/approve");
  const on_consent = href.includes("/consent") || href.includes("/device/consent");
  const denied = (errQ && errQ !== "") ||
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
  return { href, done, authed, denied, login, on_approve, on_consent, errQ, sample: text.slice(0, 200) };
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



def poll_device_token(device_code: str, token_url: str, client_id: str, proxy: str = "", attempts: int = 8):
    """Exchange device_code at token endpoint after UI allow. No browser cookies required."""
    device_code = (device_code or "").strip()
    token_url = (token_url or "").strip() or "https://auth.x.ai/oauth2/token"
    client_id = (client_id or "").strip() or "b1a00492-073a-47ea-816f-4c329264a828"
    if not device_code:
        return None
    try:
        import urllib.error
        import urllib.parse
        import urllib.request
    except Exception as e:
        print(f"token poll import err: {e}", file=sys.stderr)
        return None
    body = urllib.parse.urlencode({
        "client_id": client_id,
        "device_code": device_code,
        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
    }).encode()
    handlers = []
    proxy = (proxy or "").strip()
    if proxy:
        handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
        print(f"token_poll using proxy={proxy}", file=sys.stderr)
    else:
        handlers.append(urllib.request.ProxyHandler({}))
    opener = urllib.request.build_opener(*handlers)
    for i in range(max(1, attempts)):
        try:
            req = urllib.request.Request(
                token_url,
                data=body,
                method="POST",
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
                    "Accept": "application/json",
                },
            )
            with opener.open(req, timeout=15) as resp:
                raw = resp.read().decode("utf-8", errors="ignore")
                doc = json.loads(raw or "{}")
                if doc.get("access_token"):
                    print(f"token_poll ok attempt={i+1}", file=sys.stderr)
                    return doc
                print(f"token_poll unexpected attempt={i+1} body={raw[:160]}", file=sys.stderr)
        except Exception as e:
            err_body = ""
            try:
                import urllib.error
                if isinstance(e, urllib.error.HTTPError) and e.fp is not None:
                    err_body = e.read().decode("utf-8", errors="ignore")
            except Exception:
                pass
            low = (err_body or str(e)).lower()
            print(f"token_poll attempt={i+1} err={e} body={err_body[:200]}", file=sys.stderr)
            if "authorization_pending" in low or "slow_down" in low:
                time.sleep(2.0)
                continue
            if "invalid_grant" in low or "access_denied" in low:
                return None
            time.sleep(1.5)
            continue
        time.sleep(1.5)
    return None


async def explicit_allow_on_consent(page, user_code: str, principal: str) -> str:
    """On consent/approve page: force action=allow and submit the real form / POST approve."""
    js = r"""
async (args) => {
  const userCode = args.userCode || "";
  const principalId = args.principalId || "";
  const href = location.href || "";
  // Collect form fields
  const forms = Array.from(document.querySelectorAll("form"));
  let form = null;
  for (const f of forms) {
    const a = ((f.getAttribute("action")||"") + " " + href).toLowerCase();
    if (a.includes("approve") || a.includes("consent") || a.includes("device") || forms.length===1) {
      form = f; break;
    }
  }
  if (!form && forms.length) form = forms[0];
  const fields = {};
  if (form) {
    const fd = new FormData(form);
    fd.forEach((v,k) => { fields[k] = String(v); });
    form.querySelectorAll("input,select,textarea,button").forEach(el => {
      const name = el.getAttribute("name");
      if (!name) return;
      if (el.type === "radio" || el.type === "checkbox") {
        if (el.checked) fields[name] = el.value || "on";
      } else if (el.tagName === "BUTTON" || el.type === "submit") {
        // skip
      } else if (el.value != null && el.value !== "" && fields[name] == null) {
        fields[name] = el.value;
      }
    });
  }
  fields["user_code"] = userCode || fields["user_code"] || "";
  fields["action"] = "accept"; fields["consent"] = "accept";
  fields["principal_type"] = fields["principal_type"] || "User";
  if (principalId) fields["principal_id"] = principalId;
  // Prefer real form submit with allow button
  if (form) {
    let actionInput = form.querySelector('[name=action], [name=Action]');
    if (!actionInput) {
      actionInput = document.createElement("input");
      actionInput.type = "hidden";
      actionInput.name = "action";
      form.appendChild(actionInput);
    }
    actionInput.value = "accept";
    // also set consent if present
    let cons = form.querySelector('[name=consent], [name=decision]');
    if (cons && cons.type !== "submit") cons.value = "accept";
    let uc = form.querySelector('[name=user_code]');
    if (!uc) {
      uc = document.createElement("input");
      uc.type = "hidden"; uc.name = "user_code"; form.appendChild(uc);
    }
    uc.value = fields["user_code"];
    // Click Allow-looking submit only
    const btns = Array.from(form.querySelectorAll("button, input[type=submit]"));
    let allowBtn = null;
    for (const b of btns) {
      const t = ((b.innerText||b.textContent||b.value||"")+"").toLowerCase();
      if (t.includes("deny")||t.includes("cancel")||t.includes("reject")) {
        b.disabled = true; continue;
      }
      if (t.includes("allow")||t.includes("authorize")||t.includes("approve")) {
        allowBtn = b; break;
      }
    }
    if (allowBtn) { allowBtn.click(); return "explicit:btn:" + ((allowBtn.innerText||allowBtn.value||"Allow")+"").slice(0,40); }
    form.submit();
    return "explicit:form-submit";
  }
  // No form — POST approve directly from page
  const bodies = [];
  for (const host of ["https://auth.x.ai", "https://accounts.x.ai"]) {
    const params = new URLSearchParams();
    Object.keys(fields).forEach(k => params.set(k, fields[k]));
    try {
      const resp = await fetch(host + "/oauth2/device/approve", {
        method: "POST", credentials: "include",
        headers: {"Content-Type":"application/x-www-form-urlencoded","Accept":"text/html,application/json"},
        body: params.toString(), redirect: "follow",
      });
      const text = await resp.text();
      bodies.push({host, status: resp.status, url: (resp.url||"").slice(0,160), body: (text||"").replace(/\s+/g," ").slice(0,100)});
    } catch (e) {
      bodies.push({host, error: String(e).slice(0,100)});
    }
  }
  return "explicit:fetch:" + JSON.stringify(bodies).slice(0,240);
}
"""
    try:
        return await page.evaluate(js, {"userCode": user_code, "principalId": principal})
    except Exception as e:
        return f"explicit_err:{e}"

async def playwright_click_allow_or_continue(page) -> str:
    """Prefer real Playwright clicks; never activate Deny/Cancel."""
    # Allow / Authorize first (consent page)
    allow_names = ("Allow", "Authorize", "Approve")
    cont_names = ("Continue", "Confirm", "Next", "继续", "确认", "下一步")
    deny_names = ("Deny", "Cancel", "Reject", "Decline", "拒绝", "取消")

    async def try_names(names, tag: str) -> str:
        for name in names:
            for role in ("button", "link"):
                try:
                    loc = page.get_by_role(role, name=name, exact=True)
                    if await loc.count() < 1:
                        loc = page.get_by_role(role, name=name, exact=False)
                    n = await loc.count()
                    if n < 1:
                        continue
                    # pick first visible non-deny
                    for i in range(min(n, 4)):
                        item = loc.nth(i)
                        try:
                            if not await item.is_visible():
                                continue
                            txt = ((await item.inner_text()) or "").strip()
                            low = txt.lower()
                            if is_cookie_banner_label(txt):
                                continue
                            if any(d.lower() in low for d in deny_names):
                                continue
                            await item.click(timeout=2500)
                            return f"{tag}:{txt[:40] or name}"
                        except Exception:
                            continue
                except Exception:
                    continue
            # text locator fallback
            try:
                loc = page.get_by_text(name, exact=True)
                if await loc.count() < 1:
                    continue
                item = loc.first
                if await item.is_visible():
                    txt = ((await item.inner_text()) or name).strip()
                    low = txt.lower()
                    if any(d.lower() in low for d in deny_names):
                        continue
                    await item.click(timeout=2500)
                    return f"{tag}-text:{txt[:40]}"
            except Exception:
                pass
        return ""

    hit = await try_names(allow_names, "pw-allow")
    if hit:
        return hit
    # On consent URL, do NOT fall through to Continue-only if Allow missing — try JS next
    href = (page.url or "").lower()
    if "consent" in href or "approve" in href:
        return ""
    return await try_names(cont_names, "pw-continue")

async def run(url: str, sso: str, proxy: str, chrome: str, timeout: float, mode: str, user_code: str, device_code: str = "", token_url: str = "", client_id: str = "") -> int:
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
        f"device_auth {DEVICE_AUTH_VERSION} chrome={chrome} mode={label} headless={headless} "
        f"user_code={user_code or '-'} device_code={('yes' if device_code else 'no')} "
        f"principal={principal[:24] or '-'} claims={keys or '-'} url={url[:120]}",
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

            def on_request(req) -> None:
                try:
                    u = req.url or ""
                    if "/oauth2/device/approve" in u and (req.method or "").upper() == "POST":
                        post = (req.post_data or "")[:300]
                        print(f"approve_req {post}", file=sys.stderr)
                except Exception:
                    pass

            def on_response(resp) -> None:
                try:
                    u = resp.url or ""
                    if "/oauth2/device/" in u:
                        hit_paths.append(f"{resp.status}:{u[:180]}")
                        if "approve" in u or "done" in u or "consent" in u:
                            loc = ""
                            try:
                                loc = resp.headers.get("location") or ""
                            except Exception:
                                loc = ""
                            if loc:
                                print(f"net {resp.status} {u[:180]} loc={loc[:160]}", file=sys.stderr)
                            else:
                                print(f"net {resp.status} {u[:200]}", file=sys.stderr)
                except Exception:
                    pass

            context.on("request", on_request)
            context.on("response", on_response)
            page = await context.new_page()

            # Activate session: accounts + grok app (new accounts often deny device token otherwise)
            for warm_url in (
                "https://accounts.x.ai/",
                "https://accounts.x.ai/account",
                "https://grok.x.ai/",
                "https://grok.com/",
            ):
                try:
                    print(f"device_auth warm {warm_url}", file=sys.stderr)
                    await page.goto(warm_url, wait_until="domcontentloaded", timeout=25000)
                    await asyncio.sleep(0.5)
                except Exception as e:
                    print(f"warm err {warm_url}: {e}", file=sys.stderr)

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
                    await page.evaluate("""() => {
                      document.querySelectorAll('form').forEach(f => {
                        let a = f.querySelector('[name=action], [name=Action]');
                        if (!a) {
                          a = document.createElement('input');
                          a.type = 'hidden'; a.name = 'action'; f.appendChild(a);
                        }
                        a.value = 'accept';
                        // disable deny buttons so accidental submit cannot deny
                        f.querySelectorAll('button, input[type=submit], input[type=button]').forEach(b => {
                          const t = ((b.innerText || b.textContent || b.value || '')+'').toLowerCase();
                          if (t.includes('deny') || t.includes('cancel') || t.includes('reject')) {
                            b.setAttribute('disabled', 'true');
                            b.style.pointerEvents = 'none';
                          }
                        });
                      });
                    }""")
                except Exception:
                    pass

                # Consent: hydrate, then REAL Playwright Allow first (correct button value).
                # explicit_allow only if native click did not navigate to approve/done.
                href_pre = page.url or ""
                if "/consent" in href_pre or "/approve" in href_pre:
                    if ticks <= 3:
                        try:
                            await page.get_by_role("button", name="Allow", exact=True).wait_for(state="visible", timeout=6000)
                        except Exception:
                            pass
                        if ticks == 1:
                            await asyncio.sleep(1.8)
                            print(f"consent_hydrate tick={ticks} href={href_pre[:120]}", file=sys.stderr)
                            try:
                                dumps = await page.evaluate(
                                    """() => Array.from(document.querySelectorAll('form')).slice(0,3).map(f => ({
                                      action: (f.getAttribute('action')||'').slice(0,80),
                                      fields: Array.from(f.elements).slice(0,12).map(el => ({
                                        name: el.name||'', type: el.type||'',
                                        value: ((el.value||'')+'').slice(0,40),
                                        text: ((el.innerText||el.textContent||'')+'').trim().slice(0,30)
                                      }))
                                    }))"""
                                )
                                print(f"forms_dump {json.dumps(dumps, ensure_ascii=False)[:500]}", file=sys.stderr)
                            except Exception as e:
                                print(f"forms_dump err: {e}", file=sys.stderr)
                        # Native Allow gesture first
                        try:
                            native = await playwright_click_allow_or_continue(page)
                            if native and not is_cookie_banner_label(native) and "allow" in native.lower():
                                last_click = native
                                print(f"native_allow[{ticks}] {native!r}", file=sys.stderr)
                                try:
                                    await page.wait_for_load_state("domcontentloaded", timeout=8000)
                                except Exception:
                                    pass
                                await asyncio.sleep(1.2)
                        except Exception as e:
                            print(f"native_allow err: {e}", file=sys.stderr)
                    # Fallback explicit form only if still on consent
                    href_mid = page.url or ""
                    if ("/consent" in href_mid or "/approve" in href_mid) and not any("done" in h for h in hit_paths[-6:]):
                        try:
                            ex = await explicit_allow_on_consent(page, user_code, principal)
                            if ex:
                                last_click = ex
                                print(f"explicit_allow[{ticks}] {ex!r}", file=sys.stderr)
                                try:
                                    await page.wait_for_load_state("domcontentloaded", timeout=8000)
                                except Exception:
                                    pass
                                await asyncio.sleep(1.2)
                        except Exception as e:
                            print(f"explicit_allow err: {e}", file=sys.stderr)

                clicked = ""
                skip_click = False
                low_last = (last_click or "").lower()
                if (
                    ("allow" in low_last or "explicit" in low_last or "authorize" in low_last or "approve" in low_last)
                    and not is_cookie_banner_label(last_click or "")
                    and any(("approve" in h) or ("done" in h) for h in hit_paths[-8:])
                ):
                    skip_click = True
                    print(f"skip_post_allow_click last={last_click!r}", file=sys.stderr)
                if not skip_click:
                    try:
                        clicked = await playwright_click_allow_or_continue(page)
                    except Exception as e:
                        print(f"pw click err: {e}", file=sys.stderr)
                        clicked = ""
                    if not clicked:
                        try:
                            clicked = await page.evaluate(CLICK_JS)
                        except Exception as e:
                            print(f"click eval err: {e}", file=sys.stderr)
                            clicked = ""
                    # Never accept cookie banner as an OAuth click success
                    if clicked and is_cookie_banner_label(clicked):
                        print(f"ignore_cookie_click {clicked!r}", file=sys.stderr)
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

                # Status FIRST — never re-approve after /done (re-POST poisons device_code → invalid_grant).
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
                allowed_click = ("allow" in (last_click or "").lower()) and not click_was_deny(last_click)

                if done:
                    err_q = (st or {}).get("errQ") or ""
                    print(f"ui_success href={href[:160]} last_click={last_click!r} api_bound={api_bound} errQ={err_q!r} sample={((st or {}).get('sample') or '')[:120]!r}", file=sys.stderr)
                    if hit_paths:
                        print(f"net_hits {hit_paths[-8:]}", file=sys.stderr)
                    if err_q or (st or {}).get("denied"):
                        print(f"ui_denied_on_done errQ={err_q!r}", file=sys.stderr)
                        return 1
                    # Token is the only success — never fake ok on UI done alone.
                    print("token_poll waiting 2.5s after allow/done...", file=sys.stderr)
                    time.sleep(2.5)
                    tok = poll_device_token(device_code, token_url, client_id, proxy, attempts=15)
                    if tok and tok.get("access_token"):
                        print("TOKEN_JSON:" + json.dumps(tok, ensure_ascii=False))
                        print("ok")
                        return 0
                    print("ui_done_no_token — refusing fake ok", file=sys.stderr)
                    return 2

                # api_auth ONLY if stuck on consent with no Allow yet — never after Allow/done.
                if (
                    user_code
                    and on_consent
                    and not allowed_click
                    and not done
                    and api_attempts < 3
                    and ticks >= 6
                    and ticks % 4 == 0
                ):
                    api_attempts += 1
                    try:
                        results = await page.evaluate(API_AUTH_JS, {"userCode": user_code, "principalId": principal})
                        print(f"api_auth[{api_attempts}] {json.dumps(results, ensure_ascii=False)[:320]}", file=sys.stderr)
                        for row in results or []:
                            if isinstance(row, dict) and row.get("step") == "approve" and row.get("okish"):
                                api_bound = True
                    except Exception as e:
                        print(f"api_auth err: {e}", file=sys.stderr)

                if api_bound and not click_was_deny(last_click):
                    print(f"api_bound success last_click={last_click!r}", file=sys.stderr)
                    print("token_poll waiting 2.5s after allow/done...", file=sys.stderr)
                    time.sleep(2.5)
                    tok = poll_device_token(device_code, token_url, client_id, proxy, attempts=15)
                    if tok and tok.get("access_token"):
                        print("TOKEN_JSON:" + json.dumps(tok, ensure_ascii=False))
                        print("ok")
                        return 0
                    print("api_bound_no_token — refusing fake ok", file=sys.stderr)
                    return 2

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
                    print("timeout_ui_done_without_token_poll — fail", file=sys.stderr)
                    return 2
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
                print("timeout_good_net_no_token — fail", file=sys.stderr)
                return 2
            return 1
        finally:
            await browser.close()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True)
    ap.add_argument("--sso", required=True)
    ap.add_argument("--user-code", default="")
    ap.add_argument("--device-code", default="")
    ap.add_argument("--token-url", default="")
    ap.add_argument("--client-id", default="")
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
                device_code=(args.device_code or "").strip(),
                token_url=(args.token_url or "").strip(),
                client_id=(args.client_id or "").strip(),
            )
        )
    except Exception as e:
        print(f"device_auth crashed: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())