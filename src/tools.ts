/**
 * dns-email-auth — pure tool logic (no MCP dependency, unit-testable).
 *
 * Live DNS lookups via DNS-over-HTTPS (Cloudflare primary, Google fallback),
 * RDAP domain-expiry lookups via rdap.org, and a DS-record presence check
 * for DNSSEC. All network calls have a 10s timeout; every failure path
 * returns structured issues instead of throwing.
 */

const FETCH_TIMEOUT_MS = 10_000;
const CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes
const SPF_CHAIN_CAP = 12;

// ============================================================================
// In-memory TTL cache
// ============================================================================

interface CacheEntry {
  expires: number;
  value: Record<string, unknown>;
}

const cache = new Map<string, CacheEntry>();

function getCached(key: string): Record<string, unknown> | undefined {
  const entry = cache.get(key);
  if (!entry) return undefined;
  if (Date.now() > entry.expires) {
    cache.delete(key);
    return undefined;
  }
  return { ...entry.value, cached: true };
}

function setCached(key: string, value: Record<string, unknown>): void {
  cache.set(key, { expires: Date.now() + CACHE_TTL_MS, value });
}

/** Test helper: drop all cached entries. */
export function clearToolCache(): void {
  cache.clear();
}

// ============================================================================
// Domain validation
// ============================================================================

export interface NormalizedDomain {
  ok: boolean;
  domain: string;
  error?: string;
}

const HOSTNAME_RE =
  /^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))*\.([a-z]{2,63}|xn--[a-z0-9-]{2,59})$/;

export function normalizeDomain(raw: unknown): NormalizedDomain {
  if (typeof raw !== "string") {
    return { ok: false, domain: "", error: "Domain must be a string, e.g. \"google.com\"." };
  }
  let d = raw.trim().toLowerCase();
  d = d.replace(/^[a-z][a-z0-9+.-]*:\/\//, ""); // strip scheme (https:// etc.)
  d = d.split("/")[0].split("?")[0].split("#")[0].trim(); // strip path/query/fragment
  if (d.includes("@")) {
    return {
      ok: false,
      domain: "",
      error: `Domain "${raw}" looks like an email address. Use just the domain part (e.g. "example.com").`,
    };
  }
  d = d.replace(/\.$/, ""); // trailing dot
  if (!d) {
    return { ok: false, domain: "", error: "Empty domain. Provide a bare domain like \"google.com\"." };
  }
  if (/[^\x00-\x7f]/.test(d)) {
    return {
      ok: false,
      domain: "",
      error: `Domain "${raw}" contains non-ASCII characters. Convert internationalized domains to punycode (e.g. "xn--...") first.`,
    };
  }
  if (!HOSTNAME_RE.test(d)) {
    return {
      ok: false,
      domain: "",
      error: `Domain "${raw}" is not a valid hostname. Use a bare domain like "example.com" (no protocol, port, or email address).`,
    };
  }
  return { ok: true, domain: d };
}

// ============================================================================
// DNS-over-HTTPS client (Cloudflare primary, Google fallback)
// ============================================================================

interface DohAnswer {
  name: string;
  type: number;
  TTL: number;
  data: string;
}

interface DohResult {
  status: number; // 0 = NOERROR, 3 = NXDOMAIN
  answers: DohAnswer[];
}

async function dohQuery(name: string, type: string): Promise<DohResult> {
  const endpoints = [
    `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${type}`,
    `https://dns.google/resolve?name=${encodeURIComponent(name)}&type=${type}`,
  ];
  let lastError: unknown;
  for (const url of endpoints) {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), FETCH_TIMEOUT_MS);
    try {
      const res = await fetch(url, {
        headers: { Accept: "application/dns-json" },
        signal: ctrl.signal,
      });
      if (!res.ok) throw new Error(`HTTP ${res.status} from ${new URL(url).host}`);
      const body = (await res.json()) as { Status?: number; Answer?: DohAnswer[] };
      return { status: body.Status ?? -1, answers: body.Answer ?? [] };
    } catch (err) {
      lastError = err;
    } finally {
      clearTimeout(timer);
    }
  }
  throw lastError instanceof Error ? lastError : new Error("DNS-over-HTTPS lookup failed");
}

/**
 * Decode a DNS TXT rdata string from DoH JSON.
 * Cloudflare renders each character-string quoted, e.g. "\"v=spf1 ...\"";
 * long records arrive as multiple quoted chunks that must be joined.
 */
export function decodeTxtRdata(data: string): string {
  const trimmed = data.trim();
  if (!trimmed.startsWith('"')) return trimmed;
  const parts: string[] = [];
  const re = /"((?:[^"\\]|\\.)*)"/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(trimmed)) !== null) parts.push(m[1]);
  return parts.length ? parts.join("") : trimmed;
}

function stripDot(s: string): string {
  return s.endsWith(".") ? s.slice(0, -1) : s;
}

// ============================================================================
// Tool result interfaces (index signature required for structuredContent)
// ============================================================================

export interface SpfCheckResult {
  [key: string]: unknown;
  domain: string;
  record: string | null;
  valid: boolean;
  lookup_count: number;
  exceeds_10_lookup_limit: boolean;
  issues: string[];
}

export interface DmarcCheckResult {
  [key: string]: unknown;
  domain: string;
  record: string | null;
  valid: boolean;
  policy: string | null;
  subdomain_policy: string | null;
  pct: number | null;
  alignment: { dkim: string; spf: string };
  issues: string[];
}

export interface MxCheckResult {
  [key: string]: unknown;
  domain: string;
  mx_records: { exchange: string; priority: number }[];
  has_fallback: boolean;
  count: number;
  issues: string[];
}

export interface DomainHealthResult {
  [key: string]: unknown;
  domain: string;
  rdap_expiry: string | null;
  days_to_expiry: number | null;
  dnssec_ds_present: boolean;
  nameservers: string[];
  ns_count_ok: boolean;
  issues: string[];
}

// ============================================================================
// check_spf
// ============================================================================

interface SpfTerm {
  qualifier: string;
  mechanism: string;
  value: string;
  raw: string;
}

/** Mechanisms/modifiers that count against RFC 7208's 10-DNS-lookup limit. */
const SPF_LOOKUP_TERMS = new Set(["include", "a", "mx", "ptr", "exists", "redirect", "exp"]);

function parseSpfTerm(token: string): SpfTerm | null {
  const m = token.match(/^([+\-~?])?([a-zA-Z][a-zA-Z0-9-]*)([:=].*)?$/);
  if (!m) return null;
  return {
    qualifier: m[1] ?? "+",
    mechanism: m[2].toLowerCase(),
    value: (m[3] ?? "").replace(/^[:=]/, ""),
    raw: token,
  };
}

interface SpfWalk {
  count: number;
  capped: boolean;
}

/** Recursively count DNS-querying mechanisms, following include:/redirect= chains. */
async function walkSpf(domain: string, visited: Set<string>, depth: number): Promise<SpfWalk> {
  if (depth >= SPF_CHAIN_CAP) return { count: 0, capped: true };
  if (visited.has(domain)) return { count: 0, capped: false };
  visited.add(domain);

  let records: string[];
  try {
    const res = await dohQuery(domain, "TXT");
    if (res.status === 3) return { count: 0, capped: false };
    records = res.answers
      .map((a) => decodeTxtRdata(a.data))
      .filter((t) => t.toLowerCase().startsWith("v=spf1"));
  } catch {
    return { count: 0, capped: false }; // transient DNS failure: count what we can
  }
  if (records.length === 0) return { count: 0, capped: false };
  return countLookupsInRecord(records[0], visited, depth);
}

/** Count DNS-querying terms in an already-fetched SPF record, recursing into chains. */
async function countLookupsInRecord(
  record: string,
  visited: Set<string>,
  depth: number
): Promise<SpfWalk> {
  let count = 0;
  let capped = false;
  for (const token of record.trim().split(/\s+/)) {
    if (/^v=spf1$/i.test(token)) continue;
    const term = parseSpfTerm(token);
    if (!term) continue;
    if (!SPF_LOOKUP_TERMS.has(term.mechanism)) continue;
    count += 1; // this mechanism/modifier causes a DNS query
    if (term.mechanism === "include" || term.mechanism === "redirect") {
      const target = term.value.split("/")[0];
      if (target) {
        const nested = await walkSpf(target, visited, depth + 1);
        count += nested.count;
        if (nested.capped) capped = true;
      }
    }
  }
  return { count, capped };
}

function spfEmpty(domain: string, issues: string[]): SpfCheckResult {
  return { domain, record: null, valid: false, lookup_count: 0, exceeds_10_lookup_limit: false, issues };
}

export async function checkSpf(rawDomain: string): Promise<SpfCheckResult> {
  const norm = normalizeDomain(rawDomain);
  if (!norm.ok) {
    return spfEmpty(String(rawDomain ?? ""), [`Invalid domain: ${norm.error}`]);
  }
  const domain = norm.domain;
  const cacheKey = `check_spf:${domain}`;
  const hit = getCached(cacheKey);
  if (hit) return hit as unknown as SpfCheckResult;

  let res: DohResult;
  try {
    res = await dohQuery(domain, "TXT");
  } catch (err) {
    return spfEmpty(domain, [
      `DNS lookup failed for ${domain}: ${err instanceof Error ? err.message : String(err)}. Check connectivity and try again.`,
    ]);
  }
  if (res.status === 3) {
    return spfEmpty(domain, [`Domain ${domain} does not resolve (NXDOMAIN) — no SPF record can exist.`]);
  }

  const records = res.answers
    .map((a) => decodeTxtRdata(a.data))
    .filter((t) => t.toLowerCase().startsWith("v=spf1"));

  if (records.length === 0) {
    const r = spfEmpty(domain, [
      `No SPF record published for ${domain}. Without SPF, any mail server can claim to send as this domain.`,
    ]);
    setCached(cacheKey, r);
    return r;
  }

  const issues: string[] = [];
  let valid = true;
  const record = records[0];

  if (records.length > 1) {
    valid = false;
    issues.push(
      `Multiple SPF records published (${records.length}) — RFC 7208 allows at most one per domain. Receivers will return "permerror" and the policy is unenforceable.`
    );
  }

  // Reuse the already-fetched record for the root domain (avoids a duplicate
  // TXT query); walkSpf fetches only the chained include:/redirect= targets.
  const walk = await countLookupsInRecord(record, new Set([domain]), 0);
  const lookupCount = walk.count;
  const exceeds = lookupCount > 10;
  if (exceeds) {
    valid = false;
    issues.push(
      `SPF causes ~${lookupCount} DNS lookups, exceeding RFC 7208's 10-lookup limit. Receivers will return "permerror" and fail evaluation — flatten includes or remove unused mechanisms.`
    );
  }
  if (walk.capped) {
    issues.push(
      `include:/redirect= chain-following was capped at depth ${SPF_CHAIN_CAP}; the reported lookup count may undercount deeply nested chains.`
    );
  }

  // Inspect top-level terms for common misconfigurations.
  const terms = record
    .trim()
    .split(/\s+/)
    .map(parseSpfTerm)
    .filter((t): t is SpfTerm => t !== null);
  const allTerm = terms.find((t) => t.mechanism === "all");
  if (!allTerm) {
    issues.push('SPF record has no default "all" mechanism — evaluation falls back to "neutral" for unmatched senders.');
  } else if (allTerm.qualifier === "+") {
    valid = false;
    issues.push('SPF ends in "+all" (pass) — this authorizes ANY sender on the internet. Use "~all" or "-all" instead.');
  } else if (allTerm.qualifier === "?") {
    issues.push('SPF ends in "?all" (neutral) — offers no spoofing protection. Consider "~all" or "-all".');
  }
  if (terms.some((t) => t.mechanism === "ptr")) {
    issues.push('The "ptr" mechanism is deprecated by RFC 7208 (slow, unreliable) — remove it.');
  }

  const result: SpfCheckResult = {
    domain,
    record,
    valid,
    lookup_count: lookupCount,
    exceeds_10_lookup_limit: exceeds,
    issues,
  };
  setCached(cacheKey, result);
  return result;
}

// ============================================================================
// check_dmarc
// ============================================================================

function dmarcEmpty(domain: string, issues: string[]): DmarcCheckResult {
  return {
    domain,
    record: null,
    valid: false,
    policy: null,
    subdomain_policy: null,
    pct: null,
    alignment: { dkim: "r", spf: "r" },
    issues,
  };
}

export async function checkDmarc(rawDomain: string): Promise<DmarcCheckResult> {
  const norm = normalizeDomain(rawDomain);
  if (!norm.ok) {
    return dmarcEmpty(String(rawDomain ?? ""), [`Invalid domain: ${norm.error}`]);
  }
  const domain = norm.domain;
  const dmarcHost = `_dmarc.${domain}`;
  const cacheKey = `check_dmarc:${domain}`;
  const hit = getCached(cacheKey);
  if (hit) return hit as unknown as DmarcCheckResult;

  let res: DohResult;
  try {
    res = await dohQuery(dmarcHost, "TXT");
  } catch (err) {
    return dmarcEmpty(domain, [
      `DNS lookup failed for ${dmarcHost}: ${err instanceof Error ? err.message : String(err)}. Check connectivity and try again.`,
    ]);
  }
  if (res.status === 3) {
    const r = dmarcEmpty(domain, [
      `No DMARC record published at ${dmarcHost}. Without DMARC, receivers cannot enforce SPF/DKIM alignment — the domain is exposed to exact-domain spoofing.`,
    ]);
    setCached(cacheKey, r);
    return r;
  }

  const records = res.answers
    .map((a) => decodeTxtRdata(a.data))
    .filter((t) => t.toLowerCase().startsWith("v=dmarc1"));

  if (records.length === 0) {
    const r = dmarcEmpty(domain, [
      `No DMARC record published at ${dmarcHost} (TXT records exist, but none start with "v=DMARC1").`,
    ]);
    setCached(cacheKey, r);
    return r;
  }

  const record = records[0];
  const issues: string[] = [];
  let valid = true;
  if (records.length > 1) {
    valid = false;
    issues.push(`Multiple DMARC records at ${dmarcHost} (${records.length}) — RFC 7489 allows at most one.`);
  }

  const tags = new Map<string, string>();
  for (const part of record.split(";")) {
    const eq = part.indexOf("=");
    if (eq === -1) continue;
    tags.set(part.slice(0, eq).trim().toLowerCase(), part.slice(eq + 1).trim());
  }

  const policy = tags.get("p")?.toLowerCase() ?? null;
  const subdomainPolicy = tags.get("sp")?.toLowerCase() ?? null;
  const pctRaw = tags.get("pct");
  let pct: number | null = null;
  if (pctRaw !== undefined) {
    const n = parseInt(pctRaw, 10);
    pct = Number.isFinite(n) ? Math.min(100, Math.max(0, n)) : null;
  }

  if (!policy || !["none", "quarantine", "reject"].includes(policy)) {
    valid = false;
    issues.push(
      `DMARC policy tag "p" is missing or invalid ("${tags.get("p") ?? "absent"}") — must be one of none, quarantine, reject.`
    );
  } else if (policy === "none") {
    issues.push(
      'DMARC policy is "none" (monitoring only) — no enforcement against spoofed mail. Move to "quarantine" or "reject" once aggregate reports look clean.'
    );
  }
  if (!subdomainPolicy) {
    issues.push('No subdomain policy ("sp" tag) — subdomains inherit the organizational policy, which may be unintentional.');
  }
  if (pct !== null && pct < 100) {
    issues.push(`"pct=${pct}" — the policy applies to only ${pct}% of failing mail; the rest is unaffected.`);
  }
  if (!tags.get("rua")) {
    issues.push('No aggregate report mailbox ("rua" tag) — you will receive no DMARC feedback reports.');
  }

  const result: DmarcCheckResult = {
    domain,
    record,
    valid,
    policy,
    subdomain_policy: subdomainPolicy,
    pct,
    alignment: {
      dkim: tags.get("adkim")?.toLowerCase() ?? "r",
      spf: tags.get("aspf")?.toLowerCase() ?? "r",
    },
    issues,
  };
  setCached(cacheKey, result);
  return result;
}

// ============================================================================
// check_mx
// ============================================================================

function mxEmpty(domain: string, issues: string[]): MxCheckResult {
  return { domain, mx_records: [], has_fallback: false, count: 0, issues };
}

export async function checkMx(rawDomain: string): Promise<MxCheckResult> {
  const norm = normalizeDomain(rawDomain);
  if (!norm.ok) {
    return mxEmpty(String(rawDomain ?? ""), [`Invalid domain: ${norm.error}`]);
  }
  const domain = norm.domain;
  const cacheKey = `check_mx:${domain}`;
  const hit = getCached(cacheKey);
  if (hit) return hit as unknown as MxCheckResult;

  let res: DohResult;
  try {
    res = await dohQuery(domain, "MX");
  } catch (err) {
    return mxEmpty(domain, [
      `DNS lookup failed for ${domain}: ${err instanceof Error ? err.message : String(err)}. Check connectivity and try again.`,
    ]);
  }
  if (res.status === 3) {
    return mxEmpty(domain, [`Domain ${domain} does not resolve (NXDOMAIN) — no MX records can exist.`]);
  }

  const issues: string[] = [];
  const records = res.answers
    .map((a) => {
      const m = a.data.trim().match(/^(\d+)\s+(.+)$/);
      if (!m) return null;
      return { exchange: stripDot(m[2].trim()), priority: parseInt(m[1], 10) };
    })
    .filter((r): r is { exchange: string; priority: number } => r !== null)
    .sort((x, y) => x.priority - y.priority);

  const hasFallback = records.some((r) => r.priority === 0 && (r.exchange === "" || r.exchange === "."));

  if (records.length === 0) {
    issues.push(
      `No MX records for ${domain} — the domain cannot receive email directly (senders would fall back to the A/AAAA record, if any).`
    );
  } else if (hasFallback) {
    issues.push(
      'Null MX published ("0 .") — the domain explicitly declares it accepts NO mail (RFC 7505). Correct for non-mail domains; a problem if you expect inbound mail.'
    );
  } else if (records.length === 1) {
    issues.push("Only one MX record — no backup mail exchanger if the primary is unreachable.");
  }

  const result: MxCheckResult = {
    domain,
    mx_records: records,
    has_fallback: hasFallback,
    count: records.length,
    issues,
  };
  setCached(cacheKey, result);
  return result;
}

// ============================================================================
// domain_health
// ============================================================================

interface RdapResult {
  expiry: string | null;
  issue: string | null;
}

async function fetchRdapExpiry(domain: string): Promise<RdapResult> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), FETCH_TIMEOUT_MS);
  try {
    // rdap.org redirects (302) to the authoritative registry RDAP server; fetch follows.
    // NOTE: rdap.org's CDN rejects the default "node" user-agent with HTTP 403,
    // so we send a browser-compatible UA (public RDAP data, no auth involved).
    const res = await fetch(`https://rdap.org/domain/${encodeURIComponent(domain)}`, {
      headers: {
        Accept: "application/rdap+json",
        "User-Agent": "Mozilla/5.0 (compatible; dns-email-auth/1.0)",
      },
      signal: ctrl.signal,
    });
    if (!res.ok) {
      return {
        expiry: null,
        issue: `RDAP lookup returned HTTP ${res.status} for ${domain} — expiry unknown (best effort; try again later).`,
      };
    }
    const body = (await res.json()) as { events?: { eventAction?: string; eventDate?: string }[] };
    const exp = (body.events ?? []).find(
      (e) => typeof e?.eventAction === "string" && e.eventAction.toLowerCase() === "expiration"
    );
    if (!exp?.eventDate || Number.isNaN(Date.parse(exp.eventDate))) {
      return {
        expiry: null,
        issue: `RDAP responded for ${domain} but carried no parseable expiration event — expiry unknown (best effort).`,
      };
    }
    return { expiry: exp.eventDate, issue: null };
  } catch (err) {
    return {
      expiry: null,
      issue: `RDAP lookup failed for ${domain}: ${err instanceof Error ? err.message : String(err)} — expiry unknown (best effort).`,
    };
  } finally {
    clearTimeout(timer);
  }
}

export async function domainHealth(rawDomain: string): Promise<DomainHealthResult> {
  const norm = normalizeDomain(rawDomain);
  if (!norm.ok) {
    return {
      domain: String(rawDomain ?? ""),
      rdap_expiry: null,
      days_to_expiry: null,
      dnssec_ds_present: false,
      nameservers: [],
      ns_count_ok: false,
      issues: [`Invalid domain: ${norm.error}`],
    };
  }
  const domain = norm.domain;
  const cacheKey = `domain_health:${domain}`;
  const hit = getCached(cacheKey);
  if (hit) return hit as unknown as DomainHealthResult;

  const issues: string[] = [];

  const [rdap, nsRes, dsRes] = await Promise.all([
    fetchRdapExpiry(domain),
    dohQuery(domain, "NS").catch((err: unknown) => ({
      status: -1 as number,
      answers: [] as DohAnswer[],
      __error: err instanceof Error ? err.message : String(err),
    })),
    dohQuery(domain, "DS").catch(() => ({ status: -1 as number, answers: [] as DohAnswer[] })),
  ]);

  if (rdap.issue) issues.push(rdap.issue);

  let daysToExpiry: number | null = null;
  if (rdap.expiry) {
    const diffMs = Date.parse(rdap.expiry) - Date.now();
    daysToExpiry = Math.round(diffMs / 86_400_000);
    if (daysToExpiry < 0) {
      issues.push(`Domain expired ${Math.abs(daysToExpiry)} day(s) ago (${rdap.expiry}). Renew immediately.`);
    } else if (daysToExpiry <= 30) {
      issues.push(`Domain expires in ${daysToExpiry} day(s) (${rdap.expiry}) — renew soon to avoid lapse.`);
    }
  }

  const nsAnswers = "answers" in nsRes ? (nsRes as DohResult).answers : [];
  const nameservers = nsAnswers.map((a) => stripDot(a.data.trim())).filter(Boolean);
  const nsCountOk = nameservers.length >= 2;
  if ("__error" in nsRes) {
    issues.push(`Nameserver lookup failed for ${domain}: ${(nsRes as { __error: string }).__error}.`);
  } else if (nameservers.length === 0) {
    issues.push(`No nameservers returned for ${domain} — the domain may not be delegated or may not exist.`);
  } else if (nameservers.length < 2) {
    issues.push(`Only ${nameservers.length} nameserver(s) — best practice is at least 2 for redundancy.`);
  }

  const dsPresent = (dsRes as DohResult).answers.length > 0;
  if (!dsPresent) {
    issues.push(
      "No DS record found — DNSSEC is not enabled for this domain. (Presence check only: a DS record shows the parent delegates a trust anchor; it does not cryptographically validate the zone.)"
    );
  }

  const result: DomainHealthResult = {
    domain,
    rdap_expiry: rdap.expiry,
    days_to_expiry: daysToExpiry,
    dnssec_ds_present: dsPresent,
    nameservers,
    ns_count_ok: nsCountOk,
    issues,
  };
  setCached(cacheKey, result);
  return result;
}
