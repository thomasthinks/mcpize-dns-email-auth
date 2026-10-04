import { describe, it, expect, vi, beforeEach, beforeAll } from "vitest";
import {
  checkSpf,
  checkDmarc,
  checkMx,
  domainHealth,
  normalizeDomain,
  decodeTxtRdata,
  clearToolCache,
} from "../src/tools.js";

// ============================================================================
// Mock fetch helper (routes by DoH query params)
// ============================================================================

type DohMock = Record<string, Record<string, { status: number; answers: { name: string; type: number; TTL: number; data: string }[] }>>;

type RdapBehavior =
  | { mode: "ok"; body: unknown }
  | { mode: "http"; status: number }
  | { mode: "throw"; message: string };

function mockFetchWith(map: DohMock, rdap?: RdapBehavior) {
  const seen: string[] = [];
  const mock = vi.fn().mockImplementation(async (url: string) => {
    seen.push(url);
    if (url.startsWith("https://rdap.org/")) {
      if (!rdap) throw new Error("RDAP not mocked");
      if (rdap.mode === "throw") throw new Error(rdap.message);
      if (rdap.mode === "http") return { ok: false, status: rdap.status };
      return { ok: true, json: async () => rdap.body };
    }
    const u = new URL(url);
    const name = u.searchParams.get("name") ?? "";
    const type = u.searchParams.get("type") ?? "";
    const entry = map[name]?.[type];
    if (!entry) {
      return { ok: true, json: async () => ({ Status: 0, Answer: [] }) };
    }
    return { ok: true, json: async () => ({ Status: entry.status, Answer: entry.answers }) };
  });
  vi.stubGlobal("fetch", mock);
  return { mock, seen };
}

function txtAnswer(name: string, ...records: string[]) {
  return {
    status: 0,
    answers: records.map((r) => ({ name, type: 16, TTL: 300, data: `"${r}"` })),
  };
}

beforeEach(() => {
  clearToolCache();
  vi.unstubAllGlobals();
});

// ============================================================================
// normalizeDomain
// ============================================================================

describe("normalizeDomain", () => {
  it("accepts a plain domain", () => {
    expect(normalizeDomain("google.com")).toEqual({ ok: true, domain: "google.com" });
  });

  it("strips scheme, path, query, whitespace; lowercases", () => {
    expect(normalizeDomain("  HTTPS://Example.COM/some/page?x=1 ")).toEqual({
      ok: true,
      domain: "example.com",
    });
  });

  it("rejects garbage with a helpful error", () => {
    const r = normalizeDomain("not a domain");
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/not a valid hostname/i);
  });

  it("rejects empty input", () => {
    expect(normalizeDomain("").ok).toBe(false);
  });

  it("rejects non-ASCII with punycode guidance", () => {
    const r = normalizeDomain("münchen.de");
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/punycode/i);
  });

  it("rejects email addresses", () => {
    expect(normalizeDomain("user@example.com").ok).toBe(false);
  });
});

describe("decodeTxtRdata", () => {
  it("joins multi-chunk quoted TXT strings", () => {
    expect(decodeTxtRdata('"part one" "part two"')).toBe("part onepart two");
  });

  it("passes through unquoted data (dns.google shape)", () => {
    expect(decodeTxtRdata("v=spf1 ~all")).toBe("v=spf1 ~all");
  });
});

// ============================================================================
// check_spf (mocked DNS)
// ============================================================================

describe("checkSpf", () => {
  it("parses a valid SPF record with one include chain", async () => {
    mockFetchWith({
      "example.com": { TXT: txtAnswer("example.com", "v=spf1 include:_spf.example.com ~all") },
      "_spf.example.com": { TXT: txtAnswer("_spf.example.com", "v=spf1 ip4:1.2.3.0/24 -all") },
    });
    const r = await checkSpf("example.com");
    expect(r.record).toBe("v=spf1 include:_spf.example.com ~all");
    expect(r.valid).toBe(true);
    expect(r.lookup_count).toBe(1);
    expect(r.exceeds_10_lookup_limit).toBe(false);
    expect(r.issues).toHaveLength(0);
  });

  it("flags >10 lookups across the include chain", async () => {
    const includes = Array.from({ length: 11 }, (_, i) => `include:s${i}.example.com`).join(" ");
    mockFetchWith({
      "example.com": { TXT: txtAnswer("example.com", `v=spf1 ${includes} ~all`) },
      ...Object.fromEntries(
        Array.from({ length: 11 }, (_, i) => [
          `s${i}.example.com`,
          { TXT: txtAnswer(`s${i}.example.com`, "v=spf1 -all") },
        ])
      ),
    });
    const r = await checkSpf("example.com");
    expect(r.lookup_count).toBe(11);
    expect(r.exceeds_10_lookup_limit).toBe(true);
    expect(r.valid).toBe(false);
    expect(r.issues.some((i) => i.includes("10-lookup limit"))).toBe(true);
  });

  it("flags +all as invalid", async () => {
    mockFetchWith({ "example.com": { TXT: txtAnswer("example.com", "v=spf1 +all") } });
    const r = await checkSpf("example.com");
    expect(r.valid).toBe(false);
    expect(r.issues.some((i) => i.includes('"+all"'))).toBe(true);
  });

  it("flags multiple SPF records", async () => {
    mockFetchWith({
      "example.com": {
        TXT: txtAnswer("example.com", "v=spf1 ip4:1.2.3.4 ~all", "v=spf1 include:other.com ~all"),
      },
    });
    const r = await checkSpf("example.com");
    expect(r.valid).toBe(false);
    expect(r.issues.some((i) => i.includes("Multiple SPF records"))).toBe(true);
  });

  it("handles missing SPF record gracefully", async () => {
    mockFetchWith({ "example.com": { TXT: txtAnswer("example.com", "google-site-verification=abc") } });
    const r = await checkSpf("example.com");
    expect(r.record).toBeNull();
    expect(r.valid).toBe(false);
    expect(r.issues.some((i) => i.includes("No SPF record"))).toBe(true);
  });

  it("handles NXDOMAIN gracefully", async () => {
    mockFetchWith({ "nope.example": { TXT: { status: 3, answers: [] } } });
    const r = await checkSpf("nope.example");
    expect(r.record).toBeNull();
    expect(r.valid).toBe(false);
    expect(r.issues.some((i) => i.includes("NXDOMAIN"))).toBe(true);
  });

  it("follows redirect= chains", async () => {
    mockFetchWith({
      "example.com": { TXT: txtAnswer("example.com", "v=spf1 redirect=_spf.example.com") },
      "_spf.example.com": { TXT: txtAnswer("_spf.example.com", "v=spf1 ip4:9.9.9.0/24 -all") },
    });
    const r = await checkSpf("example.com");
    expect(r.lookup_count).toBe(1);
    expect(r.valid).toBe(true);
    expect(r.issues.some((i) => i.includes('no default "all"'))).toBe(true);
  });

  it("rejects garbage input without crashing", async () => {
    const r = await checkSpf("not a domain");
    expect(r.valid).toBe(false);
    expect(r.record).toBeNull();
    expect(r.issues[0]).toMatch(/Invalid domain/);
  });

  it("returns cached:true on repeat calls", async () => {
    const { mock } = mockFetchWith({
      "example.com": { TXT: txtAnswer("example.com", "v=spf1 -all") },
    });
    await checkSpf("example.com");
    const r2 = await checkSpf("example.com");
    expect(r2.cached).toBe(true);
    expect(mock).toHaveBeenCalledTimes(1);
  });
});

// ============================================================================
// check_dmarc (mocked DNS)
// ============================================================================

describe("checkDmarc", () => {
  it("parses a full DMARC record", async () => {
    mockFetchWith({
      "_dmarc.example.com": {
        TXT: txtAnswer(
          "_dmarc.example.com",
          "v=DMARC1; p=reject; sp=quarantine; pct=100; rua=mailto:dmarc@example.com; adkim=s; aspf=s"
        ),
      },
    });
    const r = await checkDmarc("example.com");
    expect(r.record).toContain("v=DMARC1");
    expect(r.valid).toBe(true);
    expect(r.policy).toBe("reject");
    expect(r.subdomain_policy).toBe("quarantine");
    expect(r.pct).toBe(100);
    expect(r.alignment).toEqual({ dkim: "s", spf: "s" });
    expect(r.issues).toHaveLength(0);
  });

  it("flags p=none and missing rua", async () => {
    mockFetchWith({
      "_dmarc.example.com": { TXT: txtAnswer("_dmarc.example.com", "v=DMARC1; p=none") },
    });
    const r = await checkDmarc("example.com");
    expect(r.valid).toBe(true); // syntactically valid, just weak
    expect(r.policy).toBe("none");
    expect(r.alignment).toEqual({ dkim: "r", spf: "r" });
    expect(r.issues.some((i) => i.includes('"none"'))).toBe(true);
    expect(r.issues.some((i) => i.includes("No aggregate report mailbox"))).toBe(true);
    expect(r.issues.some((i) => i.includes('No subdomain policy'))).toBe(true);
  });

  it("handles missing DMARC record gracefully", async () => {
    mockFetchWith({ "_dmarc.example.com": { TXT: { status: 3, answers: [] } } });
    const r = await checkDmarc("example.com");
    expect(r.record).toBeNull();
    expect(r.valid).toBe(false);
    expect(r.policy).toBeNull();
    expect(r.issues.some((i) => i.includes("No DMARC record"))).toBe(true);
  });

  it("rejects garbage input", async () => {
    const r = await checkDmarc("!!!");
    expect(r.valid).toBe(false);
    expect(r.issues[0]).toMatch(/Invalid domain/);
  });
});

// ============================================================================
// check_mx (mocked DNS)
// ============================================================================

describe("checkMx", () => {
  it("parses and sorts MX records by priority", async () => {
    mockFetchWith({
      "example.com": {
        MX: {
          status: 0,
          answers: [
            { name: "example.com", type: 15, TTL: 300, data: "20 mail2.example.com." },
            { name: "example.com", type: 15, TTL: 300, data: "10 mail1.example.com." },
          ],
        },
      },
    });
    const r = await checkMx("example.com");
    expect(r.count).toBe(2);
    expect(r.mx_records).toEqual([
      { exchange: "mail1.example.com", priority: 10 },
      { exchange: "mail2.example.com", priority: 20 },
    ]);
    expect(r.has_fallback).toBe(false);
    expect(r.issues).toHaveLength(0);
  });

  it("detects null MX (0 .)", async () => {
    mockFetchWith({
      "example.com": {
        MX: { status: 0, answers: [{ name: "example.com", type: 15, TTL: 300, data: "0 ." }] },
      },
    });
    const r = await checkMx("example.com");
    expect(r.has_fallback).toBe(true);
    expect(r.issues.some((i) => i.includes("Null MX"))).toBe(true);
  });

  it("warns on a single MX record", async () => {
    mockFetchWith({
      "example.com": {
        MX: { status: 0, answers: [{ name: "example.com", type: 15, TTL: 300, data: "10 mail.example.com." }] },
      },
    });
    const r = await checkMx("example.com");
    expect(r.count).toBe(1);
    expect(r.issues.some((i) => i.includes("Only one MX record"))).toBe(true);
  });

  it("handles no MX records gracefully", async () => {
    mockFetchWith({ "example.com": { MX: { status: 0, answers: [] } } });
    const r = await checkMx("example.com");
    expect(r.count).toBe(0);
    expect(r.issues.some((i) => i.includes("No MX records"))).toBe(true);
  });

  it("rejects garbage input", async () => {
    const r = await checkMx("not a domain");
    expect(r.count).toBe(0);
    expect(r.issues[0]).toMatch(/Invalid domain/);
  });
});

// ============================================================================
// domain_health (mocked)
// ============================================================================

describe("domainHealth", () => {
  it("parses RDAP expiry, NS and DS presence", async () => {
    mockFetchWith(
      {
        "example.com": {
          NS: {
            status: 0,
            answers: [
              { name: "example.com", type: 2, TTL: 300, data: "ns1.example.com." },
              { name: "example.com", type: 2, TTL: 300, data: "ns2.example.com." },
            ],
          },
          DS: { status: 0, answers: [] },
        },
      },
      {
        mode: "ok",
        body: {
          events: [
            { eventAction: "registration", eventDate: "2000-01-01T00:00:00Z" },
            { eventAction: "expiration", eventDate: "2030-06-15T00:00:00Z" },
          ],
        },
      }
    );
    const r = await domainHealth("example.com");
    expect(r.rdap_expiry).toBe("2030-06-15T00:00:00Z");
    expect(r.days_to_expiry).toBeGreaterThan(1000);
    expect(r.dnssec_ds_present).toBe(false);
    expect(r.nameservers).toEqual(["ns1.example.com", "ns2.example.com"]);
    expect(r.ns_count_ok).toBe(true);
    expect(r.issues.some((i) => i.includes("No DS record"))).toBe(true);
  });

  it("survives RDAP failure with null expiry + issue note", async () => {
    mockFetchWith(
      {
        "example.com": {
          NS: { status: 0, answers: [{ name: "example.com", type: 2, TTL: 300, data: "ns1.example.com." }] },
          DS: { status: 0, answers: [] },
        },
      },
      { mode: "throw", message: "connect timeout" }
    );
    const r = await domainHealth("example.com");
    expect(r.rdap_expiry).toBeNull();
    expect(r.days_to_expiry).toBeNull();
    expect(r.issues.some((i) => i.includes("RDAP lookup failed"))).toBe(true);
    expect(r.ns_count_ok).toBe(false); // only 1 NS
  });

  it("rejects garbage input", async () => {
    const r = await domainHealth("not a domain");
    expect(r.rdap_expiry).toBeNull();
    expect(r.issues[0]).toMatch(/Invalid domain/);
  });
});

// ============================================================================
// Live network tests (real DNS/RDAP) — verify against known-good domains
// ============================================================================

describe("live network (google.com)", () => {
  beforeAll(() => {
    vi.unstubAllGlobals();
    clearToolCache();
  });

  it("check_spf returns the real SPF record", async () => {
    const r = await checkSpf("google.com");
    expect(r.record).toContain("v=spf1");
    expect(r.record).toContain("include:_spf.google.com");
    expect(r.valid).toBe(true);
    expect(r.lookup_count).toBeGreaterThanOrEqual(1);
    expect(r.exceeds_10_lookup_limit).toBe(false);
  }, 30000);

  it("check_dmarc returns the real DMARC record", async () => {
    const r = await checkDmarc("google.com");
    expect(r.record).toContain("v=DMARC1");
    expect(r.valid).toBe(true);
    expect(r.policy).toBe("reject");
    expect(r.alignment).toEqual({ dkim: "r", spf: "r" });
  }, 30000);

  it("check_mx returns real MX records", async () => {
    const r = await checkMx("google.com");
    expect(r.count).toBeGreaterThanOrEqual(1);
    expect(r.has_fallback).toBe(false);
    expect(r.mx_records.some((m) => m.exchange.endsWith("google.com"))).toBe(true);
  }, 30000);

  it("domain_health returns real RDAP expiry, NS, DS absence", async () => {
    const r = await domainHealth("google.com");
    expect(r.rdap_expiry).toMatch(/^2028/);
    expect(r.days_to_expiry).toBeGreaterThan(300);
    expect(r.dnssec_ds_present).toBe(false);
    expect(r.nameservers.length).toBeGreaterThanOrEqual(2);
    expect(r.ns_count_ok).toBe(true);
  }, 30000);

  it("nonexistent domain degrades gracefully, never crashes", async () => {
    const [spf, dmarc, mx, health] = await Promise.all([
      checkSpf("this-domain-definitely-does-not-exist-xyz123.com"),
      checkDmarc("this-domain-definitely-does-not-exist-xyz123.com"),
      checkMx("this-domain-definitely-does-not-exist-xyz123.com"),
      domainHealth("this-domain-definitely-does-not-exist-xyz123.com"),
    ]);
    expect(spf.record).toBeNull();
    expect(spf.valid).toBe(false);
    expect(spf.issues.length).toBeGreaterThan(0);
    expect(dmarc.record).toBeNull();
    expect(dmarc.valid).toBe(false);
    expect(mx.count).toBe(0);
    expect(mx.issues.length).toBeGreaterThan(0);
    expect(health.issues.length).toBeGreaterThan(0);
  }, 60000);
});
