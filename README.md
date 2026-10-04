# dns-email-auth

[![MCPize](https://mcpize.com/badge/@mcpize/mcpize?type=hosted)](https://mcpize.com)

Live DNS email-authentication diagnostics MCP server. Fetches and analyzes a
domain's real, current records — no API key needed.

## What it does

- **SPF analysis** — parses the live SPF record, follows `include:`/`redirect=`
  chains, and counts DNS-querying mechanisms against RFC 7208's 10-lookup
  limit. Flags `+all`, multiple records, deprecated `ptr`, and missing
  default `all`.
- **DMARC analysis** — reads `_dmarc.<domain>`, reports the enforcement
  policy, subdomain policy, `pct`, DKIM/SPF alignment modes, and issues
  (`p=none` monitoring-only, missing `rua` report mailbox).
- **MX analysis** — MX records sorted by priority, null-MX (`0 .`, RFC 7505)
  detection, single-MX redundancy warning.
- **Domain health** — RDAP registration expiry (days remaining), DNSSEC
  DS-record presence, authoritative nameserver list with redundancy check.

Every tool validates input with Zod (protocol/paths stripped, hostname
syntax checked, helpful errors for garbage input), never crashes on
NXDOMAIN/timeouts (returns structured `issues` instead), caches results for
5 minutes, and enforces the free-tier quota (50 checks/day, env
`FREE_DAILY_LIMIT`).

## Tools

| Tool | Input | Output |
|------|-------|--------|
| `check_spf` | `domain` | `{domain, record, valid, lookup_count, exceeds_10_lookup_limit, issues}` |
| `check_dmarc` | `domain` | `{domain, record, valid, policy, subdomain_policy, pct, alignment: {dkim, spf}, issues}` |
| `check_mx` | `domain` | `{domain, mx_records: [{exchange, priority}], has_fallback, count, issues}` |
| `domain_health` | `domain` | `{domain, rdap_expiry, days_to_expiry, dnssec_ds_present, nameservers, ns_count_ok, issues}` |

## Data sources

- DNS: DNS-over-HTTPS JSON API — primary `https://cloudflare-dns.com/dns-query`
  (`Accept: application/dns-json`), fallback `https://dns.google/resolve`.
  Verified live on 2026-10-04.
- Registration expiry: `https://rdap.org/domain/<domain>` (follows the 302 to
  the registry RDAP server; sends a browser-compatible User-Agent because
  rdap.org's CDN returns 403 to the default Node UA).

## Limitations (read before relying on results)

- **DNSSEC is DS-presence only.** We report whether the parent publishes a DS
  record — we do NOT cryptographically validate the zone's signatures.
- **RDAP is best-effort.** rdap.org/registry servers can time out or rate-limit;
  on failure the tool returns `rdap_expiry: null` plus an `issues` note instead
  of failing the whole call.
- **SPF chain-following is capped** at depth 12 to prevent infinite loops from
  pathological `include:`/`redirect=` cycles; lookup counts may undercount
  deeper chains (reported in `issues` when the cap is hit).
- Lookup counting covers RFC 7208 §10.1 DNS-querying mechanisms
  (`include`, `a`, `mx`, `ptr`, `exists`, `redirect`, `exp`) and nested includes;
  macro expansion is not evaluated.
- Results are cached in memory for 5 minutes (`cached: true` marks hits).

## Quick Start

```bash
npm install
npm run dev     # Start with hot reload (http://localhost:8080/mcp)
```

## Development

```bash
npm run dev          # Development mode with hot reload
npm run build        # Compile TypeScript
npm test             # Run unit tests (vitest; includes live-DNS tests)
bash test-mcp.sh     # MCP protocol smoke test (server must be running)
npm start            # Run compiled server
```

## Project Structure

```
├── src/
│   ├── index.ts        # Express + MCP server, freemium quota, tool registration
│   └── tools.ts        # Pure tool functions (testable): DoH client, SPF/DMARC/MX parsers, RDAP
├── tests/
│   └── tools.test.ts   # Unit tests: mocked-DNS parsing + live google.com checks
├── test-mcp.sh         # MCP protocol smoke test
├── pricing.json        # Free/Pro plans + x402 pricing
├── seo.json            # Marketplace title/description/tags
├── mcpize.yaml         # MCPize deployment manifest
└── package.json        # Dependencies and scripts
```

## Deployment

```bash
mcpize deploy
mcpize publish
```

No secrets or credentials needed — the server is fully keyless.

## License

MIT
