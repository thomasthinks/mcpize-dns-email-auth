import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import express, { Request, Response } from "express";
import { z } from "zod";
import chalk from "chalk";
import {
  checkSpf,
  checkDmarc,
  checkMx,
  domainHealth,
  normalizeDomain,
} from "./tools.js";

// ============================================================================
// Dev Logging Utilities
// ============================================================================

const isDev = process.env.NODE_ENV !== "production";

function timestamp(): string {
  return new Date().toLocaleTimeString("en-US", { hour12: false });
}

function formatLatency(ms: number): string {
  if (ms < 100) return chalk.green(`${ms}ms`);
  if (ms < 500) return chalk.yellow(`${ms}ms`);
  return chalk.red(`${ms}ms`);
}

function truncate(str: string, maxLen = 60): string {
  if (str.length <= maxLen) return str;
  return str.slice(0, maxLen - 3) + "...";
}

function logRequest(method: string, params?: unknown): void {
  if (!isDev) return;

  const paramsStr = params ? chalk.gray(` ${truncate(JSON.stringify(params))}`) : "";
  console.log(`${chalk.gray(`[${timestamp()}]`)} ${chalk.cyan("→")} ${method}${paramsStr}`);
}

function logResponse(method: string, result: unknown, latencyMs: number): void {
  if (!isDev) return;

  const latency = formatLatency(latencyMs);

  if (method === "tools/call" && result) {
    const resultStr = typeof result === "string" ? result : JSON.stringify(result);
    console.log(
      `${chalk.gray(`[${timestamp()}]`)} ${chalk.green("←")} ${truncate(resultStr)} ${chalk.gray(`(${latency})`)}`
    );
  } else {
    console.log(`${chalk.gray(`[${timestamp()}]`)} ${chalk.green("✓")} ${method} ${chalk.gray(`(${latency})`)}`);
  }
}

function logError(method: string, error: unknown, latencyMs: number): void {
  const latency = formatLatency(latencyMs);

  let errorMsg: string;
  if (error instanceof Error) {
    errorMsg = error.message;
  } else if (typeof error === "object" && error !== null) {
    const rpcError = error as { message?: string; code?: number };
    errorMsg = rpcError.message || `Error ${rpcError.code || "unknown"}`;
  } else {
    errorMsg = String(error);
  }

  console.log(
    `${chalk.gray(`[${timestamp()}]`)} ${chalk.red("✖")} ${method} ${chalk.red(truncate(errorMsg))} ${chalk.gray(`(${latency})`)}`
  );
}

// ============================================================================
// Freemium usage tracking (in-memory, per UTC day)
// ============================================================================

const FREE_DAILY_LIMIT = parseInt(process.env.FREE_DAILY_LIMIT || "50", 10);
const dailyUsage = new Map<string, number>();

function todayKey(): string {
  return new Date().toISOString().slice(0, 10);
}

function quotaCheck(): string | null {
  const key = todayKey();
  const used = dailyUsage.get(key) ?? 0;
  if (used >= FREE_DAILY_LIMIT) {
    return `Free quota exceeded (${FREE_DAILY_LIMIT}/day). Subscribe to Pro for unlimited access.`;
  }
  dailyUsage.set(key, used + 1);
  return null;
}

function quotaError(message: string) {
  return {
    content: [
      {
        type: "text" as const,
        text: JSON.stringify({
          error: message,
          suggestion: "Your free quota resets at midnight UTC. Subscribe to Pro for unlimited access, or use x402 pay-per-call.",
        }),
      },
    ],
    isError: true as const,
  };
}

// ============================================================================
// MCP Server Setup
// ============================================================================

// Build a FRESH MCP server per request.
//
// In stateless streamable-HTTP mode the MCP SDK allows a Server to be connected
// to exactly ONE transport. Reusing a single module-scope instance throws
// "Already connected to a transport" on the second connection — and Cloud Run
// opens several (startup probe + real requests). So always create a new server
// (and a new transport) inside the request handler below.
function createMcpServer(): McpServer {
  const server = new McpServer({
    name: "dns-email-auth",
    version: "1.0.0",
  });

  // Domain argument: validated with Zod (normalize via transform, then refine).
  const domainArg = z
    .string()
    .min(1)
    .describe(
      'Domain name to check, e.g. "google.com". May include a scheme or path ("https://example.com/page") — these are stripped. Must be a valid hostname; internationalized domains must be given in punycode.'
    )
    .transform((raw) => normalizeDomain(raw));

  function withQuota<T extends Record<string, unknown>>(
    arg: { ok: boolean; domain: string; error?: string },
    run: () => Promise<T>
  ) {
    return async () => {
      if (!arg.ok) {
        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify({
                error: `Invalid domain: ${arg.error}`,
                suggestion:
                  'Provide a bare domain like "example.com" (protocol and paths are stripped automatically).',
              }),
            },
          ],
          isError: true as const,
        };
      }
      const blocked = quotaCheck();
      if (blocked) return quotaError(blocked);
      try {
        const output = await run();
        return {
          content: [{ type: "text" as const, text: JSON.stringify(output) }],
          structuredContent: output,
        };
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        console.error("[dns-email-auth] Unexpected error:", message);
        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify({
                error: `Unexpected error: ${message}`,
                suggestion:
                  "This looks like a transient failure. Try the domain again in a few seconds; if it persists, the upstream DNS/RDAP service may be unavailable.",
              }),
            },
          ],
          isError: true as const,
        };
      }
    };
  }

  server.registerTool(
    "check_spf",
    {
      title: "Check SPF Record",
      description:
        "Fetch and diagnose a domain's SPF record via live DNS. Follows include:/redirect= chains (capped at depth 12) and counts DNS-querying mechanisms against RFC 7208's 10-lookup limit. Reports the raw record, validity, lookup count, and misconfiguration issues (+all, multiple records, deprecated ptr, missing default all).",
      inputSchema: { domain: domainArg },
      outputSchema: {
        domain: z.string(),
        record: z.string().nullable(),
        valid: z.boolean(),
        lookup_count: z.number(),
        exceeds_10_lookup_limit: z.boolean(),
        issues: z.array(z.string()),
        cached: z.boolean().optional(),
      },
    },
    async ({ domain }) => withQuota(domain, () => checkSpf(domain.domain))()
  );

  server.registerTool(
    "check_dmarc",
    {
      title: "Check DMARC Record",
      description:
        "Fetch and diagnose a domain's DMARC record from _dmarc.<domain> via live DNS. Reports the raw record, enforcement policy (p=), subdomain policy (sp=), pct, DKIM/SPF alignment modes, and issues (p=none monitoring-only, missing rua reporting mailbox, missing subdomain policy).",
      inputSchema: { domain: domainArg },
      outputSchema: {
        domain: z.string(),
        record: z.string().nullable(),
        valid: z.boolean(),
        policy: z.string().nullable(),
        subdomain_policy: z.string().nullable(),
        pct: z.number().nullable(),
        alignment: z.object({ dkim: z.string(), spf: z.string() }),
        cached: z.boolean().optional(),
      },
    },
    async ({ domain }) => withQuota(domain, () => checkDmarc(domain.domain))()
  );

  server.registerTool(
    "check_mx",
    {
      title: "Check MX Records",
      description:
        "Fetch a domain's MX records via live DNS, sorted by priority. Detects null MX (\"0 .\", RFC 7505 — domain accepts no mail), single-MX setups with no backup, and missing MX records.",
      inputSchema: { domain: domainArg },
      outputSchema: {
        domain: z.string(),
        mx_records: z.array(z.object({ exchange: z.string(), priority: z.number() })),
        has_fallback: z.boolean(),
        count: z.number(),
        issues: z.array(z.string()),
        cached: z.boolean().optional(),
      },
    },
    async ({ domain }) => withQuota(domain, () => checkMx(domain.domain))()
  );

  server.registerTool(
    "domain_health",
    {
      title: "Domain Health Check",
      description:
        "Domain health overview: RDAP registration expiry (with days remaining), DNSSEC DS-record presence at the parent, and the authoritative nameserver list with a redundancy check. RDAP is best-effort; DS presence is NOT full DNSSEC validation.",
      inputSchema: { domain: domainArg },
      outputSchema: {
        domain: z.string(),
        rdap_expiry: z.string().nullable(),
        days_to_expiry: z.number().nullable(),
        dnssec_ds_present: z.boolean(),
        nameservers: z.array(z.string()),
        ns_count_ok: z.boolean(),
        issues: z.array(z.string()),
        cached: z.boolean().optional(),
      },
    },
    async ({ domain }) => withQuota(domain, () => domainHealth(domain.domain))()
  );

  return server;
}

// ============================================================================
// Express App Setup
// ============================================================================

const app = express();
app.use(express.json());

// Health check endpoint (required for Cloud Run)
app.get("/health", (_req: Request, res: Response) => {
  res.status(200).json({ status: "healthy" });
});

// MCP endpoint with dev logging
app.post("/mcp", async (req: Request, res: Response) => {
  const startTime = Date.now();
  const body = req.body;

  // Extract method and params from JSON-RPC request
  const method = body?.method || "unknown";
  const params = body?.params;

  // Log incoming request
  if (method === "tools/call") {
    const toolName = params?.name || "unknown";
    const toolArgs = params?.arguments;
    logRequest(`tools/call ${chalk.bold(toolName)}`, toolArgs);
  } else if (method !== "notifications/initialized") {
    logRequest(method, params);
  }

  const transport = new StreamableHTTPServerTransport({
    sessionIdGenerator: undefined,
    enableJsonResponse: true,
  });

  // Capture response body for logging
  let responseBody = "";
  const originalWrite = res.write.bind(res) as typeof res.write;
  const originalEnd = res.end.bind(res) as typeof res.end;

  res.write = function (chunk: unknown, encodingOrCallback?: BufferEncoding | ((error: Error | null | undefined) => void), callback?: (error: Error | null | undefined) => void) {
    if (chunk) {
      responseBody += typeof chunk === "string" ? chunk : Buffer.from(chunk as ArrayBuffer).toString();
    }
    return originalWrite(chunk as string, encodingOrCallback as BufferEncoding, callback);
  };

  res.end = function (chunk?: unknown, encodingOrCallback?: BufferEncoding | (() => void), callback?: () => void) {
    if (chunk) {
      responseBody += typeof chunk === "string" ? chunk : Buffer.from(chunk as ArrayBuffer).toString();
    }

    // Log response
    if (method !== "notifications/initialized") {
      const latency = Date.now() - startTime;

      try {
        const rpcResponse = JSON.parse(responseBody) as { result?: unknown; error?: unknown };

        if (rpcResponse?.error) {
          logError(method, rpcResponse.error, latency);
        } else if (method === "tools/call") {
          const content = (rpcResponse?.result as { content?: Array<{ text?: string }> })?.content;
          const resultText = content?.[0]?.text;
          logResponse(method, resultText, latency);
        } else {
          logResponse(method, null, latency);
        }
      } catch {
        logResponse(method, null, latency);
      }
    }

    return originalEnd(chunk as string, encodingOrCallback as BufferEncoding, callback);
  };

  res.on("close", () => {
    transport.close();
  });

  // Fresh server instance per request (see createMcpServer above) — required for
  // stateless streamable-HTTP so a second connection never reuses a transport.
  const server = createMcpServer();
  await server.connect(transport);
  await transport.handleRequest(req, res, req.body);
});

// JSON error handler (Express defaults to HTML errors)
app.use((_err: unknown, _req: Request, res: Response, _next: Function) => {
  res.status(500).json({ error: "Internal server error" });
});

// ============================================================================
// Start Server
// ============================================================================

const port = parseInt(process.env.PORT || "8080");
const httpServer = app.listen(port, () => {
  console.log();
  console.log(chalk.bold("MCP Server running on"), chalk.cyan(`http://localhost:${port}`));
  console.log(`  ${chalk.gray("Health:")} http://localhost:${port}/health`);
  console.log(`  ${chalk.gray("MCP:")}    http://localhost:${port}/mcp`);

  if (isDev) {
    console.log();
    console.log(chalk.gray("─".repeat(50)));
    console.log();
  }
});

// Graceful shutdown for Cloud Run (SIGTERM before kill)
process.on("SIGTERM", () => {
  console.log("Received SIGTERM, shutting down...");
  httpServer.close(() => {
    process.exit(0);
  });
});
