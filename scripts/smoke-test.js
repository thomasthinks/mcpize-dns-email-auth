// Smoke test — verifies the MCP server is running and responding correctly.
// Usage: npm run test:smoke (server must be running on PORT or 8080)

const BASE = `http://localhost:${process.env.PORT || 8080}`;
const HEADERS = {
  "Content-Type": "application/json",
  Accept: "application/json, text/event-stream",
};

async function rpc(method, params = {}) {
  const res = await fetch(`${BASE}/mcp`, {
    method: "POST",
    headers: HEADERS,
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  if (!res.ok) throw new Error(`${method}: HTTP ${res.status}`);
  return res.json();
}

async function main() {
  // 1. Health check
  const health = await fetch(`${BASE}/health`);
  if (!health.ok) throw new Error(`Health check failed: ${health.status}`);
  console.log("✓ Health check passed");

  // 2. Initialize
  await rpc("initialize", {
    protocolVersion: "2025-03-26",
    capabilities: {},
    clientInfo: { name: "smoke-test", version: "1.0.0" },
  });
  console.log("✓ Initialize passed");

  // 3. List tools
  const { result } = await rpc("tools/list");
  const tools = result?.tools || [];
  if (!tools.length) throw new Error("No tools registered");
  console.log(
    `✓ Found ${tools.length} tool(s): ${tools.map((t) => t.name).join(", ")}`,
  );
}

main().catch((err) => {
  console.error("✖", err.message);
  process.exit(1);
});
