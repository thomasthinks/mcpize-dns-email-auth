#!/bin/bash
# MCP Protocol Smoke Test for dns-email-auth
# Usage: start the server first (npm run dev / npm start), then: bash test-mcp.sh
# Every /mcp curl MUST include -H "Accept: application/json, text/event-stream".

BASE_URL="${MCP_URL:-http://localhost:8080}"
MCP_ENDPOINT="$BASE_URL/mcp"
HEALTH_ENDPOINT="$BASE_URL/health"
PASSED=0
FAILED=0

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

pass() { echo -e "${GREEN}PASS${NC} $1"; PASSED=$((PASSED + 1)); }
fail() { echo -e "${RED}FAIL${NC} $1: $2"; FAILED=$((FAILED + 1)); }

mcp_post() {
  curl -sf -X POST "$MCP_ENDPOINT" \
    -H "Content-Type: application/json" \
    -H "Accept: application/json, text/event-stream" \
    -d "$1" 2>/dev/null
}

echo "Testing dns-email-auth MCP server at $BASE_URL"
echo "================================"

# 1. Health check
echo ""
echo "--- Health Check ---"
HEALTH=$(curl -sf "$HEALTH_ENDPOINT" 2>/dev/null) || true
if echo "$HEALTH" | grep -q "healthy"; then
  pass "GET /health returns healthy"
else
  fail "GET /health" "Expected 'healthy', got: $HEALTH"
fi

# 2. Initialize handshake
echo ""
echo "--- MCP Initialize ---"
INIT_RESPONSE=$(mcp_post '{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "initialize",
  "params": {
    "protocolVersion": "2025-03-26",
    "capabilities": {},
    "clientInfo": { "name": "smoke-test", "version": "1.0" }
  }
}') || true
if echo "$INIT_RESPONSE" | grep -q '"result"'; then
  pass "initialize returns result"
else
  fail "initialize" "No 'result' in response: $INIT_RESPONSE"
fi

# 3. List tools
echo ""
echo "--- List Tools ---"
TOOLS_RESPONSE=$(mcp_post '{"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}') || true
if echo "$TOOLS_RESPONSE" | grep -q '"tools"'; then
  TOOL_COUNT=$(echo "$TOOLS_RESPONSE" | python3 -c "import sys,json; print(len(json.load(sys.stdin)['result']['tools']))" 2>/dev/null || echo "?")
  pass "tools/list returns tools array ($TOOL_COUNT tool(s))"
else
  fail "tools/list" "No 'tools' in response: $TOOLS_RESPONSE"
fi

EXPECTED_TOOLS=("check_spf" "check_dmarc" "check_mx" "domain_health")
for TOOL in "${EXPECTED_TOOLS[@]}"; do
  if echo "$TOOLS_RESPONSE" | grep -q "\"$TOOL\""; then
    pass "Tool '$TOOL' is registered"
  else
    fail "Tool '$TOOL'" "Not found in tools/list response"
  fi
done

# 4. Call each tool against a real domain (live network)
echo ""
echo "--- Call Tools (live: google.com) ---"
ID=3
for TOOL in "${EXPECTED_TOOLS[@]}"; do
  CALL_RESPONSE=$(mcp_post "{
    \"jsonrpc\": \"2.0\",
    \"id\": $ID,
    \"method\": \"tools/call\",
    \"params\": { \"name\": \"$TOOL\", \"arguments\": { \"domain\": \"google.com\" } }
  }") || true
  if echo "$CALL_RESPONSE" | grep -q '"content"' && ! echo "$CALL_RESPONSE" | grep -q '"isError":true'; then
    pass "tools/call $TOOL (google.com) returns content"
  else
    fail "tools/call $TOOL" "Missing content or isError: $(echo "$CALL_RESPONSE" | head -c 300)"
  fi
  ID=$((ID + 1))
done

# 5. Garbage input -> validation error (isError), not a crash
echo ""
echo "--- Validation (garbage input) ---"
ERR_RESPONSE=$(mcp_post '{
  "jsonrpc": "2.0",
  "id": 20,
  "method": "tools/call",
  "params": { "name": "check_spf", "arguments": { "domain": "not a domain" } }
}') || true
if echo "$ERR_RESPONSE" | grep -q '"isError":true' && echo "$ERR_RESPONSE" | grep -qi "invalid domain"; then
  pass "garbage domain returns structured isError (validation, no crash)"
else
  fail "garbage domain" "Expected isError validation error, got: $(echo "$ERR_RESPONSE" | head -c 300)"
fi

# 6. Nonexistent domain -> structured issues, not a crash
echo ""
echo "--- Nonexistent Domain ---"
NX_RESPONSE=$(mcp_post '{
  "jsonrpc": "2.0",
  "id": 21,
  "method": "tools/call",
  "params": { "name": "check_mx", "arguments": { "domain": "this-domain-definitely-does-not-exist-xyz123.com" } }
}') || true
if echo "$NX_RESPONSE" | grep -q '"content"' && ! echo "$NX_RESPONSE" | grep -q '"isError":true'; then
  pass "nonexistent domain returns structured issues (no crash)"
else
  fail "nonexistent domain" "Unexpected failure: $(echo "$NX_RESPONSE" | head -c 300)"
fi

# 7. Ping
echo ""
echo "--- Ping ---"
PING_RESPONSE=$(mcp_post '{"jsonrpc": "2.0", "id": 22, "method": "ping", "params": {}}') || true
if echo "$PING_RESPONSE" | grep -q '"result"'; then
  pass "ping returns result"
else
  fail "ping" "No 'result' in response: $PING_RESPONSE"
fi

# Summary
echo ""
echo "================================"
echo -e "Results: ${GREEN}$PASSED passed${NC}, ${RED}$FAILED failed${NC}"

if [ $FAILED -gt 0 ]; then
  exit 1
fi
