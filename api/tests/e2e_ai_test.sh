#!/usr/bin/env bash
# E2E test for the Detonate AI pipeline against a live Ollama instance.
#
# Exercises every AI endpoint with a safe test binary:
#   1. GET  /ai/status
#   2. POST /submit
#   3. POST /submissions/{id}/ai/summarize
#   4. GET  /submissions/{id}/ai/summary
#   5. POST /submissions/{id}/ai/classify
#   6. POST /submissions/{id}/ai/agent
#   7. POST /submissions/{id}/chat/conversations
#   8. POST /submissions/{id}/chat/conversations/{cid}/messages (SSE)
#
# Prerequisites:
#   make services && make ollama-pull && make migrate
#   API running on :8000 (or set API_URL)
#
# Usage:
#   ./e2e_ai_test.sh
#   API_URL=http://host:8000 ./e2e_ai_test.sh

set -uo pipefail

API_URL="${API_URL:-http://localhost:8000}"
BASE="$API_URL/api/v1"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SAMPLE="${SAMPLE_PATH:-$SCRIPT_DIR/fixtures/test_sample.bin}"
TIMEOUT=300

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
BOLD='\033[1m'
RESET='\033[0m'

pass() { echo -e "  ${GREEN}PASS${RESET}: $1"; }
fail() {
    echo -e "  ${RED}FAIL${RESET}: $1"
    if [[ -n "${2:-}" ]]; then
        echo "  Response: $(echo "$2" | head -5)"
    fi
    exit 1
}

echo -e "${BOLD}=== Detonate E2E AI Pipeline Test ===${RESET}"
echo "API:    $BASE"
echo "Sample: $SAMPLE"
echo ""

# --- Preflight checks ---
command -v jq >/dev/null 2>&1 || fail "jq is required but not installed"
[[ -f "$SAMPLE" ]] || fail "Test sample not found at $SAMPLE. Run: python api/tests/generate_test_sample.py"

echo "Preflight: checking API health..."
resp=$(curl -s --max-time 5 "$BASE/health" 2>/dev/null || true)
if ! echo "$resp" | jq -e '.status' >/dev/null 2>&1; then
    fail "API not reachable at $BASE (is the server running?)" "$resp"
fi
pass "API is healthy"
echo ""

# ===================================================================
# Step 1: AI Status
# ===================================================================
echo -e "${BOLD}[1/8] Checking AI status${RESET}"
resp=$(curl -s --max-time 10 "$BASE/ai/status")
enabled=$(echo "$resp" | jq -r '.enabled')
configured=$(echo "$resp" | jq -r '.configured')
provider=$(echo "$resp" | jq -r '.provider')
model=$(echo "$resp" | jq -r '.model')
[[ "$enabled" == "true" ]]    || fail "AI not enabled (set AI_ENABLED=true)" "$resp"
[[ "$configured" == "true" ]] || fail "Provider not configured (is Ollama running with model pulled?)" "$resp"
pass "enabled=$enabled configured=$configured provider=$provider model=$model"

# ===================================================================
# Step 2: Submit test sample
# ===================================================================
echo -e "${BOLD}[2/8] Submitting test sample${RESET}"
resp=$(curl -s --max-time 30 -X POST "$BASE/submit" \
    -F "file=@$SAMPLE" \
    -F "tags=e2e-test,safe-sample")
SUB_ID=$(echo "$resp" | jq -r '.id // empty')
[[ -n "$SUB_ID" ]] || fail "No submission ID returned" "$resp"
sha256=$(echo "$resp" | jq -r '.file_hash_sha256 // empty')
pass "id=$SUB_ID sha256=${sha256:0:16}..."

# ===================================================================
# Step 3: Summarize
# ===================================================================
echo -e "${BOLD}[3/8] Requesting AI summary (may take a minute)${RESET}"
resp=$(curl -s --max-time "$TIMEOUT" -X POST "$BASE/submissions/$SUB_ID/ai/summarize")
task_id=$(echo "$resp" | jq -r '.id // empty')
status=$(echo "$resp" | jq -r '.status')
if [[ "$status" != "completed" ]]; then
    err=$(echo "$resp" | jq -r '.error // "unknown"')
    fail "Summarize status=$status error=$err" "$resp"
fi
pass "task=$task_id status=$status"

# ===================================================================
# Step 4: Get cached summary
# ===================================================================
echo -e "${BOLD}[4/8] Fetching cached summary${RESET}"
resp=$(curl -s --max-time 10 "$BASE/submissions/$SUB_ID/ai/summary")
generated=$(echo "$resp" | jq -r '.generated')
summary=$(echo "$resp" | jq -r '.summary // empty')
[[ "$generated" == "true" ]]  || fail "Summary not generated" "$resp"
[[ ${#summary} -gt 10 ]]      || fail "Summary too short (${#summary} chars)" "$resp"
pass "generated=true length=${#summary}"

# ===================================================================
# Step 5: Classify
# ===================================================================
echo -e "${BOLD}[5/8] Requesting AI classification (may take a minute)${RESET}"
resp=$(curl -s --max-time "$TIMEOUT" -X POST "$BASE/submissions/$SUB_ID/ai/classify")
task_id=$(echo "$resp" | jq -r '.id // empty')
status=$(echo "$resp" | jq -r '.status')
if [[ "$status" != "completed" ]]; then
    err=$(echo "$resp" | jq -r '.error // "unknown"')
    fail "Classify status=$status error=$err" "$resp"
fi
verdict=$(echo "$resp" | jq -r '.output_data.verdict // empty')
score=$(echo "$resp" | jq -r '.output_data.score // empty')
pass "task=$task_id verdict=$verdict score=$score"

# ===================================================================
# Step 6: Agent analysis
# ===================================================================
echo -e "${BOLD}[6/8] Requesting agent analysis (may take a minute)${RESET}"
resp=$(curl -s --max-time "$TIMEOUT" -X POST "$BASE/submissions/$SUB_ID/ai/agent")
task_id=$(echo "$resp" | jq -r '.id // empty')
status=$(echo "$resp" | jq -r '.status')
if [[ "$status" != "completed" ]]; then
    err=$(echo "$resp" | jq -r '.error // "unknown"')
    fail "Agent status=$status error=$err" "$resp"
fi
agent_verdict=$(echo "$resp" | jq -r '.output_data.verdict.verdict // empty')
agent_score=$(echo "$resp" | jq -r '.output_data.verdict.score // empty')
reasoning=$(echo "$resp" | jq -r '.output_data.verdict.reasoning // empty')
tools_used=$(echo "$resp" | jq '.output_data.tool_calls | length')
pass "task=$task_id verdict=$agent_verdict score=$agent_score tools_used=$tools_used"
if [[ ${#reasoning} -gt 5 ]]; then
    echo "  Reasoning: ${reasoning:0:120}..."
fi

# ===================================================================
# Step 7: Create chat conversation
# ===================================================================
echo -e "${BOLD}[7/8] Creating chat conversation${RESET}"
resp=$(curl -s --max-time 10 -X POST "$BASE/submissions/$SUB_ID/chat/conversations")
CONV_ID=$(echo "$resp" | jq -r '.id // empty')
[[ -n "$CONV_ID" ]] || fail "No conversation ID returned" "$resp"
pass "conversation=$CONV_ID"

# ===================================================================
# Step 8: Chat message (SSE stream)
# ===================================================================
echo -e "${BOLD}[8/8] Sending chat message (SSE stream)${RESET}"
stream=$(curl -s --max-time "$TIMEOUT" -N -X POST \
    "$BASE/submissions/$SUB_ID/chat/conversations/$CONV_ID/messages" \
    -H "Content-Type: application/json" \
    -d '{"content": "What suspicious indicators did you find in this file?"}' 2>/dev/null || true)
data_count=$(echo "$stream" | grep -c "^data:" || true)
done_count=$(echo "$stream" | grep -c "\[DONE\]" || true)
[[ "$data_count" -gt 0 ]] || fail "No SSE data events received" "$stream"
[[ "$done_count" -gt 0 ]] || fail "Stream did not complete (no [DONE])" "$stream"
pass "received $data_count SSE events, stream completed"

# ===================================================================
echo ""
echo -e "${BOLD}${GREEN}=== All 8 tests passed! ===${RESET}"
