#!/bin/bash
set -e

API_BASE="${API_BASE:-http://localhost:8000/api/v1}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TEST_SAMPLE="$SCRIPT_DIR/fixtures/test_sample.sh"
PASS=0
FAIL=0

pass() { echo "  PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL + 1)); }
check() {
    if echo "$2" | grep -q "$3"; then
        pass "$1"
    else
        fail "$1 (expected '$3' in output)"
    fi
}

echo "=== Detonate Dynamic Analysis E2E Test ==="
echo ""

# Step 0: Build sandbox image
echo "[0] Building sandbox image..."
make -C "$(dirname "$SCRIPT_DIR")/.." sandbox-build
echo ""

# Step 1: Submit test sample
echo "[1] Submitting test sample..."
SUBMIT_RESPONSE=$(curl -s -X POST "$API_BASE/submit" \
    -F "file=@$TEST_SAMPLE" \
    -F "tags=e2e-test")
SUBMISSION_ID=$(echo "$SUBMIT_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])")
echo "  Submission ID: $SUBMISSION_ID"
check "Submission created" "$SUBMIT_RESPONSE" '"id"'

# Step 2: Start dynamic analysis
echo ""
echo "[2] Starting dynamic analysis..."
ANALYZE_RESPONSE=$(curl -s -X POST "$API_BASE/submissions/$SUBMISSION_ID/analyze" \
    -H "Content-Type: application/json" \
    -d '{"timeout": 30}')
echo "  Response status: $(echo "$ANALYZE_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status','?'))")"
check "Analysis completed" "$ANALYZE_RESPONSE" '"status":"completed"'

# Step 3: Check process events
echo ""
echo "[3] Checking process events..."
RESULT=$(echo "$ANALYZE_RESPONSE" | python3 -c "import sys,json; print(json.dumps(json.load(sys.stdin).get('result',{})))")
check "Has processes" "$RESULT" '"processes"'
check "Detected bash or sh" "$RESULT" '/bin/'

# Step 4: Check file creation events
echo ""
echo "[4] Checking file events..."
check "Dropped payload detected" "$RESULT" 'dropped_payload.txt'
check "Recon file detected" "$RESULT" 'recon.txt'

# Step 5: Check network events
echo ""
echo "[5] Checking network events..."
# Network may or may not show depending on --network none; curl will fail
# but strace should capture the connect attempt
echo "  (Network connections may not appear with --network none; checking stdout/stderr)"
check "Curl was executed" "$RESULT" 'curl'

# Step 6: List analyses
echo ""
echo "[6] Listing analyses..."
LIST_RESPONSE=$(curl -s "$API_BASE/submissions/$SUBMISSION_ID/analyses")
check "Analyses list not empty" "$LIST_RESPONSE" '"total":1'

# Summary
echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ] && exit 0 || exit 1
