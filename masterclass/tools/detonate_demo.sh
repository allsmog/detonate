#!/usr/bin/env bash
# detonate_demo.sh — run a masterclass training binary through the REAL Detonate
# Linux sandbox container, end to end, and print the telemetry the platform
# produces (processes / network / files). This is the same image and guest agent
# the platform's DockerMachinery uses.
#
# Requires: docker (daemon running), gcc. Builds the sandbox image if missing.
# Usage:    bash detonate_demo.sh [path-to-sample-source.c]
#
# Network is disabled (--network none) — detonation is isolated; the sample's
# connect()/DNS attempts still show in telemetry (Module 3.3's lesson).
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="${1:-$ROOT/03-dynamic-analysis/01-detonate-first-detonation/sample_beacon.c}"
IMAGE="detonate-sandbox-linux"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT

command -v docker >/dev/null || { echo "docker not found"; exit 1; }
docker info >/dev/null 2>&1 || { echo "docker daemon not running (start dockerd)"; exit 1; }

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  echo "[*] building sandbox image..."
  docker build -t "$IMAGE" -f "$ROOT/../sandbox/linux/Dockerfile" "$ROOT/../sandbox/" >/dev/null
fi

name="$(basename "${SRC%.c}")"
gcc -O0 -no-pie "$SRC" -o "$WORK/$name" && chmod +x "$WORK/$name"

echo "[*] detonating '$name' in $IMAGE (network=none, timeout=12s)..."
CID="$(docker run -d --network none --memory 512m -v "$WORK:/sample" "$IMAGE" "/sample/$name" 12)"
timeout 40 docker wait "$CID" >/dev/null 2>&1 || true
docker cp "$CID:/opt/agent/results.json" "$WORK/results.json" >/dev/null 2>&1
docker rm -f "$CID" >/dev/null 2>&1

python3 - "$WORK/results.json" <<'PY'
import json, sys
r = json.load(open(sys.argv[1]))
print("\n=== Detonate telemetry (real sandbox) ===")
print("processes:")
for p in r.get("processes", []):
    print(f"  pid={p.get('pid')} ppid={p.get('ppid')}  {p.get('command')} {' '.join(p.get('args',[]))}")
print("network (connect/DNS attempts):")
seen=set()
for c in r.get("network", []):
    k=(c.get('protocol'),c.get('address'),c.get('port'))
    if k in seen: continue
    seen.add(k)
    print(f"  {c.get('protocol')}://{c.get('address')}:{c.get('port')}")
print("files created:")
for f in r.get("files_created", []):
    print(f"  {f.get('path') if isinstance(f,dict) else f}")
PY
