#!/usr/bin/env bash
# End-to-end ReconForge lab demonstration. Everything runs against 127.0.0.1 / acme.test.
#   1. baseline comprehensive scan (lab phase 1)
#   2. lab switches to phase 2 (simulated infrastructure changes)
#   3. second scan -> change detection -> notifications (captured by local sinks)
#   4. incremental continuous-profile scan
#   5. AI-assisted analysis (heuristic provider, offline) + reports + graph export + backup
set -euo pipefail
cd "$(dirname "$0")/.."
PY=${PY:-.venv/bin/python}
RF="$PY -m reconforge.cli -c config/lab.yaml"
export LAB_TELEGRAM_TOKEN=000000:lab-token

stop_lab() { [[ -n "${LAB_PID:-}" ]] && kill "$LAB_PID" 2>/dev/null && wait "$LAB_PID" 2>/dev/null || true; }
start_lab() {
  $PY lab/lab_server.py --phase "$1" ${2:-} > lab/runtime/lab-phase$1.out 2>&1 &
  LAB_PID=$!
  for _ in $(seq 1 50); do grep -q "lab running" lab/runtime/lab-phase$1.out 2>/dev/null && return; sleep 0.2; done
  echo "lab failed to start"; cat lab/runtime/lab-phase$1.out; exit 1
}
trap stop_lab EXIT

echo "== resetting lab data"; rm -rf data/lab lab/runtime; mkdir -p lab/runtime

echo "== [1] lab phase 1 + baseline scan"
start_lab 1 --reset-sinks
$RF scan acme-lab --profile comprehensive
S1=$($PY -c "import sqlite3;print(sqlite3.connect('data/lab/reconforge.db').execute('select id from scans order by started_at desc').fetchone()[0])")
stop_lab

echo "== [2] lab phase 2 (changes introduced) + second scan"
start_lab 2
$RF scan acme-lab --profile comprehensive
S2=$($PY -c "import sqlite3;print(sqlite3.connect('data/lab/reconforge.db').execute('select id from scans order by started_at desc').fetchone()[0])")
echo "-- changes detected in $S2"; $RF changes "$S2"

echo "== [3] incremental continuous-profile scan (no new changes expected; duplicate alerts suppressed)"
$RF scan acme-lab --profile continuous --incremental
S3=$($PY -c "import sqlite3;print(sqlite3.connect('data/lab/reconforge.db').execute('select id from scans order by started_at desc').fetchone()[0])")

echo "== [4] AI-assisted analysis (offline heuristic provider) and report regeneration"
$RF analyze "$S2" --provider heuristic
$RF report "$S2"

echo "== [5] graph export, scan history, backup"
$RF graph acme-lab --format graphml --out data/lab/acme-lab.graphml
$RF graph acme-lab --format dot --out data/lab/acme-lab.dot
$RF scans
$RF db backup

echo "== notifications captured by the lab sinks"
$PY - <<'EOF'
import json, pathlib
p = pathlib.Path("lab/runtime/notifications.jsonl")
for line in p.read_text().splitlines() if p.exists() else []:
    d = json.loads(line)
    print(f"  {d['channel']:9} {(d.get('subject') or json.loads(d.get('payload') or '{}').get('text') or '')[:90]}")
EOF
echo "== unexpected (non-GET) requests received by lab web servers:"
cat lab/runtime/unexpected_methods.log 2>/dev/null || echo "  none"
echo
echo "Scans: baseline=$S1 changed=$S2 incremental=$S3"
echo "Reports: data/lab/reports/acme-lab/"
echo "Dashboard: $RF serve   ->  http://127.0.0.1:8765"
