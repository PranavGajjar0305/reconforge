#!/usr/bin/env bash
# Builds the README demo data set: the controlled lab served as example.com, scanned twice
# (baseline + changes), plus the offline heuristic analysis. Everything stays on 127.0.0.1 and
# is written to data/demo/ (git-ignored). Afterwards:
#   .venv/bin/python -m reconforge.cli -c config/demo.yaml serve --port 8790
set -euo pipefail
cd "$(dirname "$0")/.."
PY=${PY:-.venv/bin/python}
RF="$PY -m reconforge.cli -c config/demo.yaml"
DOMAIN=example.com

stop_lab() { [[ -n "${LAB_PID:-}" ]] && kill "$LAB_PID" 2>/dev/null && wait "$LAB_PID" 2>/dev/null || true; LAB_PID=; }
start_lab() {
  $PY lab/lab_server.py --phase "$1" --domain "$DOMAIN" > lab/runtime/demo-phase$1.out 2>&1 &
  LAB_PID=$!
  for _ in $(seq 1 50); do grep -q "lab running" lab/runtime/demo-phase$1.out 2>/dev/null && return; sleep 0.2; done
  echo "lab failed to start"; cat lab/runtime/demo-phase$1.out; exit 1
}
trap stop_lab EXIT

rm -rf data/demo; mkdir -p lab/runtime
echo "== baseline scan of the demo lab ($DOMAIN, phase 1)"
start_lab 1
$RF scan "$DOMAIN" --profile comprehensive
stop_lab
echo "== second scan after simulated changes (phase 2)"
start_lab 2
$RF scan "$DOMAIN" --profile comprehensive
stop_lab
S2=$($PY -c "import sqlite3;print(sqlite3.connect('data/demo/reconforge.db').execute('select id from scans order by started_at desc').fetchone()[0])")
$RF analyze "$S2" --provider heuristic >/dev/null
echo "Demo ready in data/demo. Start it with:  $RF serve --port 8790"
