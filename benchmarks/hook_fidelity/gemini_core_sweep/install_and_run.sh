#!/bin/bash
# Reproduce the Gemini hook-runner sweep. SWEEP_DIR must be an empty directory outside the repo.
# Installs each @google/gemini-cli-core version into its own npm prefix (--ignore-scripts), then
# drives dist/src/hooks/{hookRunner,hookAggregator,hookEventHandler}.js with driver.mjs. No model, no network at run time.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
SWEEP_DIR="${SWEEP_DIR:?set SWEEP_DIR to an empty scratch directory}"
VERSIONS=(0.20.2 0.22.5 0.24.5 0.25.2 0.26.0 0.27.4 0.28.2 0.29.7 0.30.0 0.30.1 0.32.1 0.33.2 0.34.0 0.35.3 0.36.0 0.37.1 0.38.2 0.40.1 0.45.3 0.50.0 0.55.1 0.60.0 0.66.0 0.67.0-preview.0 0.67.0-nightly.20261031.g6814e00d6)
mkdir -p "$SWEEP_DIR/raw" "$SWEEP_DIR/tmp"; cd "$SWEEP_DIR"
for v in "${VERSIONS[@]}"; do
  [ -d "$v/node_modules/@google/gemini-cli-core" ] || { mkdir -p "$v"; npm install --prefix "$v" --ignore-scripts --no-audit --no-fund "@google/gemini-cli-core@$v" >"install-$v.log" 2>&1; }
  TMPDIR="$SWEEP_DIR/tmp" node "$HERE/driver.mjs" "$v" "$v" "raw/$v.jsonl" >/dev/null 2>"raw/$v.stderr.txt"
done
# RESULTS_DIR receives table.md, table-per-version.txt, manifest.json and the scrubbed raw rows (default: $SWEEP_DIR/out)
python3 "$HERE/table.py" "$SWEEP_DIR/raw" "${RESULTS_DIR:-$SWEEP_DIR/out}" "$SWEEP_DIR"
