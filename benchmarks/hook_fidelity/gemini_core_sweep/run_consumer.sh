#!/bin/bash
# Layer C (real HookSystem) for every installed core version and the consumer-side scheduler probe for 0.36.0 and later
# (before 0.36.0 the hook runner turns an `ask` into `allow`, so no consumer ever sees one; see table.md).
# SWEEP_DIR holds the per-version npm prefixes made by install_and_run.sh; OUT_DIR gets raw/<version>.layerc.jsonl and
# raw/<version>.consumer.jsonl. Each version runs under its own isolated HOME and TMPDIR inside OUT_DIR: the probes never
# read or write the real ~/.gemini. JOBS versions run in parallel (default 4).
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
SWEEP_DIR="${SWEEP_DIR:?set SWEEP_DIR to the directory of per-version installs}"
OUT_DIR="${OUT_DIR:?set OUT_DIR to an empty scratch directory}"
JOBS="${JOBS:-4}"
VERSIONS=(${VERSIONS:-0.20.2 0.22.5 0.24.5 0.25.2 0.26.0 0.27.4 0.28.2 0.29.7 0.30.0 0.30.1 0.32.1 0.33.2 0.34.0 0.35.3 0.36.0 0.37.1 0.38.2 0.40.1 0.45.3 0.50.0 0.55.1 0.60.0 0.66.0 0.67.0-preview.0 0.67.0-nightly.20261031.g6814e00d6})
mkdir -p "$OUT_DIR/raw"
one() {
  local v="$1" h="$OUT_DIR/home-$v"
  mkdir -p "$h" "$OUT_DIR/tmp-$v"
  export HOME="$h" GEMINI_CLI_HOME="$h" TMPDIR="$OUT_DIR/tmp-$v" PROBE_WAIT_MS="${PROBE_WAIT_MS:-5000}"
  node "$HERE/layer_c.mjs" "$SWEEP_DIR/$v" "$v" "$OUT_DIR/raw/$v.layerc.jsonl" >/dev/null 2>"$OUT_DIR/raw/$v.layerc.stderr.txt"
  case "$v" in 0.2*|0.30*|0.31*|0.32*|0.33*|0.34*|0.35*) ;; *)
    node "$HERE/consumer_probe.mjs" "$SWEEP_DIR/$v" "$v" "$OUT_DIR/raw/$v.consumer.jsonl" >/dev/null 2>"$OUT_DIR/raw/$v.consumer.stderr.txt";; esac
  echo "$v done" >&2
}
for v in "${VERSIONS[@]}"; do
  while [ "$(jobs -rp | wc -l)" -ge "$JOBS" ]; do sleep 2; done
  one "$v" &
done
wait
