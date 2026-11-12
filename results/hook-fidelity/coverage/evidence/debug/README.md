# Codex 0.131.0 debug launches (round 3 coverage lane), committed in round 4

What this is: the artifacts of the exploratory launches behind two statements of [hook-fidelity-coverage-rerun.md](https://github.com/Suhas-123-cell/IntentShield/blob/research-notes/docs/research-notes/hook-fidelity/hook-fidelity-coverage-rerun.md): (1) Codex
0.131.0 ran no hook under `exec --dangerously-bypass-hook-trust` (0 hook events), and (2) one non-stub request in a
`RUST_LOG=trace` run (an unauthenticated plugin-cache request to a ChatGPT host, HTTP 401). The files were copied from the
round-3 scratch directory, **not re-run**; paths are scrubbed (`<HOME>`, `<SCRATCH>`, `<TMP>`). `debug_launches.txt` is the lane's
own tally (11 launches of one each, plus 2 trust-step app-server starts).

| file | content |
|---|---|
| `exp_codex.py` | the driver that made the five shapes below: `codex exec --skip-git-repo-check --dangerously-bypass-hook-trust --json hi` (plus `--enable hooks` for `toml-enable`), `RUST_LOG=trace`, stub model on loopback, isolated HOME and CODEX_HOME, `SessionStart` and `UserPromptSubmit` command hooks (the passive `coverage_hook.py`, or a `/bin/sh` witness for `toml-sh`) |
| `shapes/<shape>/config.toml`, `hooks.json`, `project-hooks.json` | the config of each shape: `toml` inline `[[hooks.*]]`, `toml-sh` the same with an sh witness, `toml-enable` inline plus `--enable hooks`, `json` `hooks.json` in CODEX_HOME, `project` a trusted project `.codex/hooks.json` |
| `shapes/<shape>/stub.jsonl` | the stub model's request log of the run (one `POST /v1/responses`; authorization header redacted by the stub) |
| `shapes/toml/stderr.txt`, `shapes/project/stderr.txt` | the trace stderr; the only two kept. `toml/stderr.txt` line 13 is the 401 plugin-cache WARN; `project/stderr.txt` lines 14 to 16 show a connection attempt to the ChatGPT host |

What the artifacts support, as counts and not more:

- Preserved: **5 shapes, 1 launch each**. In none of the five directories does a hook log (`hooks.jsonl`) or the sh witness
  (`sh-hit.txt`) exist, which is the committed trace of "0 hook events" for those 5 launches. The other 6 of the "11 of 11" launches
  left no artifact; the 11/11 figure rests on the lane's tally only and is **unsupported by committed raw files beyond 5/11**.
- The plugin-cache request is 1 trace-logged launch (`toml`), plus the connection attempt in `project`. It shows the Codex
  stub arm was not network-blocked at the time (these launches predate the refusing proxy).
- Which hook state those launches were in (bypass flag, `hooks/list` reporting the hooks `untrusted`) is from the lane's report,
  not from a preserved file.
