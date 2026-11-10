# Release manifests of the builds the study ran

Copied in round 4 from the install directories of the round-3 lanes (scratch paths scrubbed to `<SCRATCH>`), so a reader can see which
package versions were installed, their registry publish dates, the platform binary path inside each install and, for Codex, the registry
integrity hash of each build (`dist_integrity`). Claude Code 23 builds, Codex 25 (17 usable, 8 hang on `--version`), Gemini CLI 24 (the
manifest of the sweep installs; 0.29.7, 0.30.0, 0.38.0 and 0.38.2 were installed outside it, see `gemini-core/registry-integrity.json`).

What they do not cover: the round-4 installs (Claude Code 2.1.70 to 2.1.87, 17 builds, of which 5 were run; Codex 0.141.0 and 0.142.0), which
were installed with `npm install --ignore-scripts` from the public registry and have no manifest entry; every run row carries `binary_sha256`
and `version_reported` instead. Reinstalling is `npm install --ignore-scripts @anthropic-ai/claude-code@<v>`, `@openai/codex@<v>` or
`@google/gemini-cli@<v>` into an empty directory. The mitigation and guard rows carry no `binary_sha256` (build identity there rests on the
install path); there is no installer script and no DOI deposit.
