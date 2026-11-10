# Linux `/proc` reader in a container (derived by `linux_probe.py summarize` from `matrix.jsonl`, `hidepid.jsonl`, `pid1.jsonl`)

Ground truth is how each tree was built, not an independent oracle. `agree` = the detected mode equals the constructed one and the `how` text names the expected reason.

| group | harness (form) | flag | pty | nested | sources | expected | detected | source | complete | depth | mode equal | agree |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| matrix | claude (native) | yes | yes | no | default | headless | headless | proc | True | 5 | yes | yes |
| matrix | claude (native) | yes | no | no | default | headless | headless | proc | True | 3 | yes | yes |
| matrix | claude (native) | no | yes | no | default | interactive | interactive | proc | True | 5 | yes | yes |
| matrix | claude (native) | no | no | no | default | headless | headless | proc | True | 3 | yes | yes |
| matrix | claude (node) | yes | yes | no | default | headless | headless | proc | True | 5 | yes | yes |
| matrix | claude (node) | yes | no | no | default | headless | headless | proc | True | 3 | yes | yes |
| matrix | claude (node) | no | yes | no | default | interactive | interactive | proc | True | 5 | yes | yes |
| matrix | claude (node) | no | no | no | default | headless | headless | proc | True | 3 | yes | yes |
| matrix | codex (node) | yes | yes | no | default | headless | headless | proc | True | 5 | yes | yes |
| matrix | codex (node) | yes | no | no | default | headless | headless | proc | True | 3 | yes | yes |
| matrix | codex (node) | no | yes | no | default | interactive | interactive | proc | True | 5 | yes | yes |
| matrix | codex (node) | no | no | no | default | headless | headless | proc | True | 3 | yes | yes |
| matrix | gemini (node) | yes | yes | no | default | headless | headless | proc | True | 5 | yes | yes |
| matrix | gemini (node) | yes | no | no | default | headless | headless | proc | True | 3 | yes | yes |
| matrix | gemini (node) | no | yes | no | default | interactive | interactive | proc | True | 5 | yes | yes |
| matrix | gemini (node) | no | no | no | default | headless | headless | proc | True | 3 | yes | yes |
| matrix | claude (native) | yes | no | yes | default | headless | headless | proc | True | 6 | yes | yes |
| matrix | claude (native) | no | yes | yes | default | interactive | interactive | proc | True | 8 | yes | yes |
| matrix | claude (node) | yes | no | yes | default | headless | headless | proc | True | 6 | yes | yes |
| matrix | claude (node) | no | yes | yes | default | interactive | interactive | proc | True | 8 | yes | yes |
| matrix | codex (node) | yes | no | yes | default | headless | headless | proc | True | 6 | yes | yes |
| matrix | codex (node) | no | yes | yes | default | interactive | interactive | proc | True | 8 | yes | yes |
| matrix | gemini (node) | yes | no | yes | default | headless | headless | proc | True | 6 | yes | yes |
| matrix | gemini (node) | no | yes | yes | default | interactive | interactive | proc | True | 8 | yes | yes |
| matrix | claude (none) | no | yes | no | default | headless | headless | proc | True | 4 | yes | yes |
| matrix | claude (none) | no | no | no | default | headless | headless | proc | True | 2 | yes | yes |
| matrix | claude (native) | no | yes | no | ps | unknown | unknown | none | False | 0 | yes | yes |
| matrix | claude (native) | no | yes | no | proc | interactive | interactive | proc | True | 5 | yes | yes |
| hidepid | claude (native) | yes | no | no | default | unknown | unknown | none | False | 0 | yes | yes |
| pid1 | claude (native) | yes | no | no | default | headless | headless | proc | True | 1 | yes | NO |
| pid1 | claude (native) | no | no | no | default | headless | headless | proc | True | 1 | yes | NO |
| pid1 | claude (node) | yes | no | no | default | headless | headless | proc | True | 1 | yes | NO |
| pid1 | claude (node) | no | no | no | default | headless | headless | proc | True | 1 | yes | NO |
| pid1 | claude (native) | yes | yes | no | default | headless | headless | proc | True | 1 | yes | NO |
| pid1 | claude (native) | no | yes | no | default | interactive | headless | proc | True | 1 | NO | NO |
| pid1 | claude (node) | yes | yes | no | default | headless | headless | proc | True | 1 | yes | NO |
| pid1 | claude (node) | no | yes | no | default | interactive | headless | proc | True | 1 | NO | NO |
