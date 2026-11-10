# Archived Claude Code documents (retrieved 2026-11-01)

The seven documentation pages below were fetched with `curl -L https://code.claude.com/docs/en/<page>.md` on 2026-11-01
by the r3-claude lane and read unedited. They are the vendor documents that `benchmarks/hook_fidelity/signoffs.json`
cites for the Claude Code config items. The page texts are not redistributed here: they are Anthropic's documentation,
with no licence that allows a copy. To check a quotation, fetch the page and compare; the hashes are of the files the
study read, so a page that has changed since will not match. The docs carry no version number except where a sentence
says "requires v2.1.xxx". The claude-help files, which are kept, are the `--help` text of the installed releases
(`claude --help` under an isolated HOME, no login), which pins flag names per version.

| file | source | sha256 |
|---|---|---|
| hooks.md | https://code.claude.com/docs/en/hooks | 8e4d5d8c03b5a4cd0e6fe15cc8d71d782a5acc29cf738c584337d024ff1e4ca1 |
| permissions.md | https://code.claude.com/docs/en/permissions | a72bafb46a558dec5a641916b6f1482b101a8b4ca7602f0a2d3fb636b0b3c25c |
| permission-modes.md | https://code.claude.com/docs/en/permission-modes | 15c45266ded0eb4aaf86b0da1561369981d7d435c44fd7245481ea25fbc06ca3 |
| tools-reference.md | https://code.claude.com/docs/en/tools-reference | 9ae5dd8849a7fd22565136df6267aff95c0cbadb06afefb0fe48ccb727bdc72d |
| cli-reference.md | https://code.claude.com/docs/en/cli-reference | 9a68c8f3c42d6b42031f6b3080f9a6c32e86aac6fb3f2ffb1aaae1abeb3d4f07 |
| env-vars.md | https://code.claude.com/docs/en/env-vars | c6af9335007280dfe50572702d0025e0d4bb8dc28554f607cb739614b7b5c096 |
| headless.md | https://code.claude.com/docs/en/headless | 208eeb28afce5a433539821ec42ad3b077bb76420ee7ce6e21ce9cbe08cc2054 |
| claude-help-2.1.316.txt | `claude --help`, 2.1.316 | 5ca3a9dac2026e56c221fdd34380c7d7d45ebbb51c1d01b7c17c75cb076a0be8 |
| help/<version>.txt | `claude --help` of each of the 23 installed releases 2.0.41 to 2.1.316 | see the files |
