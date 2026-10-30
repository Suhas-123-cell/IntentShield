# IntentShield documentation

## Using IntentShield

- [guide.md](guide.md): running the dashboard, the Streamable HTTP gateway, the transparent proxy, the harness hooks, threat memory and packs, production settings and the REST API.
- [architecture-and-testing.md](architecture-and-testing.md): module map, entry paths, the full test sequence and failure diagnosis.
- [benchmarks.md](benchmarks.md): every benchmark protocol and table (MSB, MCPTox, InjecAgent, AgentDojo, judge, self-disclosure, live harness checks, replayed incidents) and the limits of each.
- [detectors.md](detectors.md): the optional learned detectors, their training, evaluation, negative results, the adaptive attacker and how the operator teaches them.
- [security-review.md](security-review.md): the 2026-10-30 review of the guard itself, with each finding's severity and status, the measured effect of the fixes and what is still open.

## Research notes, not user docs

- [artifact-paper.md](artifact-paper.md): draft of the artifact paper (one guard across four harnesses and a proxy).
- [paper-draft.md](paper-draft.md): the earlier complete-mediation draft; its claim is not supported, see its status note.
- [contribution.md](contribution.md): what the repository does and does not support as a contribution, the routes to a paper, the comparison with other guards and the architecture verdict.
- [related-work.md](related-work.md): literature survey and the adaptivity plan.
- [coverage-study.md](coverage-study.md): which MCP channels a hook-scoped guard sees versus a proxy, measured with benign markers.
- [icse27-demo/](icse27-demo/): demo-track paper source and video script.
