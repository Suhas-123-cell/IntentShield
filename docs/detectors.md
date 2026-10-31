# Learned detectors: training, evaluation and negative results

Moved from the README on 2026-10-29. All of these are optional and evidence-only; the README keeps the summary.

## Train the local intent classifier

Install the optional training runtime and fine-tune the checked-in,
template-group-disjoint dataset:

```bash
uv pip install --python .venv/bin/python -r requirements-ml.txt
.venv/bin/python -m intentshield.intent_training \
  --output artifacts/intent-deberta-v3-small-v2 \
  --epochs 30 \
  --learning-rate 3e-5
```

These are the settings of the current artifact (2026-10-18). The default 5 epochs collapsed
to predicting `read` for everything. Point `INTENTSHIELD_INTENT_MODEL_DIR` at the output to
turn the model on; without it the gateway runs without it, which is how every MSB result
in [benchmarks.md](benchmarks.md) was measured.

The trainer pins the resolved `microsoft/deberta-v3-small` revision, seeds the
run, uses safetensors, and writes `intent_metadata.json`, `label_map.json`, and
`evaluation_report.json`. The runtime verifies every file hash and refuses an
artifact unless validation macro-F1 is at least 0.90 and every trained class has
at least 0.80 recall. The trained families are `read`, `mutation`, and
`no_action`; `unknown` is a runtime abstention. This classifier supplies intent
evidence only—it is not an injection detector and cannot authorize execution.

Inspect readiness:

```bash
curl http://127.0.0.1:8000/api/security/status
```

## Injection classifier

An optional second stage for the MCP proxy and the hooks: a DeBERTa-v3-small binary
classifier (`data` / `instruction`) run only on descriptions and outputs the rules
pass. It is off unless configured, and its hits are evidence for review only.

```bash
# needs a local Ollama model for the generated outputs and translations
.venv/bin/python benchmarks/injection_data.py --data artifacts/data/MCPTox-Benchmark
HF_HUB_OFFLINE=1 .venv/bin/python -m intentshield.injection_training \
  --dataset artifacts/injection/dataset.jsonl --batch-size 8
```

The dataset is MCPTox clean and poisoned descriptions, tool outputs written by
qwen2.5:7b (benign ones with instructions meant for humans; injected ones in polite,
false-error, as-the-user and new-task styles) and translations of 20% of rows into six
languages. Rows are split by MCPTox server (60/10/30); MSB is not used, so its held-out
split stays clean.

First run (11 October 2026, 1,931 train / 660 validation / 918 test rows, 3 epochs):

| Held-out test servers | Result |
|---|---|
| Injections caught (descriptions, outputs, all six languages) | 716/716 |
| Benign text flagged, overall | 20.3% (41/202) |
| Clean MCPTox descriptions flagged | 20.4% (22/108) |
| Benign generated outputs flagged | 12.1% (8/66) |
| Hand-written attack probes (polite, false error, Spanish, polite description) | 4/4 |
| Hand-written benign probes | 2/4 flagged |

This is a negative result. The threshold sits at the top of its grid (0.99) and still
flags one benign row in five, including "please submit your timesheets by Friday and
send questions to hr@acme.com" and "run npm install, then copy .env.example to .env".
The model learned "imperative plus an address" rather than "addressed to the agent".
Benign examples are scarce (about 5 injected rows per benign one) and the training loss
reached 0.0001, so scores saturate near 1.0. Do not enable it on this artifact; a usable
one needs many more benign rows with human-directed instructions.

**Loader bug, found and fixed 2026-10-13 (`dc8aee0`).** The shared model loader passed
`fix_mistral_regex=True` to the tokenizer (transformers 4.57 suggests it). For DeBERTa it
splits words into fragments ("Ignore" became "I", "gno", "re"), so the classifier, trained
without it, read noise at run time: through the runtime path it caught 19.4% of the held-out
injections, not the 100% its training report shows. Fixed, the runtime path matches the report.
On the injection evaluation with hard benign texts (below) it is still unusable: 46.5% of
injections caught and 24.4% of benign texts flagged, including 100% of human-to-human requests
and of reports quoting an attack, 78% of legitimate tool-usage guidance and 44% of agent-
addressed hints. The first DeBERTa intent model was trained with the same flag, so it learned
from fragmented tokens. It was retrained with a clean tokenizer on 2026-10-18
(`intent-deberta-v3-small-v2`); on MSB that did not help (see the MSB section of [benchmarks.md](benchmarks.md): as a veto it
still blocked the task tool often, and as advisory evidence it changes nothing measurable (the v11 traces record no intent evidence and no provenance, so it is not confirmed that the model was active in that arm; treat as unconfirmed)).

## Adaptive injection detection

Four learned parts sit beside the rules. All four count only as evidence: a hit withholds a
description or sends calls that reuse an output's values to review, and none of them allows
anything. Each is optional in the proxy config.

- **Llama Prompt Guard 2** on Groq's free tier (`prompt_guard.py`; `prompt_guard` in the config).
  Long texts are scored in overlapping windows, and the highest window score counts.
- **Exemplar detector** (`exemplars.py`). Text is chunked and embedded locally with
  multilingual-e5-small. A chunk scores the class-balanced, similarity-weighted share of
  injection chunks among its k nearest known chunks; a text scores its worst chunk. There is
  one threshold per kind (description or output), tuned on validation to at most 1% benign
  flags. On validation a plain nearest-neighbour score found 20% of injections, and the vote
  found about three times as many at the same false-flag rate.
- **Learning from operator labels** (`learning.py`). Every new example passes a regression
  gate. See [Teach the detector](#teach-the-detector-operator-labels-and-induced-rules).
- **Induced rules** (`signatures.py`). A local model proposes regexes for a learned injection.
  The gates refuse unsafe patterns, broad ones, patterns naming an address, URL or number,
  and any pattern matching non-test benign text. The operator approves each rule.

**Evaluation** (`benchmarks/injection_eval.py`; 3,717 texts, held out for the learned detectors; the
rules were tuned on 1,505 of the 2,959 injections, see below). The injections are
2,959 texts from the MCPTox test servers, generated injection styles, InjecAgent and AgentDojo.
The 758 benign texts include 142 hard ones (`benchmarks/hard_negatives.py`): tool descriptions
that legitimately guide the agent, results that tell the agent its next step, reports that
quote an attack, and human-to-human requests to pay, share or grant access. Hard examples are
split by topic, so test topics never seed or tune a detector. Each cell shows the share of
injections caught and the share of benign texts flagged:

| detector | injections caught | benign flagged | hard benign flagged |
|---|---|---|---|
| rules | 49.9% | 2.1% | 14/142 (12 are quoted attacks) |
| Prompt Guard 2 (86M, Groq) | 40.2% | 2.0% | 12/142 (all quoted attacks) |
| exemplars on outputs only | 11.4% | 0.4% | 1/142 |
| exemplars, descriptions and outputs (earlier index; `results/injection/report-local-2026-10-13.json`) | 20.7% | 2.4% | 9/142 (7 are usage-guidance descriptions) |
| injection classifier | 46.5% | 24.4% | 113/142 |
| rules + Prompt Guard | 51.1% | 2.6% | 15/142 |
| **rules + exemplars on outputs only** (default since this table) | **57.8%** | **2.5%** | **15/142** |
| rules + Prompt Guard + exemplars on outputs | 58.5% | 2.9% | 15/142 |
| any of the four (rules, classifier, Prompt Guard, exemplars on outputs) | 70.6% | 24.9% (189/758) | 113/142 |

The MCPTox poisoned descriptions (370) and the 81 AgentDojo important_instructions/system_message/tool_knowledge rows were used while writing the rules, and 1,054 InjecAgent 'enhanced' rows are trivially marked (1,505 of the 2,959 injections in all); on the remaining independent families the rules catch 2.1% (30/1,454) and rules+exemplars 18.1% (263/1,454).

Sources: the rules, Prompt Guard, exemplars-on-outputs and combination rows are
`results/injection/report-rules-pg-exemplars.json` (`table.txt` is its per-family print-out); the
classifier and any-of-the-four rows are `results/injection/report-with-classifier.json`; the
descriptions-and-outputs exemplar row is `results/injection/report-local-2026-10-13.json`, the earlier
index's run. An earlier version of this table gave 21.9% / 3.4% / 16/142 for that row and 25.9% / 118/142
for any-of-the-four, citing a gitignored report that no longer holds them: no stored artifact, so they are
replaced by the committed runs above.

**Rerun on 2026-10-29 with the 0.3.5 rules** (`results/injection/report-rules-pg-2026-10-29.json`; Prompt
Guard 2 scores from the same cache, so its column is unchanged). The rules now catch 50.9% and flag 2.2%
of benign texts (49.9% / 2.1% above). The difference is 27 AgentDojo "Ignore your previous iunstructions"
rows, caught since the override tolerates one typo, a rule written after this comparison showed the miss
(so those rows are no longer independent of the rules), and one translated quoted attack. By source, with
Wilson 95% intervals and an exact McNemar test on the paired verdicts:

| source | | rules | Prompt Guard 2 | only rules / only PG2 | p |
|---|---|---|---|---|---|
| InjecAgent (neither tuned on it) | attacks | 1,071/2,108 50.8% [48.7, 52.9] | 1,060/2,108 50.3% [48.2, 52.4] | 17 / 6 | 0.035 |
| AgentDojo (rules partly written from it) | attacks | 108/135 80.0% | 34/135 25.2% | 74 / 0 | <0.001 |
| AgentDojo | benign | 0/397 | 3/397 | 0 / 3 | 0.25 |
| LLM-written plain-language outputs | attacks | 13/346 3.8% | 0/346 0.0% | 13 / 0 | <0.001 |
| MCPTox descriptions (rules tuned on them) | attacks | 313/370 84.6% | 95/370 25.7% | 218 / 0 | <0.001 |
| MCPTox descriptions | benign | 2/128 | 0/128 | 2 / 0 | 0.5 |
| hard benign texts | benign | 15/142 10.6% | 12/142 8.5% | 3 / 0 | 0.25 |

On the 1,427 injections independent of the rules (InjecAgent base, the LLM-written outputs, AgentDojo
`direct`) the rules catch 30 (2.1%) and Prompt Guard 2 catches 6 (0.4%). Read together: on explicit
injections neither was tuned on, the rules and Prompt Guard 2 are level (half a point apart on InjecAgent);
both miss plain-language injections; the rules' large leads are on data they were written from. The rules
are an offline, keyless equal of Prompt Guard 2 on explicit attacks, not a better detector.

Each detector covers different ground:

- **Prompt Guard 2** catches the explicit styles: "ignore previous" 27/27, and the "enhanced"
  InjecAgent attacks 1,054/1,054, which the rules also catch. It adds 1.2 points to the rules.
  It catches no plain-language injection: polite and as-the-user outputs 0/144, InjecAgent base
  6/1,054, AgentDojo `direct` 0/27.
- **The exemplar detector** catches what resembles its seeds: generated styles 64-76%, MCPTox
  poisoned descriptions 86.7% (261/301) with the earlier descriptions-and-outputs index
  (`report-local-2026-10-13.json`). On descriptions its tuned threshold also flagged 7 of 36 legitimate
  usage-guidance descriptions in that run (an earlier figure of 12 of 36 has no stored artifact);
  validation held only 20 such texts. So the index now flags outputs only by default (`--kinds output`).
- **No usable detector** catches plain-language injections from an independent source.
  InjecAgent base stays at 1.5% (`ds_base`, 8/544) and 3.9% (`dh_base`, 20/510), pooled 28/1,054 = 2.7%,
  for rules + Prompt Guard + exemplars (`results/injection/table.txt`), and AgentDojo `direct` at
  1/27. Only the unusable classifier does better there: 30% of InjecAgent `ds` base, at a 24%
  benign flag rate. That is the gap learning from confirmed attacks is meant to close (below).

**Adaptive attacker** (`benchmarks/adaptive_attacker.py`). These are defensive measurements
of IntentShield's own detectors with benign canary addresses. 42 held-out seeds come from the
seven families the static detectors miss most. A local model (qwen2.5:7b) gets up to 5
attempts per seed, each one rewriting the last flagged text. An attempt counts only if it keeps
its canary and a local judge says it still asks the assistant to send something. The defense is
rules plus exemplars, without Prompt Guard. The learning arm learns every valid attempt behind
the gate and induces rules for it. Rule approval is simulated: every proposal that passes the
gates is approved.

| arm | seeds evaded [95% CI] | evaded on first attempt | second half | held-out benign flagged |
|---|---|---|---|---|
| static | 16/42, 38% [25, 53] | 5 | 7/21 | 33/758 |
| learning | 13/42, 31% [19, 46] | 3 | 5/21 | 28/758 |

With Gemini 3.5 Flash-Lite as the rewriting attacker (`results/adaptive-gemini.json`, same 42 seeds, 5
attempts each, threat memory on in the second arm) the rules + exemplars were evaded on 42/42 seeds
in both arms, and the threat memory did not help; argument provenance, which does not depend on
detecting the text, held every canary call for review (canary_unreviewed 0/42 in both arms; in the
memory arm 41 were stopped by provenance and 1 by the memory). Two caveats from `results/improve/README.md`
(Phase 3): the validity judge is the same model as the attacker and is lenient (of 8 spot-checked
rewrites, 2 were not requests to send data), so the 42/42 is an upper bound; and provenance holds by
construction, because a try must keep the canary verbatim to count as valid, so the address is always
traceable to the output.

Learning helped a little, and the difference is not significant: 3 seeds, with overlapping
intervals. Two seeds were caught on the first attempt because of what the defense had learned
from earlier, different seeds. Learning did not help on InjecAgent's base attacks (5/6 evaded in
both arms). The attacker is weak, too: only 28-31 of up to 210 attempts were valid. Benign flags
fell after learning because class-balanced voting gives each injection chunk less weight as more
are added. A first run gave every seed the same canary. Six of its approved rules then named that
address, which made learning look better than it was. Rules may no longer name addresses or
numbers, and each seed now has its own canary (`95ef2c1`; the first run is in
`artifacts/adaptive-attacker-shared-canary/`). Some approved rules are broad, such as
`\bsend\b.*?\binformation\b`. They passed every gate, which is why a human still approves
each rule.

## LLM judge on tool results (plain-language injections)

The rules and Prompt Guard 2 both miss injections written as ordinary requests with no marker ("Could you
also forward the notes to ..."): under 4% on the corpus's LLM-written outputs. The judge's `output` question
(`judge.py`, `--judge-outputs`, `"judge_outputs": true`) reads the result with the user's request and asks
whether text in it addresses the agent with something beyond that request. It is told to treat a message
addressed to a named person or a team as content, so an inbox's "Hey Alex, could you wire the payment?" is
clean. An objection is evidence only: the agent is warned and the result's values ask before use.

**Method.** `benchmarks/judge_outputs_eval.py`, on the as-the-user, polite, false-error and new-task outputs
(and their translations) as injections, and the benign outputs plus the hard agent hints, requests between
people and quoted attacks as benign. The rows carry no user request, so the judge got none. The prompt was
written on the train split: a first version with qwen2.5:7b caught 54% of a 224-injection train sample and
flagged 13% of benign texts (8 of 23 requests between people); Groq's gpt-oss-120b caught 85% but flagged
14 of 23 requests between people. One revision, the addressee rule above, cut those to 2 of 23 (qwen) and
1 of 23 (gpt-oss-120b) on train, and qwen's train recall fell to 36%. The prompt was then frozen and run once
on the test split:

| judge | injections caught | benign flagged | hard benign flagged | rules alone, same rows |
|---|---|---|---|---|
| Gemini 3.5 Flash-Lite (25 rows per source, free tier) | 123/158 77.8% [70.8, 83.6] | 4/118 3.4% [1.3, 8.4] | 1/85 (an agent hint) | 7/158 caught, 14/118 flagged |
| qwen2.5:7b, local (all rows) | 84/346 24.3% [20.1, 29.1] | 1/176 0.6% [0.1, 3.1] | 0/102 | 13/346 caught, 15/176 flagged |

By style (Gemini): as the user 27/33, polite 31/44, false error 25/33, new task 40/48. The rules' benign
flags are the quoted attacks, which the judge reads correctly as reports. Rules and judge together:
78.5% caught and 15.3% benign flagged with Gemini, 27.2% and 9.1% with qwen.

**Limits.** The injections were written by an LLM for this corpus, in four styles; real attacks will differ.
The default provider, Groq's gpt-oss-120b, was not run on the test split: its free tier allows 200,000
tokens a day, which the train runs used up, and about 200 judged results would use up a day in normal use.
Gemini takes about 4 s per result and local qwen about 1 s, on every result the rules pass. Results:
`results/judge/outputs-gemini-flash-lite-test.json`, `results/judge/outputs-qwen2.5-7b-test.json`.

**Since 0.4.0** the prompt (v2.1) also names rules for how the work must be done, requests to whoever
reads or forwards the result, and text that speaks to the reviewer or vouches for itself. On the same
test split qwen2.5:7b catches 101/346 (29.2%) and flags 6/176 benign (3.4%), against 84/346 and 1/176
with the first prompt; DeepSeek's `deepseek-flash` (paid) catches 298/346 (86.1%) and flags 13/176 (7.4%), none
of them requests between people or quoted attacks. These are judge-alone rates: with the rules, which still run, the
same rows flag 20/176 (11.4%, qwen v2.1) and 27/176 (15.3%, DeepSeek), and 13 of the rules' flags are on 24 texts that
quote an attack. DeepSeek's and Gemini's recalls are on different row sets and prompts and are not ranked. Thirty hand-written jailbreaks and an adaptive attacker that sees the judge's
prompt and verdicts were run against it; the method and numbers are in
[benchmarks.md](benchmarks.md#attacks-on-the-output-judge).

## Teach the detector (operator labels and induced rules)

With `exemplar_index_dir` and `learning_regression` set in the proxy config, the
operator can teach the exemplar detector (`src/intentshield/learning.py`). Only the
operator labels; tool output is what gets labelled, never who labels. A decision may
carry a label: `injection` with a rejection, `benign` with an approval. The proxy
learns the outputs whose values the reviewed call reused (for `injection`, any flagged
output of the run when none was reused), and an approval never teaches a flagged output
as benign:

```bash
curl -X POST -H "Authorization: Bearer $INTENTSHIELD_CONTROL_TOKEN" -H "content-type: application/json" \
  -d '{"decision":"reject","learn":"injection"}' http://127.0.0.1:8001/control/approvals/APPROVAL_ID
# label a text directly, and see what was learned and why
curl -X POST ... -d '{"text":"...","label":"injection"}' http://127.0.0.1:8001/control/learning/examples
curl -H "Authorization: Bearer $INTENTSHIELD_CONTROL_TOKEN" http://127.0.0.1:8001/control/learning
```

Every example passes a regression gate before it goes live: an injection example is
refused if any benign text of the regression set (the `validation` rows of the
`learning_regression` files) becomes flagged, a benign one if any regression injection
stops being flagged. Refused examples stay listed with their gate result. Learned
examples persist in the proxy database and are replayed at start. Learning changes only
the exemplar detector: rules, quarantine and the review of mutations are untouched.

With `signature_model` set (a local Ollama model), the operator can ask for rules for a
learned injection. Proposals must compile, avoid nested quantifiers, lookarounds and
backreferences, carry at least 12 literal letters, match their source and match no
non-test benign text; the ones that pass wait as `pending` until approved:

```bash
curl -X POST ... -d '{"example_id":"EXAMPLE_ID"}' http://127.0.0.1:8001/control/rules/propose
curl -X POST ... -d '{"decision":"approve"}' http://127.0.0.1:8001/control/rules/RULE_ID
curl -H "Authorization: Bearer $INTENTSHIELD_CONTROL_TOKEN" http://127.0.0.1:8001/control/rules
```

Learned examples, approved rules, Prompt Guard 2 (`prompt_guard`) and the local
classifier are all evidence: a hit withholds a description or sends calls that reuse an
output's values to review; none of them allows anything.
