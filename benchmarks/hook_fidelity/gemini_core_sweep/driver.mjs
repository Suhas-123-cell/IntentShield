// Gemini CLI hook-runner sweep driver. Usage: node driver.mjs <pkg-prefix-dir> <version-label> <out.jsonl>
// Drives @google/gemini-cli-core's HookRunner + HookAggregator (layer A) and, where the constructor
// shape allows, HookEventHandler.fireBeforeToolEvent (layer B) with a stub config. No model, no network.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const [prefix, label, outFile] = process.argv.slice(2);
if (!prefix || !label || !outFile) { console.error('usage: driver.mjs <prefix> <label> <out.jsonl>'); process.exit(2); }
const pkgDir = path.join(prefix, 'node_modules', '@google', 'gemini-cli-core');
const pkgVersion = JSON.parse(fs.readFileSync(path.join(pkgDir, 'package.json'), 'utf8')).version;
const hooksDir = path.join(pkgDir, 'dist', 'src', 'hooks');
const imp = (f) => import(pathToFileURL(path.join(hooksDir, f)).href);
const { HookRunner } = await imp('hookRunner.js');
const { HookAggregator } = await imp('hookAggregator.js');
const { HookEventHandler } = await imp('hookEventHandler.js');
const types = await imp('types.js');

const work = fs.mkdtempSync(path.join(os.tmpdir(), 'gsweep-'));  // os.tmpdir honours TMPDIR (scratchpad)
const plans = path.join(work, 'plans'); fs.mkdirSync(plans);
const hookDir = path.join(work, 'hooks'); fs.mkdirSync(hookDir);

const baseConfig = {
  getGeminiClient: () => undefined,
  isTrustedFolder: () => true,
  sanitizationConfig: { allowedEnvironmentVariables: [], blockedEnvironmentVariables: [], enableEnvironmentVariableRedaction: false },
  storage: { getPlansDir: () => plans },
  getSessionId: () => 'sweep-session',
  getWorkingDir: () => work,
  getTargetDir: () => work,
};
// Telemetry/other accessors the runner never needs for decisions: answer false so layer B can run.
const config = new Proxy(baseConfig, { get: (t, k) => (k in t ? t[k] : (typeof k === 'string' && /^(get|is|has)/.test(k) ? () => false : undefined)) });

import { makeScenarios } from './scenarios.mjs';
const S = makeScenarios(work, hookDir);

// Guard replay (benchmarks/hook_fidelity/guard_replay.py): REPLAY_DIR holds index.json plus one <id>.json per captured guard reply
// (stdout_b64, stderr_b64, exit_code). Each becomes a scenario whose hook is stubhook.py in replay mode, so the real runner and
// aggregator see the exact bytes a third-party guard produced. REPLAY_ONLY=1 drops the 34 built-in scenarios.
if (process.env.REPLAY_DIR) {
  const dir = process.env.REPLAY_DIR;
  const index = JSON.parse(fs.readFileSync(path.join(dir, 'index.json'), 'utf8'));
  if (process.env.REPLAY_ONLY === '1') S.length = 0;
  const py = process.env.REPLAY_PYTHON || 'python3';
  const stubhook = process.env.REPLAY_STUBHOOK;
  for (const item of index) {
    add(`replay:${item.id}`, `${py} -I ${q(stubhook)} --harness gemini --reply RP --run-id ${item.id} --log ${q(path.join(work, 'replay-hooks.jsonl'))} --replay-file ${q(path.join(dir, item.id + '.json'))}`);
  }
}

const rid = (r) => ({ success: r.success, exitCode: r.exitCode ?? null, outputFormat: r.outputFormat ?? null,
  stdoutLen: (r.stdout ?? '').length, stderrHead: (r.stderr ?? '').slice(0, 400),
  error: r.error ? String(r.error.message ?? r.error).slice(0, 160) : null, output: r.output ?? null, durationMs: r.duration });

function classify(agg) {
  const f = agg.finalOutput;
  if (!f) return { decision: 'none', proceeds: 'yes', note: agg.errors.length ? 'no output; hook error ignored by consumer' : 'no output; no decision' };
  const stop = typeof f.shouldStopExecution === 'function' && f.shouldStopExecution();
  const blk = typeof f.getBlockingError === 'function' ? f.getBlockingError() : { blocked: f.decision === 'deny' || f.decision === 'block' };
  const ask = typeof f.isAskDecision === 'function' ? f.isAskDecision() : f.decision === 'ask';
  if (stop) return { decision: 'stop', proceeds: 'no', note: 'continue:false' };
  if (blk.blocked) return { decision: 'deny', proceeds: 'no', note: String(blk.reason ?? '').slice(0, 80) };
  if (ask) return { decision: 'ask', proceeds: 'ask-kept', note: 'aggregator kept the ask; what the scheduler and the tool do with it (prompt, drop, wait) is NOT driven here' };
  return { decision: 'allow', proceeds: 'yes', note: f.decision === undefined ? 'decision field absent' : '' };
}
const fo = (agg) => agg.finalOutput ? { decision: agg.finalOutput.decision ?? null, reason: agg.finalOutput.reason ?? null,
  systemMessage: agg.finalOutput.systemMessage ? String(agg.finalOutput.systemMessage).slice(0, 120) : null, continue: agg.finalOutput.continue ?? null } : null;

const runner = new HookRunner(config);
const aggregator = new HookAggregator();
const input = { session_id: 'sweep-session', transcript_path: '', cwd: work, hook_event_name: 'BeforeTool',
  timestamp: new Date().toISOString(), tool_name: 'mcp_x_t', tool_input: { a: 1 } };
const out = fs.createWriteStream(outFile);
const hookType = types.HookType?.Command ?? 'command';
const source = types.ConfigSource?.User ?? 'user';

async function layerB(cfgs) {
  try {
    const planner = { createExecutionPlan: () => ({ hookConfigs: cfgs, sequential: false }) };
    let h;
    // constructor shape differs by release: (config, logger, planner, runner, aggregator, bus) | (config, planner, runner, aggregator) | (context, planner, runner, aggregator)
    const n = HookEventHandler.length;
    const first = (/constructor\((\w+)/.exec(HookEventHandler.toString()) || [])[1];
    if (n >= 6) h = new HookEventHandler(config, { debug() {}, warn() {}, error() {} }, planner, runner, aggregator, undefined);
    else if (first === 'config') h = new HookEventHandler(config, planner, runner, aggregator);
    else h = new HookEventHandler({ config, geminiClient: undefined }, planner, runner, aggregator);
    const agg = await h.fireBeforeToolEvent('mcp_x_t', { a: 1 });
    return { ok: true, ...classify(agg), aggSuccess: agg.success, errors: agg.errors.map((e) => String(e.message).slice(0, 100)), finalOutput: fo(agg) };
  } catch (e) { return { ok: false, error: String(e?.message ?? e).slice(0, 160) }; }
}

const withTimeout = (promise, ms) => ms ? Promise.race([promise, new Promise((r) => setTimeout(() => r({ __unbounded: true }), ms))]) : promise;
for (const s of S) {
  const commands = s.commands ?? [s.command];
  const cfgs = commands.map((command, i) => ({ type: hookType, command, name: `${s.name}-${i}`, source, ...(s.timeout ? { timeout: s.timeout } : {}) }));
  const t0 = Date.now();
  let rec;
  try {
    const event = types.HookEventName?.BeforeTool ?? 'BeforeTool';
    const results = await withTimeout(Promise.all(cfgs.map((c) => runner.executeHook(c, event, input))), s.bounded);
    if (results.__unbounded) {
      rec = { version: label, pkgVersion, scenario: s.name, layerA: { decision: 'no-return', proceeds: 'hang', note: `executeHook did not return within ${s.bounded} ms`, run: { exitCode: null } }, layerB: { ok: true, decision: 'not-run', proceeds: 'not-run', note: 'skipped: layer A did not return' }, wallMs: Date.now() - t0 };
    } else {
      const agg = aggregator.aggregateResults(results, event);
      const lb = await layerB(cfgs);
      rec = { version: label, pkgVersion, scenario: s.name, layerA: { run: rid(results[0]), runs: results.length, agg: { success: agg.success, errors: agg.errors.map((e) => String(e.message).slice(0, 100)), finalOutput: fo(agg) }, ...classify(agg) }, layerB: lb, wallMs: Date.now() - t0 };
    }
  } catch (e) {
    rec = { version: label, pkgVersion, scenario: s.name, driverError: String(e?.stack ?? e).slice(0, 400) };
  }
  out.write(JSON.stringify(rec) + '\n');
}
out.end();
await new Promise((r) => out.on('finish', r));
fs.rmSync(work, { recursive: true, force: true });
process.exit(0);
