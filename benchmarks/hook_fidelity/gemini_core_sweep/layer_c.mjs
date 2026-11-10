// Layer C: the real HookSystem (registry, planner, runner, aggregator, event handler) built from a settings-shaped
// hooks.BeforeTool config on a real Config. usage: node layer_c.mjs <prefix> <label> <out.jsonl>
import fs from 'node:fs'; import os from 'node:os'; import path from 'node:path'; import { pathToFileURL } from 'node:url';
import { makeScenarios } from './scenarios.mjs';
const [prefix, label, outFile] = process.argv.slice(2);
const pkgDir = path.join(prefix, 'node_modules', '@google', 'gemini-cli-core');
const pkgVersion = JSON.parse(fs.readFileSync(path.join(pkgDir, 'package.json'), 'utf8')).version;
const core = await import(pathToFileURL(path.join(pkgDir, 'dist', 'index.js')).href);
const { HookSystem } = await import(pathToFileURL(path.join(pkgDir, 'dist', 'src', 'hooks', 'hookSystem.js')).href);
const work = fs.mkdtempSync(path.join(os.tmpdir(), 'glc-'));
const hookDir = path.join(work, 'hooks'); fs.mkdirSync(hookDir);
const S = makeScenarios(work, hookDir);
const logf = path.join(work, 'invocations.log');
const counter = (name, reply) => { const p = path.join(hookDir, name); fs.writeFileSync(p, `#!/bin/bash\ncat >/dev/null; echo x >> '${logf}'; echo '${reply}'\n`, { mode: 0o755 }); return `'${p}'`; };

function classify(f) {
  if (!f) return { decision: 'none', proceeds: 'yes' };
  const stop = typeof f.shouldStopExecution === 'function' && f.shouldStopExecution();
  const blk = typeof f.getBlockingError === 'function' ? f.getBlockingError() : { blocked: f.decision === 'deny' || f.decision === 'block' };
  const ask = typeof f.isAskDecision === 'function' ? f.isAskDecision() : f.decision === 'ask';
  if (stop) return { decision: 'stop', proceeds: 'no' };
  if (blk.blocked) return { decision: 'deny', proceeds: 'no' };
  if (ask) return { decision: 'ask', proceeds: 'ask-kept' };
  return { decision: 'allow', proceeds: 'yes' };
}
const withTimeout = (p, ms) => Promise.race([p, new Promise((r) => setTimeout(() => r({ __unbounded: true }), ms))]);

async function viaSystem({ hooksConfig, toolName, bounded = 20000, enableHooks = true, folderTrust = false, trustedFolder = true }) {
  const params = { sessionId: 'c', targetDir: work, cwd: work, debugMode: false, model: 'gemini-test', interactive: false, folderTrust, trustedFolder, hooks: hooksConfig };
  if (enableHooks !== undefined) params.enableHooks = enableHooks;
  const config = new core.Config(params);
  if (typeof config.storage?.initialize === 'function') await config.storage.initialize();
  const hs = new HookSystem(config);
  await hs.initialize();
  const handler = hs.getEventHandler();
  const t0 = Date.now();
  const agg = await withTimeout(handler.fireBeforeToolEvent(toolName, { a: 1 }), bounded);
  if (agg.__unbounded) return { decision: 'no-return', proceeds: 'hang', wallMs: Date.now() - t0 };
  return { ...classify(agg.finalOutput), errors: (agg.errors ?? []).map((e) => String(e.message).slice(0, 100)), wallMs: Date.now() - t0 };
}

const out = fs.createWriteStream(outFile);
const emit = (rec) => out.write(JSON.stringify({ version: label, pkgVersion, ...rec }) + '\n');
const TOOL = 'run_shell_command';
for (const s of S) {
  const commands = s.commands ?? [s.command];
  const hooks = commands.map((command, i) => ({ type: 'command', command, name: `${s.name}-${i}`, ...(s.timeout ? { timeout: s.timeout } : {}) }));
  try {
    emit({ scenario: s.name, kind: 'reply', config: 'one matcher group, matcher ".*"', ...await viaSystem({ hooksConfig: { BeforeTool: [{ matcher: '.*', hooks }] }, toolName: TOOL, bounded: s.bounded ?? 20000 }) });
  } catch (e) { emit({ scenario: s.name, kind: 'reply', driverError: String(e?.stack ?? e).slice(0, 400) }); }
}
// multi-hook aggregation across SEPARATE matcher groups and with the sequential flag
const A = counter('ca.sh', '{"decision":"ask","reason":"needs review"}');
const AL = counter('cl.sh', '{"decision":"allow"}');
const D = counter('cd.sh', '{"decision":"deny","reason":"blocked"}');
const group = (matcher, cmds, extra = {}) => ({ matcher, ...extra, hooks: cmds.map((command, i) => ({ type: 'command', command, name: `h${i}-${matcher}` })) });
const extra = [
  ['groups_ask_then_allow', [group('.*', [A]), group('.*', [AL])], TOOL],
  ['groups_allow_then_ask', [group('.*', [AL]), group('.*', [A])], TOOL],
  ['groups_deny_then_allow', [group('.*', [D]), group('.*', [AL])], TOOL],
  ['seq_ask_then_deny', [{ matcher: '.*', sequential: true, hooks: [{ type: 'command', command: A, name: 'q0' }, { type: 'command', command: D, name: 'q1' }] }], TOOL],
  ['dedupe_identical_hook_twice', [group('.*', [D]), group('.*', [D])], TOOL, true],
  // matcher semantics against the tool name the hook sees (BeforeTool, deny hook, so "deny/no" means the matcher selected it)
  ['matcher_exact_shell_vs_shell', [group('run_shell_command', [D])], 'run_shell_command'],
  ['matcher_exact_shell_vs_mcp', [group('run_shell_command', [D])], 'mcp_notes_search_notes'],
  ['matcher_substring_vs_shell', [group('run_shell', [D])], 'run_shell_command'],
  ['matcher_dotstar_search_notes_vs_mcp', [group('.*search_notes.*', [D])], 'mcp_notes_search_notes'],
  ['matcher_dotstar_search_notes_vs_mcp_dunder', [group('.*search_notes.*', [D])], 'notes__search_notes'],
  ['matcher_claude_style_mcp_vs_mcp', [group('mcp__notes__search_notes', [D])], 'mcp_notes_search_notes'],
  ['matcher_claude_style_mcp_vs_dunder', [group('mcp__notes__search_notes', [D])], 'notes__search_notes'],
  ['matcher_mcp_prefix_vs_mcp', [group('mcp_notes_.*', [D])], 'mcp_notes_search_notes'],
  ['matcher_bash_vs_shell', [group('Bash', [D])], 'run_shell_command'],
  ['matcher_write_alt_vs_write_file', [group('write_file|replace', [D])], 'write_file'],
  ['matcher_write_alt_vs_shell', [group('write_file|replace', [D])], 'run_shell_command'],
  ['matcher_star_vs_shell', [group('*', [D])], 'run_shell_command'],
  ['matcher_empty_vs_shell', [group('', [D])], 'run_shell_command'],
  ['matcher_absent_vs_shell', [{ hooks: [{ type: 'command', command: D, name: 'nm' }] }], 'run_shell_command'],
  ['matcher_invalid_regex_literal_vs_literal', [group('run_shell_command(', [D])], 'run_shell_command('],
];
const trustCases = [['trust_folderTrust_on_folder_trusted', { folderTrust: true, trustedFolder: true }], ['trust_folderTrust_on_folder_untrusted', { folderTrust: true, trustedFolder: false }]];
for (const [name, tr] of trustCases) {
  try { fs.rmSync(logf, { force: true }); const r = await viaSystem({ hooksConfig: { BeforeTool: [group('.*', [D])] }, toolName: TOOL, ...tr });
    emit({ scenario: name, kind: 'trust', trust: tr, invocations: fs.existsSync(logf) ? fs.readFileSync(logf, 'utf8').trim().split('\n').length : 0, ...r });
  } catch (e) { emit({ scenario: name, kind: 'trust', driverError: String(e?.stack ?? e).slice(0, 400) }); }
}
for (const [name, bt, tool, dup] of extra) {
  try {
    fs.rmSync(logf, { force: true });
    const r = await viaSystem({ hooksConfig: { BeforeTool: bt }, toolName: tool });
    const invocations = fs.existsSync(logf) ? fs.readFileSync(logf, 'utf8').trim().split('\n').length : 0;
    emit({ scenario: name, kind: name.startsWith('matcher_') ? 'matcher' : 'multi', tool, invocations, ...r });
  } catch (e) { emit({ scenario: name, kind: 'multi', driverError: String(e?.stack ?? e).slice(0, 400) }); }
}
// enableHooks: not passed (the Config default of this release) vs passed false vs true; and whether a HookSystem exists on a real initialised Config
try {
  const cfg = new core.Config({ sessionId: 'c', targetDir: work, cwd: work, debugMode: false, model: 'gemini-test', interactive: false, hooks: { BeforeTool: [{ matcher: '.*', hooks: [{ type: 'command', command: D, name: 'ee' }] }] } });
  emit({ scenario: 'config_default_enableHooks', kind: 'default', getEnableHooks: typeof cfg.getEnableHooks === 'function' ? cfg.getEnableHooks() : 'no-accessor' });
} catch (e) { emit({ scenario: 'config_default_enableHooks', kind: 'default', driverError: String(e).slice(0, 300) }); }
out.end(); await new Promise((r) => out.on('finish', r));
fs.rmSync(work, { recursive: true, force: true });
process.exit(0);
