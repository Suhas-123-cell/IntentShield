// Consumer-side probe: drives the real Scheduler (hook -> policy -> confirmation -> execute) of an installed @google/gemini-cli-core
// against a real Config, real PolicyEngine (default TOML policies via createPolicyEngineConfig), real ShellTool and a
// DiscoveredMCPTool whose server connection is replaced by an in-process stub. No model, no network. HOME must be an isolated directory.
// usage: node consumer_probe.mjs <prefix> <label> <out.jsonl> [scenario-filter-regex]
import fs from 'node:fs'; import os from 'node:os'; import path from 'node:path'; import { pathToFileURL } from 'node:url';
const [prefix, label, outFile, filter] = process.argv.slice(2);
const pkgDir = path.join(prefix, 'node_modules', '@google', 'gemini-cli-core');
const pkgVersion = JSON.parse(fs.readFileSync(path.join(pkgDir, 'package.json'), 'utf8')).version;
const imp = (rel) => import(pathToFileURL(path.join(pkgDir, rel)).href);
const core = await imp('dist/index.js');
const { createPolicyEngineConfig } = await imp('dist/src/policy/config.js');
const { DiscoveredMCPTool, DiscoveredMCPToolInvocation } = await imp('dist/src/tools/mcp-tool.js');
const { Scheduler } = await imp('dist/src/scheduler/scheduler.js');
const { MessageBusType } = await imp('dist/src/confirmation-bus/types.js');
const { ShellTool } = await imp('dist/src/tools/shell.js');

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'gcp-'));
const hookDir = path.join(root, 'hooks'); fs.mkdirSync(hookDir);
const script = (name, body) => { const p = path.join(hookDir, name); fs.writeFileSync(p, `#!/bin/bash\n${body}\n`, { mode: 0o755 }); return p; };
const HOOKS = {
  ask: script('ask.sh', `cat >/dev/null; echo '{"decision":"ask","reason":"needs review"}'`),
  allow: script('allow.sh', `cat >/dev/null; echo '{"decision":"allow"}'`),
  deny: script('deny.sh', `cat >/dev/null; echo '{"decision":"deny","reason":"blocked by guard"}'`),
  none: null,
};
const MAX_WAIT = Number(process.env.PROBE_WAIT_MS ?? 8000);

async function runOne(sc) {
  const work = fs.mkdtempSync(path.join(root, 'w-')); fs.mkdirSync(path.join(work, '.gemini'), { recursive: true });
  const marker = path.join(work, 'ran-marker.txt');
  const interactive = sc.interactive;
  const settings = { mcpServers: { notes: { command: 'unused', trust: !!sc.trust } }, mcp: sc.mcpAllowed ? { allowed: ['notes'] } : {}, tools: sc.excludeShell ? { exclude: ['run_shell_command'] } : {} };
  const approvalMode = sc.approval;
  const policy = await createPolicyEngineConfig(settings, approvalMode, undefined, interactive);
  if (sc.denyRule) policy.rules.push({ toolName: sc.denyRule, argsPattern: sc.tool === 'shell' ? /ran-marker/ : /"query"/, decision: 'deny', priority: 4.95, source: 'probe (argument-scoped deny keeps the tool registered)' });
  const hooks = HOOKS[sc.hook] ? { BeforeTool: [{ matcher: '.*', hooks: [{ type: 'command', command: `'${HOOKS[sc.hook]}'`, name: 'probe-hook', timeout: 5000 }] }] } : undefined;
  const config = new core.Config({ sessionId: 'p', targetDir: work, cwd: work, debugMode: false, model: 'gemini-test', interactive,
    approvalMode, folderTrust: sc.folderTrust ?? false, trustedFolder: sc.trustedFolder ?? true, policyEngineConfig: policy, enableHooks: true, hooks, mcpServers: settings.mcpServers,
    // no model is contacted: tools are registered by hand below
  });
  await config.initialize();
  if (typeof config.storage?.initialize === 'function') await config.storage.initialize();
  DiscoveredMCPToolInvocation.allowlist?.clear?.(); if (sc.sessionAllowlist) DiscoveredMCPToolInvocation.allowlist.add('notes');
  const bus = config.getMessageBus();
  const registry = config.getToolRegistry();
  let toolName, args;
  if (sc.tool === 'shell') {
    toolName = 'run_shell_command'; args = { command: `touch '${marker}'` };
    if (!registry.getTool(toolName)) registry.registerTool(new ShellTool(config, bus));
  } else {
    const mcpTool = { callTool: async () => { fs.writeFileSync(marker, 'mcp'); return [{ functionResponse: { name: 'search_notes', response: { content: [{ type: 'text', text: 'ok' }] } } }]; } };
    const tool = new DiscoveredMCPTool(mcpTool, 'notes', 'search_notes', 'stub search', { type: 'object', properties: { query: { type: 'string' } } }, bus, !!sc.trust, false, undefined, config);
    registry.registerTool(tool); toolName = tool.name; args = { query: 'x' };
  }
  const states = [];
  try { bus.subscribe(MessageBusType.TOOL_CALLS_UPDATE, (m) => { for (const c of m.toolCalls ?? []) { const s = c.status; if (states[states.length - 1] !== s) states.push(s); } }); } catch { /* old bus shape */ }
  const scheduler = new Scheduler({ context: config, getPreferredEditor: () => undefined, schedulerId: 'probe' });
  const ac = new AbortController();
  const t0 = Date.now();
  let settled = false, results, thrown;
  const p = scheduler.schedule([{ callId: 'c1', name: toolName, args, isClientInitiated: false, prompt_id: 'p1' }], ac.signal)
    .then((r) => { settled = true; results = r; }, (e) => { settled = true; thrown = e; });
  await Promise.race([p, new Promise((r) => setTimeout(r, MAX_WAIT))]);
  const ran = fs.existsSync(marker);
  const waitedMs = Date.now() - t0;
  let outcome;
  if (!settled) outcome = states.includes('awaiting_approval') ? 'PROMPT-WAIT' : 'HANG-NO-PROMPT';
  else if (thrown) outcome = 'THROWN';
  else { const r = results?.[0]; outcome = ran ? 'RAN' : (r?.status === 'error' ? 'ERROR' : (r?.status ?? 'unknown').toUpperCase()); }
  const r0 = results?.[0];
  const rec = { scenario: sc.name, ...sc, outcome, ran, settled, waitedMs, states, error: thrown ? String(thrown.message).slice(0, 200) : (r0?.response?.error ? String(r0.response.error.message).slice(0, 200) : null), errorType: r0?.response?.errorType ?? null };
  ac.abort(); try { scheduler.dispose?.(); } catch { /* */ }
  return rec;
}

const base = { approval: 'yolo', interactive: false, tool: 'shell', hook: 'none', trust: false };
const sc = [];
const add = (name, o) => sc.push({ name, ...base, ...o });
for (const tool of ['shell', 'mcp']) for (const [approval, interactive] of [['default', true], ['default', false], ['yolo', true], ['yolo', false]]) for (const hook of ['none', 'allow', 'ask', 'deny']) for (const trust of tool === 'mcp' ? [false, true] : [false]) {
  add(`${tool}|${approval}|${interactive ? 'interactive' : 'headless'}|hook=${hook}${tool === 'mcp' ? `|trust=${trust}` : ''}`, { tool, approval, interactive, hook, trust });
}
add('mcp|default|headless|hook=ask|mcp.allowed', { tool: 'mcp', approval: 'default', interactive: false, hook: 'ask', mcpAllowed: true });
add('mcp|default|interactive|hook=ask|mcp.allowed', { tool: 'mcp', approval: 'default', interactive: true, hook: 'ask', mcpAllowed: true });
add('mcp|yolo|headless|hook=ask|trust=true|folderTrust-on|folder-untrusted', { tool: 'mcp', approval: 'yolo', interactive: false, hook: 'ask', trust: true, folderTrust: true, trustedFolder: false });
add('mcp|yolo|headless|hook=ask|trust=true|folderTrust-on|folder-trusted', { tool: 'mcp', approval: 'yolo', interactive: false, hook: 'ask', trust: true, folderTrust: true, trustedFolder: true });
add('mcp|yolo|interactive|hook=ask|trust=false|session-allowlist', { tool: 'mcp', approval: 'yolo', interactive: true, hook: 'ask', sessionAllowlist: true });
add('mcp|default|interactive|hook=ask|trust=false|session-allowlist', { tool: 'mcp', approval: 'default', interactive: true, hook: 'ask', sessionAllowlist: true });
add('shell|yolo|interactive|hook=ask|policy-deny-rule', { interactive: true, hook: 'ask', denyRule: 'run_shell_command' });
add('shell|yolo|headless|hook=ask|policy-deny-rule', { interactive: false, hook: 'ask', denyRule: 'run_shell_command' });
add('shell|default|headless|hook=ask|tools.exclude', { approval: 'default', interactive: false, hook: 'ask', excludeShell: true });
add('shell|yolo|headless|hook=none|policy-deny-rule', { interactive: false, hook: 'none', denyRule: 'run_shell_command' });
add('shell|yolo|headless|hook=allow|policy-deny-rule', { interactive: false, hook: 'allow', denyRule: 'run_shell_command' });
add('mcp|yolo|headless|hook=ask|policy-deny-rule', { tool: 'mcp', interactive: false, hook: 'ask', denyRule: 'mcp_notes_*' });
add('mcp|yolo|headless|hook=none|policy-deny-rule', { tool: 'mcp', interactive: false, hook: 'none', denyRule: 'mcp_notes_*' });
add('mcp|yolo|headless|hook=allow|policy-deny-rule', { tool: 'mcp', interactive: false, hook: 'allow', denyRule: 'mcp_notes_*' });


// Direct consumer probes (item 1 and 2): the invocation's own shouldConfirmExecute(signal, forcedDecision), no scheduler.
async function direct(sc) {
  const work = fs.mkdtempSync(path.join(root, 'd-'));
  const settings = { mcpServers: { notes: { command: 'unused', trust: !!sc.trust } } };
  const policy = await createPolicyEngineConfig(settings, sc.approval, undefined, true);
  const config = new core.Config({ sessionId: 'd', targetDir: work, cwd: work, debugMode: false, model: 'gemini-test', interactive: true, approvalMode: sc.approval,
    folderTrust: sc.folderTrust ?? false, trustedFolder: sc.trustedFolder ?? true, policyEngineConfig: policy, enableHooks: false });
  await config.initialize();
  const bus = config.getMessageBus();
  DiscoveredMCPToolInvocation.allowlist?.clear?.(); if (sc.sessionAllowlist) DiscoveredMCPToolInvocation.allowlist.add('notes');
  let invocation;
  if (sc.tool === 'shell') invocation = new ShellTool(config, bus).build({ command: 'echo hi' });
  else invocation = new DiscoveredMCPTool({ callTool: async () => [] }, 'notes', 'search_notes', 'stub', { type: 'object', properties: {} }, bus, !!sc.trust, false, undefined, config).build({});
  const res = {};
  for (const forced of [undefined, 'ask_user']) {
    const key = forced ?? 'none';
    // the message-bus policy query (forcedDecision undefined) needs a responder; the real MessageBus has the PolicyEngine as its responder
    try {
      const d = await Promise.race([invocation.shouldConfirmExecute(new AbortController().signal, forced), new Promise((r) => setTimeout(() => r('__timeout'), 3000))]);
      res[key] = d === '__timeout' ? 'TIMEOUT' : d === false ? 'false(no confirmation: proceeds)' : (d?.type ? `details:${d.type}` : String(d));
    } catch (e) { res[key] = `throws:${String(e.message).slice(0, 80)}`; }
  }
  return { ...sc, scenario: sc.name, kind: 'direct', forced: res };
}
const directScenarios = [];
for (const approval of ['default', 'yolo']) {
  directScenarios.push({ name: `direct|shell|${approval}`, tool: 'shell', approval });
  for (const trust of [false, true]) directScenarios.push({ name: `direct|mcp|${approval}|trust=${trust}`, tool: 'mcp', approval, trust });
  directScenarios.push({ name: `direct|mcp|${approval}|trust=false|session-allowlist`, tool: 'mcp', approval, sessionAllowlist: true });
  directScenarios.push({ name: `direct|mcp|${approval}|trust=true|folderTrust-on|folder-untrusted`, tool: 'mcp', approval, trust: true, folderTrust: true, trustedFolder: false });
}

const out = fs.createWriteStream(outFile);
for (const d of directScenarios) {
  if (filter && !new RegExp(filter).test(d.name)) continue;
  let rec;
  try { rec = await direct(d); } catch (e) { rec = { scenario: d.name, ...d, kind: 'direct', driverError: String(e?.stack ?? e).slice(0, 500) }; }
  out.write(JSON.stringify({ version: label, pkgVersion, ...rec }) + '\n');
}
for (const s of sc) {
  if (filter && !new RegExp(filter).test(s.name)) continue;
  let rec;
  try { rec = await runOne(s); } catch (e) { rec = { scenario: s.name, ...s, outcome: 'DRIVER-ERROR', driverError: String(e?.stack ?? e).slice(0, 500) }; }
  out.write(JSON.stringify({ version: label, pkgVersion, ...rec }) + '\n');
}
out.end(); await new Promise((r) => out.on('finish', r));
fs.rmSync(root, { recursive: true, force: true });
process.exit(0);
