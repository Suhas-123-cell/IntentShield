// Scripted BeforeTool hook replies shared by driver.mjs (layers A and B) and layer_c.mjs (real HookSystem).
// makeScenarios(work, hookDir) writes the hook scripts under hookDir and returns [{name, command | commands, timeout?, bounded?}].
import fs from 'node:fs';
import path from 'node:path';

export function makeScenarios(work, hookDir) {
  function script(name, body, { shebang = '#!/bin/bash', mode = 0o755 } = {}) {
    const p = path.join(hookDir, name);
    fs.writeFileSync(p, `${shebang}\n${body}\n`, { mode });
    fs.chmodSync(p, mode);
    return p;
  }
  const TB = 'Traceback (most recent call last):\n  File "/x/intentshield/hook.py", line 12, in <module>\n    main()\n  File "/x/intentshield/hook.py", line 9, in main\n    raise RuntimeError("guard crashed")\nRuntimeError: guard crashed';
  fs.writeFileSync(path.join(work, 'tb.txt'), TB + '\n');
  fs.writeFileSync(path.join(work, 'crash.py'), 'raise RuntimeError("guard crashed")\n');

  const S = [];  // [name, command, opts]
  const add = (name, command, opts = {}) => S.push({ name, command, ...opts });
  const q = (p) => `'${p}'`;
  add('allow', q(script('allow.sh', `cat >/dev/null; echo '{"decision":"allow"}'`)));
  add('ask', q(script('ask.sh', `cat >/dev/null; echo '{"decision":"ask","reason":"needs review"}'`)));
  add('deny', q(script('deny.sh', `cat >/dev/null; echo '{"decision":"deny","reason":"blocked by guard"}'`)));
  add('block', q(script('block.sh', `cat >/dev/null; echo '{"decision":"block","reason":"blocked by guard"}'`)));
  add('empty_exit0', q(script('empty0.sh', `cat >/dev/null; exit 0`)));
  add('malformed_json_exit0', q(script('mal0.sh', `cat >/dev/null; echo '{"decision":"den'`)));
  add('malformed_json_exit2', q(script('mal2.sh', `cat >/dev/null; echo '{"decision":"den' >&2; exit 2`)));
  add('exit1_empty', q(script('e1.sh', `cat >/dev/null; exit 1`)));
  add('exit1_stderr', q(script('e1s.sh', `cat >/dev/null; echo 'hook failed' >&2; exit 1`)));
  add('exit2_empty', q(script('e2.sh', `cat >/dev/null; exit 2`)));
  add('exit2_stderr', q(script('e2s.sh', `cat >/dev/null; echo 'blocked: dangerous' >&2; exit 2`)));
  add('exit2_json_allow', q(script('e2j.sh', `cat >/dev/null; echo '{"decision":"allow"}'; exit 2`)));
  add('exit2_json_deny', q(script('e2jd.sh', `cat >/dev/null; echo '{"decision":"deny","reason":"r"}'; exit 2`)));
  add('exit3_text', q(script('e3.sh', `cat >/dev/null; echo 'some failure text'; exit 3`)));
  add('exit3_empty', q(script('e3e.sh', `cat >/dev/null; exit 3`)));
  add('intentshield_crash_exit2', q(script('crash2.sh', `cat >/dev/null; cat ${q(path.join(work, 'tb.txt'))} >&2; exit 2`)));
  add('python_uncaught_exit1', q(script('crash1.sh', `cat >/dev/null; exec python3 -I ${q(path.join(work, 'crash.py'))}`)));
  add('exit126_script_empty', q(script('e126.sh', `cat >/dev/null; exit 126`)));
  add('exit126_script_stderr', q(script('e126s.sh', `cat >/dev/null; echo 'cannot execute' >&2; exit 126`)));
  add('exit127_script_empty', q(script('e127.sh', `cat >/dev/null; exit 127`)));
  add('nonexec_file_126', q(script('nonexec.sh', `echo '{"decision":"allow"}'`, { mode: 0o644 })));
  add('bad_interpreter_shebang', q(script('badinterp.sh', `print("x")`, { shebang: '#!/nonexistent/path/python3' })));
  add('missing_command_127', q(path.join(hookDir, 'does-not-exist.sh')));
  add('timeout', q(script('hang.sh', `exec sleep 30`)), { timeout: 1500 });
  // round 2 (critic): reply-space gaps, a missing interpreter on PATH, a grandchild that holds the pipe past the timeout,
  // and several hooks at once (layer B aggregates them through the real HookEventHandler path).
  add('continue_false', q(script('cf.sh', `cat >/dev/null; echo '{"continue":false,"stopReason":"halt"}'`)));
  add('unknown_decision', q(script('unk.sh', `cat >/dev/null; echo '{"decision":"approve","reason":"r"}'`)));
  add('exit2_json_on_stderr', q(script('e2se.sh', `cat >/dev/null; echo '{"decision":"deny","reason":"r"}' >&2; exit 2`)));
  add('exit1_json_deny_stdout', q(script('e1jd.sh', `cat >/dev/null; echo '{"decision":"deny","reason":"r"}'; exit 1`)));
  add('python3_missing_on_path', `PATH=/nonexistent python3 ${q(path.join(work, 'crash.py'))}`);
  add('timeout_grandchild_holds_pipe', q(script('gchild.sh', `sleep 30 & sleep 30`)), { timeout: 1500, bounded: 12000 });
  add('multi_ask_plus_allow', null, { commands: [q(script('m1a.sh', `cat >/dev/null; echo '{"decision":"ask","reason":"needs review"}'`)),
                                                    q(script('m1b.sh', `cat >/dev/null; echo '{"decision":"allow"}'`))] });
  add('multi_deny_plus_allow', null, { commands: [q(script('m2a.sh', `cat >/dev/null; echo '{"decision":"deny","reason":"blocked"}'`)),
                                                     q(script('m2b.sh', `cat >/dev/null; echo '{"decision":"allow"}'`))] });
  add('multi_crash_exit1_then_deny', null, { commands: [q(script('m3a.sh', `cat >/dev/null; echo 'hook failed' >&2; exit 1`)),
                                                           q(script('m3b.sh', `cat >/dev/null; echo '{"decision":"deny","reason":"blocked"}'`))] });
  add('multi_ask_plus_ask', null, { commands: [q(script('m4a.sh', `cat >/dev/null; echo '{"decision":"ask","reason":"a"}'`)),
                                                 q(script('m4b.sh', `cat >/dev/null; echo '{"decision":"ask","reason":"b"}'`))] });
  return S;
}
