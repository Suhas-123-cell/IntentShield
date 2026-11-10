import sys, json, os, subprocess, shutil
from pathlib import Path
sys.path.insert(0,"benchmarks")
from hook_fidelity.stub_model import Script, StubServer
variant=sys.argv[1]
S=Path("<SCRATCH>")
B=str(S/"releases/codex/0.131.0/node_modules/@openai/codex-darwin-arm64/vendor/aarch64-apple-darwin/codex/codex")
run=S/f"r3/exp/{variant}"; shutil.rmtree(run,ignore_errors=True); (run/"home/codex-home").mkdir(parents=True); (run/"work").mkdir()
stub=StubServer(Script.from_obj({"nonce":"x","final_text":"stub done"}), run/"stub.jsonl").start()
hook=f"{sys.executable} {Path('benchmarks/hook_fidelity/coverage_hook.py').resolve()} codex {run/'hooks.jsonl'}"
toml=f'check_for_update_on_startup = false\nmodel = "stub-model"\nmodel_provider = "stub"\napproval_policy = "never"\n[model_providers.stub]\nname = "stub"\nbase_url = "{stub.url}/v1"\nenv_key = "STUB_API_KEY"\nwire_api = "responses"\nrequest_max_retries = 0\nstream_max_retries = 0\n'
hooks={"SessionStart":[{"hooks":[{"type":"command","command":hook,"timeout":20}]}],"UserPromptSubmit":[{"hooks":[{"type":"command","command":hook,"timeout":20}]}]}
if variant=="json":
    (run/"home/codex-home/hooks.json").write_text(json.dumps({"hooks":hooks}))
elif variant=="project":
    (run/"work/.codex").mkdir(); (run/"work/.codex/hooks.json").write_text(json.dumps({"hooks":hooks})); toml+=f'[projects."{(run/"work").resolve()}"]\ntrust_level = "trusted"\n'
elif variant in ("toml","toml-sh","toml-enable"):
    for e in hooks: toml+=f'[[hooks.{e}]]\n[[hooks.{e}.hooks]]\ntype = "command"\ncommand = {json.dumps(hook)}\ntimeout = 20\n'
if variant=="toml-sh":
    toml=toml.replace(json.dumps(hook), json.dumps(f"/bin/sh -c 'cat >> {run}/sh-hit.txt; echo >> {run}/sh-hit.txt'"))
(run/"home/codex-home/config.toml").write_text(toml)
env={"PATH":os.environ["PATH"],"HOME":str(run/"home"),"CODEX_HOME":str(run/"home/codex-home"),"STUB_API_KEY":"x","RUST_LOG":"trace","NO_PROXY":"127.0.0.1"}
p=subprocess.run([B,"exec","--skip-git-repo-check","--dangerously-bypass-hook-trust","--json"]+(["--enable","hooks"] if variant=="toml-enable" else [])+["hi"],cwd=run/"work",env=env,capture_output=True,text=True,timeout=60,stdin=subprocess.DEVNULL)
(run/'stderr.txt').write_text(p.stderr);print(variant, p.returncode, (run/"sh-hit.txt").exists(), (run/"hooks.jsonl").exists() and (run/"hooks.jsonl").read_text()[:300], p.stdout[-300:])
stub.stop()
