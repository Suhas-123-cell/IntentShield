import json,glob,random,re,os,sys,hashlib
sys.path.insert(0,os.path.dirname(os.path.abspath(__file__)))
import analyze as A
D=A.D
S=json.load(open(f"{D}/S_by_pattern.json")); cache=json.load(open(f"{D}/hookcache.json"))
G={h:json.load(open(f"{D}/hookrepos_{h}.json")) for h in ["claude","codex","gemini","cursor"]}
H2F={"claude_cli":"claude","claude_action":"claude","codex_cli":"codex","codex_action":"codex","gemini_cli":"gemini","gemini_action":"gemini","cursor_cli":"cursor"}
files={}
for f in sorted(glob.glob(f"{D}/E_h_*.json")):
    for i in json.load(open(f))["items"]: files.setdefault((i["repo"],i["path"]),i)
rng=random.Random(20261031)
plan=[("claude_action",4),("claude_cli",3),("codex_action",2),("codex_cli",1),("gemini_action",1),("cursor_cli",1)]
sel=[]
for pat,n in plan:
    pool=sorted(S[pat]); 
    # exclude intersection repos from random stratum to keep strata clean
    pool=[r for r in pool if r not in set(G[H2F[pat]]["guard"])]
    for r in rng.sample(pool,n): sel.append(("random",pat,r))
for h,pat,n in [("claude","claude_action",3),("claude","claude_cli",2),("codex","codex_action",1),("gemini","gemini_action",1),("cursor","cursor_cli",1)]:
    pool=sorted(set(G[h]["guard"])&set(S[pat]))
    for r in rng.sample(pool,n): sel.append(("hook-bearing",pat,r))
json.dump(sel,open(f"{D}/sample_sel.json","w"))
for kind,pat,r in sel:
    ks=[k for k in files if k[0]==r and A.text(files[k]) and pat in A.classify(A.text(files[k]))[0]]
    k=sorted(ks)[0]; t=A.text(files[k]); h=H2F[pat]
    ls=A.logical_lines(t)
    key=[l for l in ls if A.RX[pat].search(l)][:2]
    on=re.search(r"^on:\s*\n((?:\s+.*\n|\n)+)",t,re.M); trig=re.findall(r"^\s{2}(\w+):",on.group(1),re.M)[:6] if on else re.findall(r"^on:\s*(.*)",t,re.M)
    flags=sorted(set(re.findall(r"--dangerously-skip-permissions|--allowedTools|allowed_tools|--yolo|--force|-y\b|--full-auto|danger-full-access|--sandbox\s+\S+|permission-mode\S*|--permission-mode\s+\S+|bypassPermissions|--approval-mode\s+\S+|prompt_file|--max-turns\s*\S+",t)))
    print("="*100);print(kind,pat,r,k[1],f"len={len(t)}");print(" trigger:",trig);print(" key:",[x[:200] for x in key]);print(" flags:",flags)
    print(" prompt-ish:",[l[:160] for l in ls if re.match(r"(prompt|direct_prompt|name):",l)][:5])
    if kind=="hook-bearing" or r in G[h]["hook"]:
        for f in {"claude":[".claude/settings.json"],"codex":[".codex/hooks.json",".codex/config.toml"],"gemini":[".gemini/settings.json"],"cursor":[".cursor/hooks.json"]}[h]:
            c=cache.get(f"{r}|{f}")
            if c: print(" HOOKCFG",f,re.sub(r"\s+"," ",c)[:700])
