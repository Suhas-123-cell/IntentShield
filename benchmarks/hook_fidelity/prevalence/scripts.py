"""Static look at PreToolUse hook commands in headless Claude repos: what do they point at; does the script text mention permissionDecision/ask. Text only, never executed."""
import tempfile
import json,re,os,sys,collections,urllib.request,urllib.error
from concurrent.futures import ThreadPoolExecutor
D=os.path.join((os.environ.get("HF_SCRATCH") or os.path.join(tempfile.gettempdir(), "intentshield-hook-fidelity")), "prev_data")
cache=json.load(open(f"{D}/hookcache.json"))
repos=json.load(open(f"{D}/hookrepos_claude.json"))["guard"]
SC=f"{D}/scriptcache.json"; sc=json.load(open(SC)) if os.path.exists(SC) else {}
def fetch(a):
    r,p=a;k=f"{r}|{p}"
    if k in sc: return
    try:
        with urllib.request.urlopen(urllib.request.Request(f"https://raw.githubusercontent.com/{r}/HEAD/{p}",headers={"User-Agent":"hook-fidelity-prevalence-study"}),timeout=30) as x: sc[k]=x.read(200000).decode("utf-8","replace")
    except urllib.error.HTTPError as e: sc[k]=None if e.code==404 else "__ERR__"
    except Exception: sc[k]="__ERR__"
info={}; jobs=[]
for r in repos:
    j=json.loads(cache[f"{r}|.claude/settings.json"]); cmds=[]
    for ent in j["hooks"].get("PreToolUse",[]) or []:
        if not isinstance(ent,dict): continue
        for h in ent.get("hooks",[]) or []:
            if isinstance(h,dict): cmds.append((ent.get("matcher",""),h.get("type","command"),h.get("command") or h.get("url") or h.get("prompt") or ""))
    info[r]=cmds
    for m,t,c in cmds:
        for tok in re.findall(r"[\w./${}\-]+\.(?:py|sh|js|mjs|cjs|ts|rb|go)\b",c):
            p=re.sub(r"^\"?\$\{?(?:CLAUDE_PROJECT_DIR|PWD)\}?\"?/?","",tok); p=re.sub(r"^(\./)+","",p)
            if "$" in p or p.startswith("~") or p.startswith("/"): continue
            jobs.append((r,p))
with ThreadPoolExecutor(14) as ex: list(ex.map(fetch,set(jobs)))
json.dump(sc,open(SC,"w"))
cat=collections.Counter(); rows=[]
for r,cmds in info.items():
    kinds=set(); ask=False; pd=False; fetched=False
    for m,t,c in cmds:
        if t!="command": kinds.add("non-command("+t+")")
        toks=re.findall(r"[\w./${}\-]+\.(?:py|sh|js|mjs|cjs|ts|rb|go)\b",c)
        if toks:
            got=False
            for tok in toks:
                p=re.sub(r"^(\./)+","",re.sub(r"^\"?\$\{?(?:CLAUDE_PROJECT_DIR|PWD)\}?\"?/?","",tok))
                t2=sc.get(f"{r}|{p}")
                if t2 and t2!="__ERR__":
                    got=True; fetched=True
                    if "permissionDecision" in t2 or "hookSpecificOutput" in t2: pd=True
                    if re.search(r"""['"]ask['"]""",t2) and ("permissionDecision" in t2 or "hookSpecificOutput" in t2): ask=True
            kinds.add("repo-script" if got else "script-not-found-in-repo")
        else:
            kinds.add("inline/other command")
    rows.append((r,sorted(kinds),fetched,pd,ask))
n=len(rows)
print("repos with PreToolUse in .claude/settings.json:",n)
print("with >=1 repo-local script text fetched:",sum(1 for x in rows if x[2]))
print("script text mentions permissionDecision/hookSpecificOutput:",sum(1 for x in rows if x[3]))
print("script text mentions permissionDecision AND the string 'ask':",sum(1 for x in rows if x[4]))
print("kinds:",collections.Counter(k for x in rows for k in x[1]).most_common())
json.dump(rows,open(f"{D}/script_rows.json","w"))
