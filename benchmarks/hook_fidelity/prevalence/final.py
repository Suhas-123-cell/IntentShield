import json,re,glob,collections,sys,os
sys.path.insert(0,os.path.dirname(os.path.abspath(__file__)))
import analyze as A
D=A.D
H2F={"claude_cli":"claude","claude_action":"claude","codex_cli":"codex","codex_action":"codex","gemini_cli":"gemini","gemini_action":"gemini","cursor_cli":"cursor"}
cache=json.load(open(f"{D}/hookcache.json"))
files={}  # (repo,path)->(hits,inlinehook,item)
for f in sorted(glob.glob(f"{D}/E_h_*.json")):
    for i in json.load(open(f))["items"]:
        k=(i["repo"],i["path"])
        if k in files: continue
        t=A.text(i)
        if not t: continue
        h,hook=A.classify(t)
        files[k]=(h,hook,i)
out={}
pat=collections.defaultdict(lambda:{"files":set(),"repos":set(),"lock_files":0,"inline_hook_files":set()})
for (r,p),(h,hook,i) in files.items():
    for x in h:
        pat[x]["files"].add((r,p)); pat[x]["repos"].add(r)
        if p.endswith(".lock.yml"): pat[x]["lock_files"]+=1
        if hook: pat[x]["inline_hook_files"].add((r,p))
print("verified headless invocations in enumerated workflow files (candidate files unioned across queries, %d files fetched)"%len(files))
for x,v in sorted(pat.items()):
    print(f"  {x:14s} files {len(v['files']):6d} repos {len(v['repos']):6d} lock.yml files {v['lock_files']:4d} files w/ inline hook text {len(v['inline_hook_files']):4d} repos {len({r for r,_ in v['inline_hook_files']})}")
W=collections.defaultdict(set)
for (r,p),(h,hook,i) in files.items():
    for x in h: W[H2F[x]].add(r)
allW=set().union(*W.values())
print("repos per harness (any headless pattern):",{h:len(r) for h,r in W.items()},"union",len(allW))
multi=collections.Counter(sum(1 for h in W if r in W[h]) for r in allW)
print("repos using >1 harness:",dict(multi))
# non-lock repos
nl=collections.defaultdict(set)
for (r,p),(h,hook,i) in files.items():
    if p.endswith(".lock.yml"): continue
    for x in h: nl[H2F[x]].add(r)
print("repos excluding .lock.yml files:",{h:len(r) for h,r in nl.items()})
# hook config at HEAD
FILES={"claude":[".claude/settings.json"],"codex":[".codex/hooks.json",".codex/config.toml"],"gemini":[".gemini/settings.json"],"cursor":[".cursor/hooks.json"]}
def evs(t,f):
    if f.endswith(".toml"):
        ev=set(re.findall(r"^\s*\[+hooks\.(\w+)",t,re.M))
        if not ev and re.search(r"\bhooks\b",t): ev={"?toml"}
        return ev
    try:
        j=json.loads(t); h=j.get("hooks")
        return set(h.keys()) if isinstance(h,dict) and h else set()
    except Exception: return None
GUARD={"claude":{"PreToolUse"},"codex":{"PreToolUse"},"gemini":{"BeforeTool"},"cursor":{"preToolUse","beforeShellExecution","beforeMCPExecution"}}
res={}
for h,rs in W.items():
    n=len(rs);pres=0;anyh=0;g=0;unparse=0;evc=collections.Counter();hookrepos=[];grepos=[]
    for r in rs:
        e=set();got=False
        for f in FILES[h]:
            t=cache.get(f"{r}|{f}")
            if t and t!="__ERR__":
                got=True; x=evs(t,f)
                if x is None: unparse+=1
                else: e|=x
        pres+=got
        if e: anyh+=1; hookrepos.append(r)
        if e&GUARD[h] or (h=="codex" and any(re.search("PreToolUse",cache.get(f"{r}|{f}") or "") for f in FILES[h])): g+=1; grepos.append(r)
        for x in e: evc[x]+=1
    res[h]={"repos":n,"config_present":pres,"any_hook":anyh,"guard_capable_event":g,"unparsable":unparse}
    print(h,res[h],dict(evc.most_common(8)))
    json.dump({"hook":hookrepos,"guard":grepos},open(f"{D}/hookrepos_{h}.json","w"))
# search-side cross check
K={"claude":["k_claude_PreToolUse"],"codex":["k_codex_hooks_json_Pre","k_codex_config_Pre"],"gemini":["k_gemini_BeforeTool"],"cursor":["k_cursor_beforeShell","k_cursor_preToolUse","k_cursor_beforeMCP"]}
for h,ks in K.items():
    hs=set()
    for k in ks:
        for i in json.load(open(f"{D}/E_{k}.json"))["items"]:
            if i["path"] in (".claude/settings.json",".codex/hooks.json",".codex/config.toml",".gemini/settings.json",".cursor/hooks.json"): hs.add(i["repo"])
    inter=hs&W[h]
    print("search cross-check",h,"hook-config repos (search, root path)",len(hs),"∩ headless repos",len(inter))
    json.dump(sorted(inter),open(f"{D}/inter_search_{h}.json","w"))
