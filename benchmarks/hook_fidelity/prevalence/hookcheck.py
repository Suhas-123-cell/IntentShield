"""For headless-using repos, fetch the harness hook-config files at default-branch HEAD (raw text only) and record presence/event names."""
import json,sys,os,glob,re,urllib.request,urllib.error,collections
from concurrent.futures import ThreadPoolExecutor
sys.path.insert(0,os.path.dirname(os.path.abspath(__file__)))
import analyze as A
D=A.D
CACHE=f"{D}/hookcache.json"
cache=json.load(open(CACHE)) if os.path.exists(CACHE) else {}
FILES={"claude":[".claude/settings.json"],"codex":[".codex/hooks.json",".codex/config.toml"],"gemini":[".gemini/settings.json"],"cursor":[".cursor/hooks.json"]}
H2F={"claude_cli":"claude","claude_action":"claude","codex_cli":"codex","codex_action":"codex","gemini_cli":"gemini","gemini_action":"gemini","cursor_cli":"cursor"}
def fetch(args):
    repo,path=args; k=f"{repo}|{path}"
    if k in cache: return
    u=f"https://raw.githubusercontent.com/{repo}/HEAD/{path}"
    for _ in range(3):
        try:
            with urllib.request.urlopen(urllib.request.Request(u,headers={"User-Agent":"hook-fidelity-prevalence-study"}),timeout=30) as r:
                cache[k]=r.read(300000).decode("utf-8","replace"); return
        except urllib.error.HTTPError as e:
            if e.code==404: cache[k]=None; return
        except Exception: pass
    cache[k]="__ERR__"
W=collections.defaultdict(set)   # harness -> repos
for f in glob.glob(f"{D}/E_h_*.json"):
    d=json.load(open(f))
    for i in d["items"]:
        t=A.text(i)
        if not t: continue
        hits,_=A.classify(t)
        for h in hits: W[H2F[h]].add(i["repo"])
jobs=[(r,p) for h,rs in W.items() for r in rs for p in FILES[h]]
with ThreadPoolExecutor(14) as ex: list(ex.map(fetch,jobs))
json.dump(cache,open(CACHE,"w"))
json.dump({h:sorted(r) for h,r in W.items()},open(f"{D}/W_repos.json","w"))
print({h:len(r) for h,r in W.items()},"jobs",len(jobs))
