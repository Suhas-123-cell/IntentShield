import json,glob,collections,sys,os
sys.path.insert(0,os.path.dirname(os.path.abspath(__file__)))
import analyze as A
D=A.D
G={h:json.load(open(f"{D}/hookrepos_{h}.json")) for h in ["claude","codex","gemini","cursor"]}
H2F={"claude_cli":"claude","claude_action":"claude","codex_cli":"codex","codex_action":"codex","gemini_cli":"gemini","gemini_action":"gemini","cursor_cli":"cursor"}
S=collections.defaultdict(set); seen=set()
for f in sorted(glob.glob(f"{D}/E_h_*.json")):
    for i in json.load(open(f))["items"]:
        k=(i["repo"],i["path"])
        if k in seen: continue
        seen.add(k); t=A.text(i)
        if not t: continue
        h,_=A.classify(t)
        for x in h: S[x].add(i["repo"])
import math
def wil(k,n):
    z=1.96;p=k/n;d=1+z*z/n;c=p+z*z/2/n;m=z*math.sqrt(p*(1-p)/n+z*z/4/n/n);return (c-m)/d,(c+m)/d
for x,rs in sorted(S.items()):
    h=H2F[x];a=len(rs&set(G[h]["hook"]));g=len(rs&set(G[h]["guard"]));n=len(rs)
    lo,hi=wil(g,n)
    print(f"{x:14s} n={n:6d} any-hook {a:5d} ({100*a/n:.1f}%) guard-event {g:5d} ({100*g/n:.2f}%, Wilson {100*lo:.1f}-{100*hi:.1f})")
# claude both
cl=S["claude_action"]|S["claude_cli"]; print("claude union",len(cl),len(cl&set(G["claude"]["guard"])))
only_cli=S["claude_cli"]-S["claude_action"]; print("claude_cli only",len(only_cli),len(only_cli&set(G["claude"]["guard"])))
json.dump({k:sorted(v) for k,v in S.items()},open(f"{D}/S_by_pattern.json","w"))
