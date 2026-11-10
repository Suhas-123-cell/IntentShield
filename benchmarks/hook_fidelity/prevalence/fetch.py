"""Fetch raw file text for enumerated hits (immutable sha URLs). Text only; nothing is executed."""
import tempfile
import json,sys,os,hashlib,urllib.request,re
from concurrent.futures import ThreadPoolExecutor
D=os.path.join((os.environ.get("HF_SCRATCH") or os.path.join(tempfile.gettempdir(), "intentshield-hook-fidelity")), "prev_data")
R=D+"/raw"; os.makedirs(R,exist_ok=True)
def key(i): return hashlib.sha1((i["repo"]+"|"+i["path"]).encode()).hexdigest()
def raw_url(u):
    m=re.match(r"https://github.com/([^/]+/[^/]+)/blob/([0-9a-f]{40})/(.*)",u)
    return f"https://raw.githubusercontent.com/{m.group(1)}/{m.group(2)}/{m.group(3)}" if m else None
def get(i):
    p=f"{R}/{key(i)}.txt"
    if os.path.exists(p): return
    u=raw_url(i["url"])
    if not u: return
    for _ in range(3):
        try:
            with urllib.request.urlopen(urllib.request.Request(u,headers={"User-Agent":"hook-fidelity-prevalence-study"}),timeout=30) as r:
                open(p,"wb").write(r.read(400000)); return
        except Exception as e:
            err=str(e)
            if "404" in err: open(p,"wb").write(b"");return
    open(p+".err","w").write("fail")
for n in sys.argv[1:]:
    d=json.load(open(f"{D}/E_{n}.json"))
    with ThreadPoolExecutor(12) as ex: list(ex.map(get,d["items"]))
    print("fetched",n,len(d["items"]),flush=True)
