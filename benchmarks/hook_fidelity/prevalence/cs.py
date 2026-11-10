"""GitHub code search runner: counts and (optionally) paginated enumeration. Read-only, own gh auth."""
import tempfile
import json, subprocess, sys, time, os, datetime
D = os.path.join((os.environ.get("HF_SCRATCH") or os.path.join(tempfile.gettempdir(), "intentshield-hook-fidelity")), "prev_data")
def call(q, page=1, per_page=100):
    for attempt in range(6):
        r = subprocess.run(["gh","api","-X","GET","search/code","-f",f"q={q}","-f",f"per_page={per_page}","-f",f"page={page}"],capture_output=True,text=True)
        if r.returncode==0:
            return json.loads(r.stdout)
        err = r.stderr+r.stdout
        if "rate limit" in err.lower() or "403" in err or "429" in err:
            time.sleep(40); continue
        return {"error":err[:300]}
    return {"error":"rate-limited out"}
def run(name, q, enumerate_=False, maxpages=10):
    out = {"name":name,"query":q,"utc":datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
    d = call(q,1); time.sleep(6.5)
    if "error" in d: out["error"]=d["error"]; json.dump(out,open(f"{D}/{name}.json","w")); return out
    out["total_count"]=d["total_count"]; out["incomplete"]=d["incomplete_results"]
    items=[(i["repository"]["full_name"],i["path"],i["html_url"]) for i in d["items"]]
    if enumerate_ and d["total_count"]>100:
        for p in range(2,min(maxpages,(min(d["total_count"],1000)+99)//100)+1):
            e=call(q,p); time.sleep(6.5)
            if "error" in e: out["page_error"]=[p,e["error"]]; break
            items+=[(i["repository"]["full_name"],i["path"],i["html_url"]) for i in e["items"]]
    out["items"]=items; out["n_items"]=len(items); out["n_repos"]=len({i[0] for i in items})
    json.dump(out,open(f"{D}/{name}.json","w"))
    print(name,out["total_count"],out["incomplete"],out["n_items"],out["n_repos"],flush=True)
    return out
if __name__=="__main__":
    spec=json.load(open(sys.argv[1]))
    for s in spec: run(s["name"],s["q"],s.get("enum",False))
