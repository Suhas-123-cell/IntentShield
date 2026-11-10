"""Sharded GitHub code search enumeration (read-only). Splits a query by file size until each shard <=1000 hits."""
import tempfile
import json, subprocess, sys, time, datetime, os
D = os.path.join((os.environ.get("HF_SCRATCH") or os.path.join(tempfile.gettempdir(), "intentshield-hook-fidelity")), "prev_data")
NREQ = 0
def call(q, page=1):
    global NREQ
    for attempt in range(8):
        NREQ += 1
        r = subprocess.run(["gh","api","-X","GET","-H","Accept: application/vnd.github.text-match+json","search/code","-f",f"q={q}","-f","per_page=100","-f",f"page={page}"],capture_output=True,text=True)
        time.sleep(6.5)
        if r.returncode==0:
            return json.loads(r.stdout)
        err=(r.stderr+r.stdout).lower()
        if "rate limit" in err or "403" in err or "429" in err or "abuse" in err or "502" in err or "503" in err:
            time.sleep(45); continue
        return {"error":err[:300]}
    return {"error":"retries exhausted"}
def items_of(d):
    out=[]
    for i in d["items"]:
        frag=""
        for tm in i.get("text_matches",[])[:1]:
            frag=tm.get("fragment","")[:240]
        out.append({"repo":i["repository"]["full_name"],"fork":i["repository"].get("fork"),"path":i["path"],"url":i["html_url"],"frag":frag})
    return out
def enum_range(q, lo, hi, acc, log):
    d = call(f"{q} size:{lo}..{hi}")
    if "error" in d: log.append({"range":[lo,hi],"error":d["error"]}); return
    t=d["total_count"]
    if t==0: return
    if t<=1000 or lo>=hi:
        acc.extend(items_of(d))
        pages=(min(t,1000)+99)//100
        for p in range(2,pages+1):
            e=call(f"{q} size:{lo}..{hi}",p)
            if "error" in e: log.append({"range":[lo,hi],"page":p,"error":e["error"]}); break
            acc.extend(items_of(e))
        if t>1000: log.append({"range":[lo,hi],"truncated":t})
        log.append({"range":[lo,hi],"total":t,"incomplete":d["incomplete_results"]})
    else:
        mid=(lo+hi)//2
        enum_range(q,lo,mid,acc,log); enum_range(q,mid+1,hi,acc,log)
BOUNDS=[0,300,600,900,1200,1600,2000,2500,3000,4000,5000,6500,8000,10000,13000,17000,22000,30000,50000,100000,400000]
def enum(name,q):
    acc=[];log=[];n0=NREQ
    t0=datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    top=call(q)
    total=top.get("total_count") if "error" not in top else None
    if total is not None and total<=1000:
        acc.extend(items_of(top))
        for p in range(2,(total+99)//100+1):
            e=call(q,p)
            if "error" in e: log.append({"page":p,"error":e["error"]}); break
            acc.extend(items_of(e))
        log.append({"unsharded":True,"total":total})
    else:
        for a,b in zip(BOUNDS[:-1],[x-1 for x in BOUNDS[1:]]):
            enum_range(q,a if a==0 else a,b,acc,log)
    seen={};
    for i in acc: seen[(i["repo"],i["path"])]=i
    res={"name":name,"query":q,"utc_start":t0,"utc_end":datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),"total_count_unsharded":total,"incomplete_unsharded":top.get("incomplete_results"),"n_items_unique":len(seen),"n_repos":len({k[0] for k in seen}),"requests":NREQ-n0,"log":log,"items":list(seen.values())}
    json.dump(res,open(f"{D}/E_{name}.json","w"))
    print(name,total,res["n_items_unique"],res["n_repos"],"req",res["requests"],flush=True)
def count(name,q):
    d=call(q)
    res={"name":name,"query":q,"utc":datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),"total_count":d.get("total_count"),"incomplete":d.get("incomplete_results"),"error":d.get("error")}
    json.dump(res,open(f"{D}/C_{name}.json","w")); print("count",name,res["total_count"],flush=True)
if __name__=="__main__":
    spec=json.load(open(sys.argv[1]))
    for s in spec:
        (enum if s["mode"]=="enum" else count)(s["name"],s["q"])
