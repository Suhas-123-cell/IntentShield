import tempfile
import json,re,os,sys,hashlib,collections
D=os.path.join((os.environ.get("HF_SCRATCH") or os.path.join(tempfile.gettempdir(), "intentshield-hook-fidelity")), "prev_data")
def key(i): return hashlib.sha1((i["repo"]+"|"+i["path"]).encode()).hexdigest()
def text(i):
    p=f"{D}/raw/{key(i)}.txt"
    try: return open(p,encoding="utf-8",errors="replace").read()
    except: return None
def logical_lines(t):
    t=re.sub(r"\\\n\s*"," ",t)
    out=[]
    for l in t.split("\n"):
        s=l.strip()
        if s.startswith("#"): continue
        out.append(s)
    return out
RX={
 "claude_cli":re.compile(r"(?:^|[\s\"'(`$/=])(?:claude|claude-code|@anthropic-ai/claude-code(?:@\S+)?)(?:\s+\S+)*?\s+(?:-p|--print)(?:\s|$|=|\"|')"),
 "codex_cli":re.compile(r"(?:^|[\s\"'(`$/=])codex(?:\s+(?:-\S+|\S+=\S+))*\s+exec(?:\s|$)"),
 "gemini_cli":re.compile(r"(?:^|[\s\"'(`$/=])gemini(?:\s+\S+)*?\s+(?:-p|--prompt)(?:\s|$|=|\"|')"),
 "cursor_cli":re.compile(r"(?:^|[\s\"'(`$/=])(?:cursor-agent|cursor\s+agent)(?:\s+\S+)*?\s+(?:-p|--print)(?:\s|$|=|\"|')"),
 "claude_action":re.compile(r"uses:\s*[\"']?(?:anthropics/claude-code-action|anthropics/claude-code-base-action)"),
 "codex_action":re.compile(r"uses:\s*[\"']?openai/codex-action"),
 "gemini_action":re.compile(r"uses:\s*[\"']?google-github-actions/run-gemini-cli"),
}
HOOKRX=re.compile(r"PreToolUse|BeforeTool|beforeShellExecution|beforeMCPExecution|preToolUse|\"hooks\"\s*:|^\s*hooks\s*:",re.M)
def classify(t):
    ls=logical_lines(t); hit=set()
    for l in ls:
        for k,rx in RX.items():
            if rx.search(l): hit.add(k)
    return hit, bool(HOOKRX.search("\n".join(ls)))
if __name__=="__main__":
    for n in sys.argv[1:]:
        d=json.load(open(f"{D}/E_{n}.json")); c=collections.Counter(); repos=collections.defaultdict(set); hk=collections.defaultdict(set); miss=0; lock=0
        for i in d["items"]:
            t=text(i)
            if not t: miss+=1; continue
            h,hook=classify(t)
            for k in h:
                c[k]+=1; repos[k].add(i["repo"])
                if hook: hk[k].add(i["repo"])
            if i["path"].endswith(".lock.yml") and h: lock+=1
        print(n,"items",len(d["items"]),"unfetched",miss,"file-level",dict(c),"repo-level",{k:len(v) for k,v in repos.items()},"repos w/ inline hook text",{k:len(v) for k,v in hk.items()},"lock.yml hits",lock)
