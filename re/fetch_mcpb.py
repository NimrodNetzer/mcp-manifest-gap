"""Download MCPB (desktop extension) bundles listed in the official MCP registry,
verify the registry-pinned sha256, and unpack manifest + payload. Never executes anything."""
import json, sys, random, hashlib, zipfile, urllib.request, io
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
reg = json.load(open(sys.argv[1])); OUT = Path(sys.argv[2]); N = int(sys.argv[3])
items = []
for s in reg:
    for p in s.get("packages") or []:
        if p.get("registryType") == "mcpb":
            items.append(dict(server=s["name"], url=p["identifier"], sha256=p.get("fileSha256"), version=s.get("version")))
random.seed(11); sample = random.sample(items, min(N, len(items)))

def one(it):
    key = hashlib.sha1(it["url"].encode()).hexdigest()[:12]; d = OUT / key
    if (d / "meta.json").exists(): return
    d.mkdir(parents=True, exist_ok=True); meta = dict(it)
    try:
        req = urllib.request.Request(it["url"], headers={"User-Agent": "mcp-research-client"})
        with urllib.request.urlopen(req, timeout=120) as r:
            if int(r.headers.get("Content-Length") or 0) > 150e6: raise RuntimeError("too large")
            blob = r.read(int(150e6) + 1)
        meta["size"] = len(blob); meta["sha256_actual"] = hashlib.sha256(blob).hexdigest()
        meta["sha256_match"] = (meta["sha256_actual"] == (it["sha256"] or "").lower()) if it["sha256"] else None
        z = zipfile.ZipFile(io.BytesIO(blob)); meta["files"] = [(i.filename, i.file_size) for i in z.infolist()][:5000]
        for i in z.infolist():
            if i.is_dir() or ".." in i.filename or i.filename.startswith("/"): continue
            if "node_modules/" in i.filename and not i.filename.endswith("package.json"): continue
            target = d / "x" / i.filename; target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(z.read(i))
        meta["status"] = "ok"
    except Exception as e:
        meta["status"] = "error"; meta["error"] = f"{type(e).__name__}: {str(e)[:200]}"
    (d / "meta.json").write_text(json.dumps(meta))

with ThreadPoolExecutor(12) as ex: list(ex.map(one, sample))
