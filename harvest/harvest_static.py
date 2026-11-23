"""Download npm tarballs of MCP servers listed in the official registry and
statically extract tool declarations (no package code is executed)."""
import json, subprocess, sys, tempfile, hashlib, os, tarfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
EXTRACT = str(Path(__file__).with_name("extract_tools.js"))
items = json.load(open(sys.argv[1])); OUT = Path(sys.argv[2]); OUT.mkdir(parents=True, exist_ok=True)

def one(it):
    out = OUT / (hashlib.sha1(it["pkg"].encode()).hexdigest()[:12] + ".json")
    if out.exists(): return
    rec = dict(it)
    with tempfile.TemporaryDirectory() as d:
        try:
            spec = f'{it["pkg"]}@{it["version"]}' if it.get("version") not in (None, "", "latest") else it["pkg"]
            r = subprocess.run(["npm", "pack", spec, "--silent", "--pack-destination", d], capture_output=True, text=True, timeout=120, cwd=d)
            if r.returncode: raise RuntimeError(r.stderr.strip()[-200:])
            tgz = next(Path(d).glob("*.tgz"))
            with tarfile.open(tgz) as t: t.extractall(Path(d) / "x", filter="data")
            pkgdir = next((Path(d) / "x").iterdir())
            r = subprocess.run(["node", EXTRACT, str(pkgdir)], capture_output=True, text=True, timeout=180)
            rec.update(json.loads(r.stdout)); rec["status"] = "ok"
            try: rec["pkg_json"] = {k: v for k, v in json.loads((pkgdir / "package.json").read_text()).items() if k in ("version", "repository", "homepage", "dependencies")}
            except Exception: pass
        except Exception as e:
            rec["status"] = "error"; rec["error"] = f"{type(e).__name__}: {str(e)[:200]}"
    out.write_text(json.dumps(rec))

with ThreadPoolExecutor(16) as ex: list(ex.map(one, items))
