"""Static triage of binary MCPB entry points: format, language/toolchain, Go build info.
Nothing is executed; `go version -m` only parses the embedded buildinfo section."""
import json, subprocess, sys, re, os
from pathlib import Path
bins = json.load(open(sys.argv[1])); out = []
def sh(*a):
    try: return subprocess.run(a, capture_output=True, text=True, timeout=120).stdout
    except Exception as e: return ""
for d, entry, ntools in bins:
    x = Path(d) / "x"; man = json.load(open(x / "manifest.json"))
    cand = x / (entry or "")
    if not cand.is_file() or cand.stat().st_size < 200_000 or cand.suffix in (".sh", ".cmd", ".bat", ".ps1"):
        # entry is a launcher script: pick the largest executable-looking file in the bundle
        files = [p for p in x.rglob("*") if p.is_file() and p.stat().st_size > 500_000]
        cand = max(files, key=lambda p: p.stat().st_size) if files else cand
    rec = dict(dir=d, server=json.load(open(Path(d) / "meta.json"))["server"], entry=entry, binary=str(cand.relative_to(x)) if cand.exists() else None,
               declared_tools=[t.get("name") for t in man.get("tools") or []], tools_generated=man.get("tools_generated", False))
    if cand.is_file():
        rec["file"] = sh("file", "-b", str(cand))[:120]; rec["size"] = cand.stat().st_size
        bi = sh("go", "version", "-m", str(cand))
        if bi:
            rec["lang"] = "go"; rec["go_main"] = (re.search(r"\n\s*path\s+(\S+)", bi) or [None, None])[1]
            rec["go_deps"] = re.findall(r"\n\s*dep\s+(\S+)\s+(\S+)", bi)
        else:
            head = open(cand, "rb").read()
            if b"_MEIPASS" in head or b"PyInstaller" in head: rec["lang"] = "pyinstaller"
            elif b"/rustc/" in head or b".cargo/registry" in head: rec["lang"] = "rust"
            elif b"BSJ\x42" in head or b"mscoree.dll" in head or b"System.Private.CoreLib" in head: rec["lang"] = "dotnet"
            elif b"NODE_SEA_BLOB" in head or b"bun:main" in head or b"BUN_" in head: rec["lang"] = "js-bundled(node-sea/bun)"
            elif b"pkg/prelude" in head: rec["lang"] = "js-bundled(pkg)"
            elif b"__nuitka" in head.lower() or b"nuitka" in head.lower(): rec["lang"] = "nuitka"
            else: rec["lang"] = "unknown"
    out.append(rec)
json.dump(out, open(sys.argv[2], "w"), indent=1)
import collections
print(collections.Counter(r.get("lang") for r in out))
print(collections.Counter(dep for r in out for dep, v in r.get("go_deps", []) if "mcp" in dep.lower()))
