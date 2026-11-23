"""For every Go binary with manifest-declared tools: recover the description the
binary serves (go_strings.py) and compare it with the manifest description.
Also run the phase-1 declaration rules on both texts to see which security-relevant
signals exist ONLY in the model-facing text."""
import json, sys, difflib, collections, re
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent)); sys.path.insert(0, str(Path(__file__).parent.parent / "scanner"))
import go_strings
from rules import scan_text

rows = json.load(open(sys.argv[1])); out = []
seen = set()
for r in rows:
    if r["lang"] != "go" or not r["declared"] or r["server"] in seen: continue
    man = json.load(open(Path(r["dir"]) / "x" / "manifest.json")); decl = [t for t in man.get("tools") or [] if t.get("name")]
    try:
        arch, nlit, served = go_strings.served_descriptions(str(Path(r["dir"]) / "x" / r["binary"]), [t["name"] for t in decl])
    except Exception as e:
        out.append({"server": r["server"], "error": repr(e)[:200]}); continue
    seen.add(r["server"])
    names = {t["name"].lower() for t in decl}
    for t in decl:
        m = (t.get("description") or "").strip(); s = served.get(t["name"])
        rec = {"server": r["server"], "arch": arch, "tool": t["name"], "manifest": m, "served": s}
        if s is None: rec["cls"] = "not_recovered"
        else:
            s2 = s.strip()
            ratio = difflib.SequenceMatcher(None, m.lower(), s2.lower()).ratio()
            rec["similarity"] = round(ratio, 2); rec["len_manifest"] = len(m); rec["len_served"] = len(s2)
            rec["fragment"] = s.startswith(" ")
            rec["cls"] = "identical" if m == s2 else ("served_extends_manifest" if s2.startswith(m.rstrip(".")) else "different")
            rm = {h[0] for h in scan_text(m, t["name"], names)}; rs = {h[0] for h in scan_text(s2, t["name"], names)}
            rec["signals_only_served"] = sorted(rs - rm)
        out.append(rec)
json.dump(out, open(sys.argv[2], "w"), indent=1)
ok = [o for o in out if "cls" in o]
print("servers:", len(seen), "tools:", len(ok), "errors:", sum(1 for o in out if "error" in o))
print(collections.Counter(o["cls"] for o in ok))
rec = [o for o in ok if o["cls"] != "not_recovered"]
print("served longer than manifest:", sum(1 for o in rec if o["len_served"] > o["len_manifest"]), "/", len(rec))
print("median len manifest/served:", sorted(o["len_manifest"] for o in rec)[len(rec)//2], sorted(o["len_served"] for o in rec)[len(rec)//2])
print("signals only in served text:", collections.Counter(x for o in rec for x in o["signals_only_served"]))
print("tools with >=1 served-only signal:", sum(1 for o in rec if o["signals_only_served"]), "servers:", len({o["server"] for o in rec if o["signals_only_served"]}))
