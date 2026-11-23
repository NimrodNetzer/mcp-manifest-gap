"""Recall on MCPTox poisoned tool descriptions (independent, AAAI'26, CC BY 4.0).
Rules v1 were written BEFORE looking at this dataset (see rules.v1.sha256)."""
import json, sys, asyncio, collections, importlib
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
OLIVE = Path(sys.argv[2]); sys.path.insert(0, str(OLIVE / "src"))
rules = importlib.import_module(sys.argv[3] if len(sys.argv) > 3 else "rules")
import yaml
from olive.inspectors.patterns import PatternInspector
from olive.inspectors.decode import DecodeInspector
from olive.gateway.pipeline import Decision
class Ctx: direction = "inbound"
P = yaml.safe_load(open(OLIVE / "policies/default.yaml"))["injection_patterns"]
INS = [PatternInspector(P), DecodeInspector(P)]

async def olive(text):
    for i in INS:
        v = await i.inspect(Ctx(), text)
        if v.decision != Decision.ALLOW: return True
    return False

async def main():
    data = json.load(open(sys.argv[1]))
    cases = [v for block in data for v in block.values()]
    split = sys.argv[5] if len(sys.argv) > 5 else "all"
    dev = set(json.load(open(Path(__file__).with_name("mcptox_dev_servers.json"))))
    if split == "dev": cases = [c for c in cases if c["server_name"] in dev]
    if split == "test": cases = [c for c in cases if c["server_name"] not in dev]
    agg = collections.Counter(); by_par = collections.defaultdict(collections.Counter); by_risk = collections.defaultdict(collections.Counter); rulehits = collections.Counter()
    misses = []
    for c in cases:
        text = c["tool_content"]
        hits = rules.scan_text(text, c.get("tool_name"))
        hi = [h for h in hits if h[1] in ("high", "medium")]
        o = await olive(text)
        for h in hits: rulehits[h[0]] += 1
        r = dict(n=1, olive=o, rules_hm=bool(hi), rules_any=bool(hits), combined_hm=o or bool(hi))
        for k, v in r.items(): agg[k] += v; by_par[c["paradigm"]][k] += v; by_risk[c["security risk"]][k] += v
        if not (o or hi): misses.append(text[:300])
    def fmt(c): return {k: f"{c[k]}/{c['n']} ({100*c[k]/c['n']:.0f}%)" for k in ("olive", "rules_hm", "combined_hm", "rules_any")}
    res = {"overall": fmt(agg), "by_paradigm": {p: fmt(c) for p, c in sorted(by_par.items())},
           "by_risk": {p: fmt(c) for p, c in sorted(by_risk.items())}, "rule_hits": dict(rulehits.most_common())}
    print(json.dumps(res, indent=1)); return res, misses

res, misses = asyncio.run(main())
Path(sys.argv[4] if len(sys.argv) > 4 else "mcptox_eval.json").write_text(json.dumps({"result": res, "sample_misses": misses[:40]}, indent=1))
