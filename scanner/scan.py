"""Scan harvested MCP declarations with (1) Olive's own inbound inspectors
(PatternInspector + DecodeInspector, unchanged, reused from the Olive repo) and
(2) MCP-specific declaration rules (rules.py). Writes findings.jsonl + summary."""
import asyncio, json, sys, yaml, collections
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from rules import scan_text

OLIVE = Path(sys.argv[3]) if len(sys.argv) > 3 else None
if OLIVE: sys.path.insert(0, str(OLIVE / "src"))
from olive.inspectors.patterns import PatternInspector
from olive.inspectors.decode import DecodeInspector
from olive.gateway.pipeline import Decision

import re
TEST_FILE = re.compile(r"(^|/)(tests?|__tests__|fixtures?|examples?)/|\.(test|spec)\.[mc]?js$")

class Ctx:  # inspectors only read content; a minimal stand-in context
    direction = "inbound"; tool_name = "tools/list"; role = "scanner"; session_id = "scan"

PATTERNS = yaml.safe_load(open((OLIVE or Path(".")) / "policies/default.yaml"))["injection_patterns"]
OLIVE_INSPECTORS = [PatternInspector(PATTERNS), DecodeInspector(PATTERNS)]

def tool_text(t):
    return "\n".join(filter(None, [t.get("title"), t.get("description"), *t.get("param_texts", []), " ".join(t.get("params", []))]))

async def olive_verdict(text):
    for insp in OLIVE_INSPECTORS:
        try:
            v = await insp.inspect(Ctx(), text)
        except Exception as e:
            return ("olive.error", "low", repr(e)[:80])
        if v.decision != Decision.ALLOW:
            return (f"olive.{v.rule}", "medium", (v.evidence or "")[:160])
    return None

async def main(decl_dir, out_dir):
    out = Path(out_dir); out.mkdir(parents=True, exist_ok=True)
    stats = collections.Counter(); per_rule = collections.Counter(); per_rule_servers = collections.defaultdict(set)
    sev_servers = collections.defaultdict(set)
    with open(out / "findings.jsonl", "w") as fh:
        for f in sorted(Path(decl_dir).glob("*.json")):
            rec = json.loads(f.read_text()); stats["packages"] += 1
            if rec.get("status") != "ok": stats["download_error"] += 1; continue
            tools = [t for t in rec.get("tools", []) if not TEST_FILE.search(t.get("file") or "")]
            stats["packages_ok"] += 1; stats["tools"] += len(tools)
            if tools: stats["packages_with_tools"] += 1
            local = {n.lower() for t in tools for n in [t["name"], *t.get("params", [])]}
            for t in tools:
                text = tool_text(t)
                hits = scan_text(text, t.get("name"), local)
                ov = await olive_verdict(text)
                if ov: hits.append(ov)
                for rid, sev, ev in hits:
                    per_rule[rid] += 1; per_rule_servers[rid].add(rec["pkg"]); sev_servers[sev].add(rec["pkg"])
                if hits:
                    fh.write(json.dumps({"pkg": rec["pkg"], "server": rec["server"], "version": rec.get("version"), "repo": rec.get("repo"),
                                         "tool": t["name"], "file": t.get("file"), "findings": hits, "text": text[:4000]}) + "\n")
    summary = {"stats": dict(stats),
               "rules": {r: {"tools": per_rule[r], "packages": len(per_rule_servers[r])} for r in sorted(per_rule, key=lambda r: -per_rule[r])},
               "packages_by_max_severity": {s: len(v) for s, v in sev_servers.items()}}
    (out / "summary.json").write_text(json.dumps(summary, indent=1))
    print(json.dumps(summary, indent=1))

asyncio.run(main(sys.argv[1], sys.argv[2]))
