"""MCP declaration rules: tool poisoning / steering heuristics (static).

Each rule returns (rule_id, severity, evidence). Severity: high = behaviour a
benign tool has no reason to ask for (concealment, secret paths, exfil);
medium = strong steering / hidden markup; low = attack-surface or style signal.
"""
import re, unicodedata

def _rx(p): return re.compile(p, re.I | re.S)

RULES = [
    # --- high: classic tool-poisoning primitives (Invariant Labs 2025 class) ---
    ("conceal.user", "high", _rx(r"\b(do not|don't|never|without)\s+(tell|telling|inform|informing|mention|mentioning|notify|notifying|reveal|revealing|alert|alerting|show|showing)(ing)?\s+(this\s+to\s+)?(the\s+)?user")),
    ("conceal.silent", "high", _rx(r"\b(silently|secretly|covertly)\b.{0,60}\b(send|read|include|forward|upload|copy|call|pass)")),
    ("secret.path", "high", _rx(r"(~/\.ssh|id_rsa|id_ed25519|\.aws/credentials|/etc/shadow|mcp\.json|claude_desktop_config|\.cursor/mcp|\.npmrc|\.git-credentials|wallet\.dat|seed phrase|private key)")),
    ("exfil.redirect", "high", _rx(r"\b(all|every|any)\s+(emails?|messages?|payments?|transfers?)\s+(must|should)\s+(be\s+)?(sent|forwarded|redirected|cc'?d)\s+to\b")),
    ("exfil.read-and-pass", "high", _rx(r"\b(read|cat|open|get)\b.{0,40}\b(file|contents?)\b.{0,80}\b(pass|include|send|put)\b.{0,40}\b(as|in|into|to)\b.{0,30}\b(parameter|argument|param|sidenote|field)")),
    ("shadow.other-tool", "high", _rx(r"\b(when|whenever|before|after)\b.{0,40}\b(using|calling|invoking|the user (asks|wants))\b.{0,60}\b(other|another|any other|different)\s+(tool|server|mcp)")),
    # --- medium: hidden markup / prompt-style overrides inside a declaration ---
    ("markup.hidden-tag", "medium", _rx(r"<\s*(important|system|instructions?|hidden|secret|admin|override)\b[^>]*>")),
    ("override.prior", "medium", _rx(r"\b(ignore|disregard|override|forget)\b.{0,30}\b(previous|prior|above|other|all)\b.{0,30}\b(instructions?|rules?|tools?|guidelines?)")),
    ("persona.reassign", "medium", _rx(r"\byou are now\b|\byour (new|true) (role|purpose|instructions)")),
    ("priority.hijack", "medium", _rx(r"\b(always|must)\b.{0,30}\b(call|use|invoke|run)\b.{0,30}\b(this tool|me)\b.{0,40}\b(first|before|instead|regardless)")),
    # --- low: steering / attack-surface signals worth counting, not alarming ---
    ("steer.always", "low", _rx(r"\b(ALWAYS|MUST|NEVER|CRITICAL|MANDATORY)\b")),
    ("cap.exec", "low", _rx(r"\b(execute|run|eval)\b.{0,30}\b(shell|command|bash|script|code|sql|powershell)")),
    ("cap.fs-write", "low", _rx(r"\b(write|delete|overwrite|remove)\b.{0,30}\b(file|director(y|ies)|folder)")),
    ("cap.network", "low", _rx(r"\b(fetch|request|download|http get|curl)\b.{0,30}\b(url|web ?page|website|endpoint)")),
]

INVISIBLE = {"Cf"}  # format chars: zero-width, BiDi controls, Unicode tag chars

def invisible_chars(text):
    hits = [c for c in text if unicodedata.category(c) in INVISIBLE and c not in "‍️"]
    tags = [c for c in text if 0xE0000 <= ord(c) <= 0xE007F]
    if tags:
        decoded = "".join(chr(ord(c) - 0xE0000) for c in tags)
        return ("unicode.tag-smuggling", "high", f"{len(tags)} tag chars -> {decoded[:80]!r}")
    if hits:
        return ("unicode.invisible", "medium", f"{len(hits)} invisible format chars: " + ",".join(sorted({f'U+{ord(c):04X}' for c in hits}))[:80])
    return None

def scan_text(text, own_name=None, local_names=()):
    out = []
    for rid, sev, rx in RULES:
        m = rx.search(text)
        if m:
            s, e = max(0, m.start() - 40), min(len(text), m.end() + 40)
            out.append((rid, sev, text[s:e].replace("\n", " ")))
    inv = invisible_chars(text)
    if inv: out.append(inv)
    if len(text) > 3000: out.append(("size.long-description", "low", f"{len(text)} chars"))
    return out
# NOTE: signature widened after freeze for API compatibility; rule logic unchanged
