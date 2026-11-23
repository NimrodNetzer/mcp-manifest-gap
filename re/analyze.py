"""Declared-vs-actual analysis of binary MCP servers (static only).
For each binary: (1) are the manifest-declared tool names / descriptions present in
the binary? (2) capability inventory from recovered Go symbols (GoReSym) or Rust
crate paths; (3) embedded hosts. Output: one JSON row per binary."""
import json, re, subprocess, sys
from pathlib import Path
from urllib.parse import urlparse
tri = json.load(open(sys.argv[1])); GORESYM = sys.argv[3]

GO_CAPS = {  # stdlib / common package prefixes -> capability label
    "exec": [r"^os/exec\."], "net-client": [r"^net/http\.\(\*Client\)\.Do", r"^net/http\.Get$", r"^net/http\.Post", r"^net\.Dial"],
    "net-listen": [r"^net/http\.ListenAndServe", r"^net\.Listen"], "fs-read": [r"^os\.ReadFile$", r"^os\.Open$", r"^io/ioutil\.ReadFile"],
    "fs-write": [r"^os\.WriteFile$", r"^os\.Create$", r"^os\.Remove", r"^os\.Rename$"], "home-dir": [r"^os\.UserHomeDir$"],
    "env-read": [r"^os\.Environ$"], "keychain": [r"keyring", r"keychain"], "clipboard": [r"clipboard"], "screenshot": [r"screenshot"],
    "ptrace/proc": [r"^syscall\.PtraceAttach", r"process\.Processes"], "crypto-wallet": [r"go-ethereum", r"solana"],
}
RUST_CAPS = {"exec": [rb"std::process::Command", rb"process/command\.rs", rb"tokio::process", rb"tokio-[\d.]+/src/process"],
             "net-client": [rb"reqwest-", rb"hyper-[\d.]+/src/client", rb"ureq-"], "net-listen": [rb"axum-", rb"actix-web", rb"tokio-[\d.]+/src/net/tcp/listener"],
             "fs-write": [rb"std::fs::write", rb"fs::remove_file"], "home-dir": [rb"dirs-", rb"home-[\d.]+/src"],
             "keychain": [rb"keyring-", rb"security-framework"], "clipboard": [rb"arboard-", rb"clipboard"], "screenshot": [rb"xcap-", rb"screenshots-"]}
TELEMETRY = re.compile(rb"(posthog-go|app\.posthog\.com|us\.i\.posthog\.com|eu\.i\.posthog\.com|api2?\.amplitude\.com|api\.mixpanel\.com|api\.segment\.io|getsentry/sentry-go|ingest\.sentry\.io|datadoghq\.com|api\.honeycomb\.io|otlp|opentelemetry\.io/otel/exporters)", re.I)
URL = re.compile(rb"https?://[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
SENSITIVE = re.compile(rb"(\.ssh/|id_rsa|\.aws/credentials|Login Data|Cookies|\.config/gcloud|keychain-db|wallet\.dat|\.npmrc|\.git-credentials|claude_desktop_config\.json|\.cursor/mcp\.json)")

rows = []
for r in tri:
    if r.get("lang") not in ("go", "rust") or not r.get("binary"): continue
    p = Path(r["dir"]) / "x" / r["binary"]; blob = p.read_bytes()
    man = json.load(open(Path(r["dir"]) / "x" / "manifest.json")); decl = man.get("tools") or []
    row = {k: r[k] for k in ("server", "dir", "binary", "lang", "tools_generated")}
    row["declared"] = len(decl)
    row["declared_name_missing"] = [t["name"] for t in decl if t.get("name") and t["name"].encode() not in blob]
    desc_div = []
    for t in decl:
        d = (t.get("description") or "").strip()
        if len(d) >= 25 and d[:40].encode() not in blob and t.get("name", "").encode() in blob: desc_div.append(t["name"])
    row["description_diverges"] = desc_div
    caps = set()
    if r["lang"] == "go":
        try:
            g = json.loads(subprocess.run([GORESYM, "-t", "-d", "-p", str(p)], capture_output=True, text=True, timeout=300).stdout)
            syms = [f["FullName"] for f in (g.get("UserFunctions") or []) + (g.get("StdFunctions") or [])]
            row["user_funcs"] = len(g.get("UserFunctions") or [])
            for cap, pats in GO_CAPS.items():
                if any(re.search(pp, s) for pp in pats for s in syms): caps.add(cap)
            row["handler_like_funcs"] = sorted({s for s in (f["FullName"] for f in g.get("UserFunctions") or []) if re.search(r"(?i)\.(handle|tool)[A-Z_]\w*$", s)})[:200]
        except Exception as e:
            row["goresym_error"] = repr(e)[:120]
        if not row.get("user_funcs"):
            # GoReSym cannot parse newer pclntab layouts (Go 1.26+ here); function names are
            # still stored as strings in pclntab, so fall back to a byte search for them.
            FALLBACK = {"exec": [b"os/exec.Command"], "net-client": [b"net/http.(*Client).Do"], "net-listen": [b"net/http.ListenAndServe", b"net.Listen"],
                        "fs-read": [b"os.ReadFile"], "fs-write": [b"os.WriteFile", b"os.Remove"], "home-dir": [b"os.UserHomeDir"],
                        "keychain": [b"keyring", b"wincred"], "clipboard": [b"clipboard"], "screenshot": [b"screenshot"]}
            caps |= {c for c, ps in FALLBACK.items() if any(pp in blob for pp in ps)}; row["caps_method"] = "pclntab-strings"
    else:
        for cap, pats in RUST_CAPS.items():
            if any(pp in blob for pp in pats): caps.add(cap)
    row["caps"] = sorted(caps)
    row["telemetry"] = sorted({m.group(1).decode().lower() for m in TELEMETRY.finditer(blob)})
    hosts = {urlparse(u.decode()).hostname for u in URL.findall(blob)}
    row["hosts"] = sorted(h for h in hosts if h and not re.search(r"(golang\.org|github\.com|go\.dev|rust-lang|w3\.org|json-schema|example\.(com|org)|googleapis\.com/auth|localhost|mozilla|apple\.com/DTDs|xml|schemas\.|crates\.io|docs\.rs|opensource|semver|unicode\.org|ietf|iana|modelcontextprotocol)", h))[:60]
    row["sensitive_paths"] = sorted({m.group(1).decode() for m in SENSITIVE.finditer(blob)})
    rows.append(row)
json.dump(rows, open(sys.argv[2], "w"), indent=1)
print(len(rows))
