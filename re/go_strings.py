"""Recover Go string literals *as referenced by code* (pointer + length pairs) from
a compiled binary, without executing it. Go strings are not NUL-terminated, so a
plain `strings` dump merges neighbours; the code that loads them carries the exact
length. Supports x86-64 (LEA rip-rel + MOV imm) and arm64 (ADRP+ADD + MOV imm),
ELF / Mach-O (incl. universal) / PE via LIEF, disassembly via Capstone.

Then, for each tool name declared in the bundle manifest, find the literal equal to
the name in code and the description literal loaded next to it (same registration
call site) -> the description the server actually sends in tools/list."""
import sys, json, re
import lief, capstone
from capstone import x86_const, arm64_const

def load(path):
    b = lief.parse(path)
    if isinstance(b, lief.MachO.FatBinary):
        pick = None
        for i in range(b.size):
            m = b.at(i)
            if m.header.cpu_type == lief.MachO.Header.CPU_TYPE.X86_64: pick = m
            if pick is None and m.header.cpu_type == lief.MachO.Header.CPU_TYPE.ARM64: pick = m
        b = pick or b.at(0)
    return b

def arch_of(b):
    if isinstance(b, lief.ELF.Binary): return "x86" if b.header.machine_type == lief.ELF.ARCH.X86_64 else "arm64"
    if isinstance(b, lief.MachO.Binary): return "x86" if b.header.cpu_type == lief.MachO.Header.CPU_TYPE.X86_64 else "arm64"
    return "x86" if b.header.machine == lief.PE.Header.MACHINE_TYPES.AMD64 else "arm64"

def sections(b):
    base = b.optional_header.imagebase if isinstance(b, lief.PE.Binary) else 0
    out = []
    for s in b.sections:
        out.append((s.name, base + s.virtual_address, bytes(s.content)))
    return out

def read(secs, addr, n):
    for name, va, data in secs:
        if va <= addr and addr + n <= va + len(data): return data[addr - va: addr - va + n]
    return None

def text_section(secs):
    for name, va, data in secs:
        if name in (".text", "__text"): return va, data
    raise RuntimeError("no text")

def sweep(md, code, va, step):
    """Linear sweep that skips undecodable bytes instead of stopping (Capstone stops at
    the first invalid instruction; Go text contains alignment padding / data)."""
    off = 0; n = len(code)
    while off < n:
        last = off
        for ins in md.disasm_lite(code[off:], va + off):
            yield ins
            last = ins[0] - va + ins[1]
        off = last + step   # skip the undecodable unit (or finish when last == n)

def _try(secs, tgt, n, minlen, maxlen):
    if not (minlen <= n <= maxlen): return None
    raw = read(secs, tgt, n)
    if not raw: return None
    try: s = raw.decode("utf-8")
    except UnicodeDecodeError: return None
    return s if (s.isprintable() or "\n" in s) else None

MEM = re.compile(r"(?:qword ptr )?\[(\w+)(?: ([+-]) (0x[0-9a-f]+|\d+))?\]")
def _slot(txt):
    m = MEM.search(txt)
    if not m: return None
    off = int(m.group(3), 0) * (-1 if m.group(2) == "-" else 1) if m.group(3) else 0
    return (m.group(1), off)

def literals(path, minlen=3, maxlen=20000):
    """Pair each code-loaded string pointer with its length, in either order:
    (a) register pair  ptr->reg, len->next arg reg      (Go regabi call args)
    (b) memory slots   ptr->[base+o], len->[base+o+8]   (struct / composite literal)"""
    b = load(path); arch = arch_of(b); secs = sections(b); va, code = text_section(secs)
    lits = []; idx = 0
    ptr_reg = {}; imm_reg = {}; ptr_slot = {}; len_slot = {}
    def emit(i, tgt, n):
        s = _try(secs, tgt, n, minlen, maxlen)
        if s is not None: lits.append((i, s)); return True
        return False
    if arch == "x86":
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        last_lea = None
        for (addr, size, mn, ops) in sweep(md, code, va, 1):
            idx += 1
            if mn == "lea" and "[rip" in ops:
                m = re.search(r"^(\w+), \[rip ([+-]) 0x([0-9a-f]+)\]", ops)
                if m:
                    tgt = addr + size + int(m.group(3), 16) * (1 if m.group(2) == "+" else -1)
                    ptr_reg[m.group(1)] = (idx, tgt); last_lea = (idx, tgt)
                continue
            if mn != "mov": continue
            dst, _, src = ops.partition(", ")
            if "[" in dst:
                sl = _slot(dst)
                if not sl: continue
                if src in ptr_reg and idx - ptr_reg[src][0] <= 8:
                    ptr_slot[sl] = (idx, ptr_reg[src][1])
                    L = len_slot.get((sl[0], sl[1] + 8))
                    if L and abs(idx - L[0]) <= 10 and emit(idx, ptr_reg[src][1], L[1]): len_slot.pop((sl[0], sl[1] + 8), None)
                elif re.fullmatch(r"0x[0-9a-f]+|\d+", src):
                    n = int(src, 0); len_slot[sl] = (idx, n)
                    P = ptr_slot.get((sl[0], sl[1] - 8))
                    if P and abs(idx - P[0]) <= 10 and emit(idx, P[1], n): ptr_slot.pop((sl[0], sl[1] - 8), None)
            elif re.fullmatch(r"0x[0-9a-f]+|\d+", src):
                if last_lea and idx - last_lea[0] <= 4 and emit(idx, last_lea[1], int(src, 0)): last_lea = None
                else: imm_reg[dst] = (idx, int(src, 0))
            if len(len_slot) > 64: len_slot = {k: v for k, v in len_slot.items() if idx - v[0] <= 10}
            if len(ptr_slot) > 64: ptr_slot = {k: v for k, v in ptr_slot.items() if idx - v[0] <= 10}
    else:
        md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
        pages = {}; pend = []
        for (addr, size, mn, ops) in sweep(md, code, va, 4):
            idx += 1
            if mn == "adrp":
                m = re.match(r"(\w+), #0x([0-9a-f]+)", ops)
                if m: pages[m.group(1)] = (idx, int(m.group(2), 16))
            elif mn == "add":
                m = re.match(r"(\w+), (\w+), #0x([0-9a-f]+)$", ops)
                if m and m.group(2) in pages and idx - pages[m.group(2)][0] <= 3:
                    ptr_reg[m.group(1)] = (idx, pages[m.group(2)][1] + int(m.group(3), 16))
                    pend.append((idx, ptr_reg[m.group(1)][1]))
            elif mn in ("mov", "movz", "orr"):
                m = re.match(r"(\w+), #(0x[0-9a-f]+|\d+)$", ops) or re.match(r"(\w+), \w+, #(0x[0-9a-f]+|\d+)$", ops)
                if m:
                    r_, n = m.group(1), int(m.group(2), 0); imm_reg[r_] = (idx, n)
                    # call-arg idiom: ADRP/ADD ptr then MOV $len (most recent unconsumed pointer)
                    if pend and idx - pend[-1][0] <= 4 and emit(idx, pend[-1][1], n): pend.pop()
            elif mn == "stp":
                m = re.match(r"(\w+), (\w+), \[", ops)
                if m and m.group(1) in ptr_reg and m.group(2) in imm_reg and idx - ptr_reg[m.group(1)][0] <= 8 and idx - imm_reg[m.group(2)][0] <= 8:
                    emit(idx, ptr_reg[m.group(1)][1], imm_reg[m.group(2)][1])
            elif mn == "str":
                m = re.match(r"(\w+), \[(\w+)(?:, #(-?0x[0-9a-f]+|-?\d+))?\]", ops)
                if m:
                    sl = (m.group(2), int(m.group(3), 0) if m.group(3) else 0)
                    if m.group(1) in ptr_reg and idx - ptr_reg[m.group(1)][0] <= 8:
                        ptr_slot[sl] = (idx, ptr_reg[m.group(1)][1]); L = len_slot.get((sl[0], sl[1] + 8))
                        if L and abs(idx - L[0]) <= 10: emit(idx, ptr_reg[m.group(1)][1], L[1])
                    elif m.group(1) in imm_reg and idx - imm_reg[m.group(1)][0] <= 8:
                        n = imm_reg[m.group(1)][1]; len_slot[sl] = (idx, n); P = ptr_slot.get((sl[0], sl[1] - 8))
                        if P and abs(idx - P[0]) <= 10: emit(idx, P[1], n)
            if len(len_slot) > 64: len_slot = {k: v for k, v in len_slot.items() if idx - v[0] <= 10}
            if len(ptr_slot) > 64: ptr_slot = {k: v for k, v in ptr_slot.items() if idx - v[0] <= 10}
            if pend and idx - pend[0][0] > 6: pend = [q for q in pend if idx - q[0] <= 6]
    lits.extend(data_literals(secs, minlen, maxlen))
    return arch, lits

def data_literals(secs, minlen, maxlen):
    """Statically initialised Go strings (global tables of tool specs): 16-byte
    {ptr, len} headers inside data sections. Position = address/8 in a separate
    index space so neighbouring struct fields stay 'close'."""
    import struct
    ro = [(va, len(d)) for n, va, d in secs if "rodata" in n or n in (".rdata", "__cstring", "__const")]
    def in_ro(a): return any(v <= a < v + l for v, l in ro)
    out = []
    for name, va, data in secs:
        if not any(k in name for k in ("data", "__const")) or "rodata" in name or name == ".rdata": continue
        for off in range(0, len(data) - 15, 8):
            ptr, n = struct.unpack_from("<QQ", data, off)
            if minlen <= n <= maxlen and in_ro(ptr):
                s_ = _try(secs, ptr, n, minlen, maxlen)
                if s_ is not None: out.append((10**9 + (va + off) // 8, s_))
    return out

FMT = re.compile(r"%[-+# 0-9.]*[sdvqxXfgtTwp]")
def looks_like_description(t):
    """Tool descriptions are sentence-like prose; reject format strings / error
    messages (Go errors are lowercase by convention) and short parameter hints."""
    u = t.strip()
    if len(u) < 30 or " " not in u or FMT.search(u): return False
    if u[0].islower(): return False
    if len(u.split()) < 6: return False
    return True

def served_descriptions(path, names, span=60):
    arch, lits = literals(path)
    blob = open(path, "rb").read()
    out = {}
    pos = {}
    for k, (i, s) in enumerate(lits): pos.setdefault(s, []).append(k)
    for name in names:
        best = None
        for k in pos.get(name, []):
            i0 = lits[k][0]
            # nearest long, sentence-like literal at the same call site (prefer after the name)
            cands = [(abs(lits[j][0] - i0) + (0 if j > k else 5) - min(len(lits[j][1]), 400) / 20, lits[j][1]) for j in range(max(0, k - 15), min(len(lits), k + 25))
                     if j != k and abs(lits[j][0] - i0) <= span and looks_like_description(lits[j][1])]
            if cands:
                c = min(cands)
                if best is None or c[0] < best[0]: best = c
        out[name] = best[1] if best else None
        if out[name] is None and blob is not None:   # go:embed'ed JSON tool catalogue
            m = re.search(rb'"name"\s*:\s*"' + re.escape(name.encode()) + rb'"[^{}]{0,600}?"description"\s*:\s*"((?:[^"\\]|\\.)*)"', blob)
            if m:
                try: out[name] = json.loads(b'"' + m.group(1) + b'"')
                except Exception: pass
    return arch, len(lits), out

if __name__ == "__main__":
    path, names = sys.argv[1], json.loads(sys.argv[2])
    print(json.dumps(served_descriptions(path, names), indent=1))
