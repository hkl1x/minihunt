# -*- coding: utf-8 -*-
"""
extract_offsets.py — WMPF flue.dll Hook 偏移自动提取器
思路来源: CSDN《WMPFDebugger版本适配完全指南》+ 本机 26134 验证管线
用法:
    python extract_offsets.py <flue.dll 路径> [版本号]
输出:
    addresses.<ver>.json 草稿 + 控制台证据报告
"""
import sys, os, json, mmap, struct, bisect, re
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

# ---------- 候选锚点字符串 ----------
# (JSON字段名, 候选字符串列表, 引用要求)
ANCHORS = [
    ("LoadStartHookOffset",
     [b"AppletIndexContainer::OnLoadStart(bool, const std::string &)",  # 锚点1: 日志签名串
      b"applet_index_container.cc"],                                     # 锚点2: 源文件路径串
     "loadstart"),   # 双锚点函数级交集: OnLoadStart 函数同时引用两个字符串
    ("CastToJsonHookOffset", [b"CastToJson\x00"],            "unique"),
    ("CDPFilterHookOffset",  [b"SendToClientFilter\x00"],    "pick_enclosing"),
]

def log(msg):
    print(msg, flush=True)

def find_ascii(hay, needle, limit=16):
    hits, start = [], 0
    while len(hits) < limit:
        i = hay.find(needle, start)
        if i < 0:
            break
        hits.append(i)
        start = i + 1
    return hits

def main(dll_path, version=None):
    dll_path = os.path.abspath(dll_path)
    if not version:
        m = re.search(r"(\d{5})", os.path.basename(os.path.dirname(os.path.dirname(dll_path))))
        version = m.group(1) if m else "unknown"
    out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), f"addresses.{version}.json")

    log(f"[i] DLL: {dll_path}")
    f = open(dll_path, "rb")
    mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
    pe = pefile.PE(data=mm[:], fast_load=True)
    IMAGE_BASE = pe.OPTIONAL_HEADER.ImageBase
    secs = [(s.Name.rstrip(b"\x00").decode(errors="replace"), s.VirtualAddress,
             max(s.Misc_VirtualSize, s.SizeOfRawData), s.PointerToRawData, s.SizeOfRawData)
            for s in pe.sections]

    def off2va(off):
        for n, va, vsz, raw, rsz in secs:
            if raw <= off < raw + rsz:
                return IMAGE_BASE + va + (off - raw)
        return None

    def rva2off(rva):
        for n, va, vsz, raw, rsz in secs:
            if va <= rva < va + vsz:
                return raw + (rva - va)
        return None

    def cstr_at_va(va, maxn=140):
        o = rva2off(va - IMAGE_BASE)
        if o is None:
            return None
        b = mm[o:o + maxn]
        z = b.find(b"\x00")
        return b[:z if z >= 0 else maxn]

    text = next(s for s in secs if s[0] == ".text")
    tname, tva, tvsz, traw, trsz = text
    img = pe.get_memory_mapped_image()
    text_bytes = bytes(img[tva:tva + tvsz])

    # ---------- .pdata 函数边界表 ----------
    pdata = next(s for s in secs if s[0] == ".pdata")
    pd = img[pdata[1]:pdata[1] + pdata[2]]
    starts = sorted({struct.unpack_from("<III", pd, i * 12)[0] for i in range(len(pd) // 12)})
    def func_bounds(rva):
        i = bisect.bisect_right(starts, rva) - 1
        if i < 0:
            return None, None
        fs = starts[i]
        fe = starts[i + 1] if i + 1 < len(starts) else tva + tvsz
        return fs, fe

    # ---------- 1) 定位锚点字符串 ----------
    log("\n[1] 定位锚点字符串")
    anchor_map = {}   # field -> list of (start_va, end_va, needle)
    for field, needles, _ in ANCHORS:
        for nd in needles:
            hits = find_ascii(mm, nd)
            for h in hits:
                va = off2va(h)
                if va and b"\x00" in mm[h:h + len(nd) + 4]:
                    # 引用可能落在字符串中间(如 path 拼接),记录区间 [va, va+len)
                    anchor_map.setdefault(field, []).append((va, va + len(nd), nd))
        vals = anchor_map.get(field, [])
        log(f"    {field}: {len(vals)} anchor(s) -> {[hex(v[0]) for v in vals]}")

    # ---------- 2) 全 .text RIP 相对引用扫描 ----------
    log("\n[2] 扫描 .text RIP 相对引用 (耗时 ~2-3 分钟)")
    # 锚点区间扩为"完整日志串": 向前回溯到 \x00 之后, 向后到 \x00 — 覆盖 lea 指向串中间的情况
    def full_string_span(file_off):
        s = file_off
        while s > 0 and mm[s - 1] != 0:
            s -= 1
        e = file_off
        while mm[e] != 0:
            e += 1
        return s, e

    target_vas = {}   # va -> (field, anchor_idx)
    anchor_spans = {} # field -> [(start_va, end_va)]
    for field, lst in anchor_map.items():
        spans = []
        for nd in sorted({it[2] for it in lst}):
            h = mm.find(nd)
            while h >= 0:
                va = off2va(h)
                if va:
                    s, e = full_string_span(h)
                    spans.append((va - (h - s), va + (e - h)))
                    break
                h = mm.find(nd, h + 1)
        anchor_spans[field] = spans
        for i, (s, e) in enumerate(spans):
            for v in range(s, e):
                target_vas[v] = (field, i)
        log(f"    {field}: spans -> {[(hex(a), hex(b)) for a, b in spans]}")

    refs = {}  # field -> list of (xref_rva, disp_pos, anchor_idx)
    n = len(text_bytes)
    mv = memoryview(text_bytes)
    # 滑动窗口: 对 .text 每个 disp32 可能位置(指令尾 -4)都解一次 — 覆盖任意长度指令的 rip 相对引用
    for i in range(n - 4):
        d = struct.unpack_from("<i", mv, i)[0]
        if -0x10000000 < d < 0x10000000:  # ±256MB, 覆盖 .text→.rdata 全跨度
            va = IMAGE_BASE + tva + i + 4 + d
            t = target_vas.get(va)
            if t:
                field, ai = t
                refs.setdefault(field, []).append((tva + i, i, ai))
    for k, v in refs.items():
        log(f"    {k}: {len(v)} xref(s)")

    # ---------- 3) xref -> 所属函数起始 (.pdata) ----------
    log("\n[3] 回溯函数起始地址")
    result = {"Version": int(version)}
    evidence = {}

    for field, needles, mode in ANCHORS:
        xrefs = refs.get(field, [])
        # per_anchor[i] = {func: xref_count} 引用第 i 条锚点串的函数
        per_anchor = [{} for _ in anchor_spans.get(field, [])]
        for xref_rva, disp_pos, ai in xrefs:
            fs, fe = func_bounds(xref_rva)
            if not fs:
                continue
            per_anchor[ai][fs] = per_anchor[ai].get(fs, 0) + 1
        cand, how = None, None
        if len(per_anchor) > 1:
            # 多锚点: 取同时引用所有锚点、且引用次数最高的函数 (OnLoadStart 同时引用签名串+源文件路径)
            common = set(per_anchor[0])
            for s in per_anchor[1:]:
                common &= set(s)
            if common:
                cand = max(common, key=lambda f2: sum(s.get(f2, 0) for s in per_anchor))
                how = f"多锚点交集({len(common)}个候选)"
        if cand is None:
            # 单锚点回退
            votes = {}
            for s in per_anchor:
                for fn, c in s.items():
                    votes[fn] = votes.get(fn, 0) + c
            if not votes:
                log(f"    !! {field}: 未找到,需人工分析")
                continue
            if mode == "pick_enclosing":
                # CDPFilter: 取引用它的最大函数体(外层过滤函数, 内部小函数是普通日志点)
                def fsize(fn):
                    a, b = func_bounds(fn)
                    return b - a
                cand = max(votes.items(), key=lambda kv: fsize(kv[0]))[0]
            else:
                # CastToJson: 引用次数最多者
                cand = max(votes.items(), key=lambda kv: kv[1])[0]
            how = "单锚点投票"
        fs, fe = func_bounds(cand)
        result[field] = f"0x{cand:X}"
        evidence[field] = {"func": f"{hex(fs)}..{hex(fe)}", "size": hex(fe - fs), "how": how}
        log(f"    {field} = 0x{cand:X}  [{how}] (func {hex(fs)}..{hex(fe)}, size {hex(fe-fs)})")

    # ---------- 4) 结构体魔法数字扫描 ----------
    log("\n[4] 扫描 Hook 函数及调用链中的结构体魔法数字")
    MAGIC = {0x40: "LaunchConfig[0]", 0x650: "LaunchConfig[1]", 0x8: "LaunchConfig[2]/filter_type",
             0x608: "RemoteDebugConfig[0]", 0x10: "RemoteDebugConfig[1]", 0x1E0: "SceneOffset",
             0x288: "WebSocketURLString", 0x2EC: "RemoteDebugMode", 0x44D: "scene=1101"}
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    disp_hits = {}   # disp -> list of (func, insn_va, text)
    def scan_func(fs, fe):
        body = bytes(img[fs:min(fe, fs + 0x6000)])
        for insn in md.disasm(body, IMAGE_BASE + fs):
            # 仅统计 "+ disp]" 正偏移 (结构体字段访问), 排除 "[rsp-0x10]" 类栈噪音
            # capstone 对小偏移输出十进制([rdi + 8]), 大偏移输出十六进制([rax + 0x608]), 两种都要接住
            for m in re.findall(r"\+ (0x[0-9a-f]+|\d+)\]", insn.op_str):
                v = int(m, 0)
                if v in MAGIC:
                    disp_hits.setdefault(v, []).append((fs, hex(insn.address), f"{insn.mnemonic} {insn.op_str}"))

    hook_funcs = []
    for field in ("LoadStartHookOffset", "CDPFilterHookOffset", "CastToJsonHookOffset"):
        if field in result:
            fs, fe = func_bounds(int(result[field], 16))
            scan_func(fs, fe)
            hook_funcs.append((field, fs, fe))
    # LoadStart 直接 callees
    if "LoadStartHookOffset" in result:
        fs, fe = func_bounds(int(result["LoadStartHookOffset"], 16))
        body = bytes(img[fs:fe])
        for insn in md.disasm(body, IMAGE_BASE + fs):
            if insn.mnemonic == "call" and insn.op_str.startswith("0x"):
                t = int(insn.op_str, 16) - IMAGE_BASE
                cfs, cfe = func_bounds(t)
                if cfs and 8 < cfe - cfs <= 0x8000:
                    scan_func(cfs, cfe)

    for v, lst in sorted(disp_hits.items()):
        log(f"    disp {hex(v)} ({MAGIC[v]}): {len(lst)} hits, e.g. {lst[0][1]} {lst[0][2]}")

    # 从证据推导结构体偏移(仅记录命中项)
    def has(v):
        return v in disp_hits
    struct_offsets = {}
    if has(0x40) and has(0x650) and has(0x8):
        struct_offsets["LaunchConfigOffsets"] = [64, 1616, 8]
    if has(0x608) and has(0x10):
        struct_offsets["RemoteDebugConfigOffsets"] = [1544, 16]
    if has(0x1E0):
        struct_offsets["SceneOffset"] = 480
    if has(0x288):
        struct_offsets["WebSocketURLStringOffset"] = 648
    if has(0x2EC):
        struct_offsets["RemoteDebugModeOffset"] = 748
    if struct_offsets:
        result["MiniAppConfigStructOffsets"] = struct_offsets

    # ---------- 5) 写出 JSON ----------
    with open(out_path, "w", encoding="utf-8") as w:
        json.dump(result, w, indent=2)
    log(f"\n[+] 已写出 {out_path}")
    log(json.dumps(result, indent=2))

    # 证据文件
    ev_path = out_path.replace(".json", ".evidence.txt")
    with open(ev_path, "w", encoding="utf-8") as w:
        w.write(f"DLL: {dll_path}\nImageBase: {hex(IMAGE_BASE)}\n\n")
        for field, fs, fe in hook_funcs:
            w.write(f"{field}: func {hex(fs)}..{hex(fe)}\n")
        w.write("\nMagic disp hits:\n")
        for v, lst in sorted(disp_hits.items()):
            w.write(f"  {hex(v)} ({MAGIC[v]}):\n")
            for fs, va, s in lst[:6]:
                w.write(f"    func {hex(fs)} @ {va}: {s}\n")
    log(f"[+] 证据: {ev_path}")
    try:
        mm.close()
    except Exception:
        pass
    f.close()
    return result

if __name__ == "__main__":
    dll = sys.argv[1] if len(sys.argv) > 1 else \
        os.path.expandvars(r"%APPDATA%\Tencent\xwechat\xplugin\Plugins\RadiumWMPF\26134\extracted\runtime\flue.dll")
    ver = sys.argv[2] if len(sys.argv) > 2 else None
    main(dll, ver)
