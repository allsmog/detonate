#!/usr/bin/env python3
"""make_diagrams.py — generate the masterclass SVG diagrams.

Hand-rolled SVG (no deps) so the diagrams are reproducible and version-controlled.
Run from anywhere:  python3 make_diagrams.py
Writes *.svg next to this script. GitHub renders these inline in the READMEs.
"""
from __future__ import annotations

import pathlib

HERE = pathlib.Path(__file__).parent

FONT = "font-family='ui-sans-serif,system-ui,Segoe UI,Roboto,Helvetica,Arial'"
MONO = "font-family='ui-monospace,SFMono-Regular,Menlo,Consolas,monospace'"


def _box(x, y, w, h, fill, stroke, rx=8):
    return f"<rect x='{x}' y='{y}' width='{w}' height='{h}' rx='{rx}' fill='{fill}' stroke='{stroke}' stroke-width='1.5'/>"


def _esc(s: str) -> str:
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _text(x, y, s, size=14, fill="#0f172a", weight="400", anchor="start", font=FONT):
    return (f"<text x='{x}' y='{y}' font-size='{size}' fill='{fill}' "
            f"font-weight='{weight}' text-anchor='{anchor}' {font}>{_esc(s)}</text>")


def learning_path() -> str:
    levels = [
        ("1", "Foundations", "PE/ELF · asm · toolchain · triage", "#dbeafe", "#3b82f6"),
        ("2", "Static Analysis", "strings · imports · entropy · YARA", "#dcfce7", "#22c55e"),
        ("3", "Dynamic Analysis", "process tree · network/C2 · MITRE", "#fef9c3", "#eab308"),
        ("4", "Unpacking & Deobfuscation", "UPX · custom packers · obfuscation", "#ffedd5", "#f97316"),
        ("5", "Anti-Analysis", "VM/sandbox · anti-debug · evasion", "#fee2e2", "#ef4444"),
        ("6", "Config & IOC Extraction", "decrypt config · extractor · STIX", "#f3e8ff", "#a855f7"),
        ("7", "Capstone", "unknown sample · full kill chain · report", "#e0e7ff", "#6366f1"),
    ]
    W, rowh, pad = 860, 64, 14
    H = pad * 2 + len(levels) * (rowh + 12) + 60
    out = [f"<svg xmlns='http://www.w3.org/2000/svg' width='{W}' height='{H}' viewBox='0 0 {W} {H}'>"]
    out.append(f"<rect width='{W}' height='{H}' fill='#ffffff'/>")
    out.append(_text(pad, 34, "Detonate Masterclass — learning path", 20, "#0f172a", "700"))
    y = 58
    indent_step = 70
    for i, (num, title, sub, fill, stroke) in enumerate(levels):
        x = pad + i * indent_step
        w = W - x - pad
        out.append(_box(x, y, w, rowh, fill, stroke))
        out.append(f"<circle cx='{x+26}' cy='{y+rowh/2}' r='16' fill='{stroke}'/>")
        out.append(_text(x + 26, y + rowh / 2 + 5, num, 16, "#ffffff", "700", "middle"))
        out.append(_text(x + 52, y + 26, f"Level {num} — {title}", 15, "#0f172a", "600"))
        out.append(_text(x + 52, y + 46, sub, 12, "#475569"))
        y += rowh + 12
    out.append(_text(pad, y + 18, "Supplements: Windows/PE · Real-sample practice · CTF challenges (auto-graded)", 12, "#475569", "500"))
    out.append("</svg>")
    return "\n".join(out)


def kill_chain() -> str:
    steps = [
        ("Packed PE", "UPX · 0 sections", "#fee2e2", "#ef4444"),
        ("Unpack", "upx -d → 30 sections", "#ffedd5", "#f97316"),
        ("Anti-debug", "ptrace → force ret 0", "#fef9c3", "#eab308"),
        ("Deobfuscate", "XOR UA · stack strings", "#dcfce7", "#22c55e"),
        ("Config (RC4)", "CFG0 → C2 + bot id", "#dbeafe", "#3b82f6"),
        ("Report + IOCs", "STIX · MITRE · YARA", "#f3e8ff", "#a855f7"),
    ]
    bw, bh, gap, pad = 130, 70, 28, 18
    W = pad * 2 + len(steps) * bw + (len(steps) - 1) * gap
    H = 150
    out = [f"<svg xmlns='http://www.w3.org/2000/svg' width='{W}' height='{H}' viewBox='0 0 {W} {H}'>"]
    out.append(f"<rect width='{W}' height='{H}' fill='#ffffff'/>")
    out.append(_text(pad, 30, "Capstone kill chain — crackmalware", 18, "#0f172a", "700"))
    y = 56
    x = pad
    for i, (t, s, fill, stroke) in enumerate(steps):
        out.append(_box(x, y, bw, bh, fill, stroke))
        out.append(_text(x + bw / 2, y + 28, t, 13, "#0f172a", "600", "middle"))
        out.append(_text(x + bw / 2, y + 48, s, 10, "#475569", "400", "middle", MONO))
        if i < len(steps) - 1:
            ax = x + bw + 4
            out.append(f"<path d='M {ax} {y+bh/2} l {gap-8} 0' stroke='#94a3b8' stroke-width='2' marker-end='url(#arr)'/>")
        x += bw + gap
    out.insert(1, "<defs><marker id='arr' markerWidth='8' markerHeight='8' refX='6' refY='3' orient='auto'><path d='M0,0 L6,3 L0,6 Z' fill='#94a3b8'/></marker></defs>")
    out.append(_text(pad, H - 14, "Each stage is a level you trained: L4 → L5 → L4 → L6 → reporting.", 11, "#475569"))
    out.append("</svg>")
    return "\n".join(out)


def process_tree() -> str:
    W, H, pad = 560, 200, 18
    out = [f"<svg xmlns='http://www.w3.org/2000/svg' width='{W}' height='{H}' viewBox='0 0 {W} {H}'>"]
    out.append(f"<rect width='{W}' height='{H}' fill='#ffffff'/>")
    out.append(_text(pad, 30, "Process tree from strace (Module 3.2)", 16, "#0f172a", "700"))
    # parent
    out.append(_box(pad, 56, 230, 52, "#dbeafe", "#3b82f6"))
    out.append(_text(pad + 12, 78, "stage0 (pid 12425)", 13, "#0f172a", "600", "start", MONO))
    out.append(_text(pad + 12, 96, "execve /tmp/multistage", 11, "#475569", "400", "start", MONO))
    # edge
    out.append(f"<path d='M {pad+40} 108 L {pad+40} 140 L {pad+90} 140' stroke='#94a3b8' stroke-width='2' fill='none'/>")
    out.append(_text(pad + 46, 132, "clone()", 10, "#64748b", "400", "start", MONO))
    # child
    out.append(_box(pad + 90, 116, 300, 52, "#dcfce7", "#22c55e"))
    out.append(_text(pad + 102, 138, "child (pid 12426)", 13, "#0f172a", "600", "start", MONO))
    out.append(_text(pad + 102, 156, "execve /bin/echo  \"stage1-payload-executed\"", 11, "#475569", "400", "start", MONO))
    out.append("</svg>")
    return "\n".join(out)


def main() -> None:
    for name, fn in (("learning-path", learning_path), ("kill-chain", kill_chain), ("process-tree", process_tree)):
        (HERE / f"{name}.svg").write_text(fn())
        print(f"wrote {name}.svg")


if __name__ == "__main__":
    main()
