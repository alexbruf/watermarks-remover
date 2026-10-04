#!/usr/bin/env python3
"""Regenerate the V14_UNASSIGNED range table in src/unidata14.rs.

Python's unicodedata is pinned per Python build (3.11 -> Unicode 14.0) while the
Rust crates track newer Unicode. The Python module's decisions (and labels) treat
anything assigned after 14.0 as unassigned (Cn / "UNKNOWN"). This script takes a
TSV dump of the Rust side (`cargo run --example dump_ucd`: cp<TAB>cat<TAB>name)
and emits the ranges where the two disagree, so Rust can mimic Python's view.

Usage: cargo run -q --example dump_ucd > rust_ucd.tsv
       python3 tests/gen_unidata14.py rust_ucd.tsv > table.rs.txt
"""
import sys
import unicodedata

cps = []
for line in open(sys.argv[1], encoding="utf-8"):
    cp, cat, name = line.rstrip("\n").split("\t", 2)
    cp = int(cp, 16)
    if 0xD800 <= cp <= 0xDFFF:
        continue
    c = chr(cp)
    if unicodedata.category(c) == "Cn" and (cat != "Cn" or name != "UNKNOWN"):
        cps.append(cp)
ranges = []
for cp in cps:
    if ranges and ranges[-1][1] == cp - 1:
        ranges[-1][1] = cp
    else:
        ranges.append([cp, cp])
print("const V14_UNASSIGNED: &[(u32, u32)] = &[")
for a, b in ranges:
    print(f"    (0x{a:X}, 0x{b:X}),")
print("];")
