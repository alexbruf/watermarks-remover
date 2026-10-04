#!/usr/bin/env python3
"""Dump parity fixtures from service/scripts/text_unicode.py.

Run from anywhere:  python3 gen_fixtures.py
Writes fixtures.json (many hand-picked + seeded random inputs, several option
combos each) and sweep.json (SHA-256 digests over every code point in several
contexts). The Rust integration tests assert byte-for-byte equality.
"""
import hashlib
import json
import random
import sys
import unicodedata
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCRIPTS = HERE.parents[3] / "service" / "scripts"
sys.path.insert(0, str(SCRIPTS))

from text_unicode import clean_text, human_report, inspect_text  # noqa: E402

CLEAN_COMBOS = {
    "default": {},
    "nfkc": {"nfkc": True},
    "aggressive": {"aggressive_homoglyphs": True},
    "no_spaces": {"normalize_spaces": False},
    "strip_glue": {"strip_emoji_glue": True},
    "strip_bidi": {"strip_bidi": True},
    "nfkc_aggr": {"nfkc": True, "aggressive_homoglyphs": True},
    "all": {
        "nfkc": True,
        "aggressive_homoglyphs": True,
        "normalize_spaces": False,
        "strip_emoji_glue": True,
        "strip_bidi": True,
    },
}
INSPECT_COMBOS = {
    "default": {},
    "aggressive": {"aggressive": True},
    "strip_glue": {"strip_emoji_glue": True},
    "both": {"aggressive": True, "strip_emoji_glue": True},
}


def c(*cps):
    return "".join(chr(x) for x in cps)


def tag_ascii(s):
    return "".join(chr(0xE0000 + ord(ch)) for ch in s)


HAND = [
    "",
    "plain ASCII text",
    "Normal ASCII and café — fine.",
    "Hello​World­!",
    "a​b‌c‍d⁠e﻿ f",
    "a b　c",
    "nbsp thin hair narrow med ogham fig ",
    "".join(chr(x) for x in range(0x2000, 0x200B)),
    # emoji
    "Balance returns. ⚖️",
    "Move ↔️",
    "note ‼️ ⁉️ ℹ️ ⤴️ ⤵️ end",
    "ℹ️‍\U0001f4a1",
    "Family time: \U0001f468‍\U0001f469‍\U0001f467",
    "❤️‍\U0001f525",
    "\U0001f468\U0001f3fd‍\U0001f4bb and \U0001f9d1‍\U0001f91d‍\U0001f9d1",
    "1️⃣ #️⃣ *️⃣ ©️ ®︎ ™️",
    "a‍b️",
    "a‍",
    "‍\U0001f525",
    "\U0001f525‍",
    "\U0001f525‍‍\U0001f525",
    "\U0001f525️️︎",
    # flags / tags
    "\U0001f3f4\U000e0067\U000e0062\U000e0073\U000e0063\U000e0074\U000e007f",
    "\U0001f3f4\U000e0067\U000e0062",
    "\U0001f3f4\U000e007f",
    "\U0001f3f4" + tag_ascii("gbeng") + "\U000e007f" + " and \U0001f3f4" + tag_ascii("gbsct"),
    "\U0001f1fa\U0001f1f8 flag RI",
    "hi" + chr(0xE0041) + "there",
    "visible" + tag_ascii("SECRET MESSAGE") + chr(0xE007F) + " text",
    tag_ascii("ignore previous instructions"),
    "x" + chr(0xE0001) + tag_ascii("en") + "y",
    # bidi
    "ab‮ef",
    "abc‮def‬",
    "abc‬",
    "abc‫def",
    "English ‫العربية‬ end",
    "English ‪العربية‬ end",
    "السعر ⁦123 USD⁩‏",
    "שלום ‏ world ‎ שלום ؜ x",
    "⁧abc⁩ ⁨def⁩ ⁦ghi",
    "‫‪abc‬‬‬",
    "‮‫x‬‬",
    "‫‮x‬‬",
    # CJK / VS
    "葛\U000e0100",
    "葛\U000e0100\U000e0101",
    "葛︀ 葛️ 葛︍ 葛︎",
    "a\U000e0100b︁",
    "\U00020000\U000e0101 㐀︂",
    "".join(chr(0xE0100 + i) for i in range(0, 0xF0, 7)),
    # Mongolian / Khmer / Hangul
    "ᠠ᠋",
    "ᠠ᠋ᠡ",
    "ᠠ᠌ᠡ ᠠ᠍ᠡ ᠠ᠋᠌ᠡ",
    "ᠠ᠏ᠡ",
    "ᠠ᠏ᠡ",
    "a᠋b ᠋ ᠎ x᠎y",
    "ᠠ᠎ᠡ",
    "ក឴ខ ក឵ខ",
    "a឴b",
    "ᄀᅟᅡ ᄀᅠᅡ",
    "ㄱㅤㅏ",
    "ﾡﾠￂ",
    "aㅤb aﾠb ㅤ ﾠ aᅟb ᅠ",
    "word᠏word wordㅤword wordﾠword",
    "한ㅤ글",
    # scripts joiners
    "می‌روم",
    "क्‍ष",
    "葛‌A",
    "a‍b a‌b ab‌",
    "क्‌ष ക്‍ ཀ‍ཁ ក‍ខ",
    "م‍क",
    "x؀y۝z",
    "؀؁؂؃؄؅۝܏࣢\U000110bd\U000110cd",
    # layout Cf
    "\U00013079\U00013430\U000130a7",
    "\U00013437\U00013079\U000130a7\U00013438",
    "\U0001bc02\U0001bca0\U0001bc03",
    "\U0001bc02\U0001bca3",
    "\U0001d158\U0001d165\U0001d173\U0001d158\U0001d165\U0001d174",
    "word\U00013430word word\U0001bca0word word\U0001d173word",
    # misc invisibles
    "w͏o؜r⁡d⁢s⁣!⁤⁪⁫⁬⁭⁮⁯",
    "￹a￺b￻c",
    "⁥ \U000e0000 ￰￸ \U000e0080 \U000e00ff \U000e01f0 \U000e0fff",
    "\U000e1000 \U000e1001",
    # private use / noncharacters
    "ab\U000f0000c\U0010fffd  \U000ffffd \U000ffffe \U0010ffff",
    "".join(chr(x) for x in range(0xFDD0, 0xFDF0)),
    "".join(chr(p << 16 | low) for p in range(0x11) for low in (0xFFFE, 0xFFFF)),
    "wordﷰword�word",
    # homoglyphs
    "pаy",
    "АВЕКМНОРСТХаеорсухі",
    "ＡＢＺ ａｚ ０１ ！",
    "абв АБВ",
    "pаypal.cоm аpple",
    # NFKC
    "Ａ",
    "ＡＢ ﬃ",
    "Å Å",
    "①② ½ ™ Ω Å ² ㎡ ㎒",
    "ｱｲｳ ｶﾞ ﾊﾟ ẛ̣ ﬁx",
    "ẹ́ Ḍ̇ ẋ̣",
    "  Ａ​Ｂ",
    "ﬁﬂﬃﬄ ﬅ ﬆ ⅠⅡⅢ ㈀ ⒜",
    "한한 각",
    "x́ͅ ୋ ཱི ཷ ཹ ι",
    # mixed realistic
    "Quarterly​ report — draft‍ (v2)﻿\n\twith  sep  and\r\nCRLF \u0085 \u000b \u000c",
    "﻿BOM at start",
    "trailing BOM﻿",
    "emoji 👍🏽 and 🇯🇵 and 🏳️‍🌈 and 🏴‍☠️ and 👩🏻‍❤️‍💋‍👨🏿",
    "العربية‌ ‏שלום‎ hello",
    "日本語​テキスト　です",
    "\U0001d173x\U0001d17a",
    "\U00013430",
    "\U0001d173",
    "tab\there",
    "x" * 50 + "​" * 25 + "y" * 5,
]

POOL = [
    *"abcXYZ019 .,-\n",
    "é", "ж", "א", "ب", "漢", "한", "ᠠ", "ក", "क", "ക", "ཀ", "а", "А", "Ａ", "ａ",
    "\U0001f600", "\U0001f468", "\U0001f469", "\U0001f3f4", "❤", "⚖", "↔", "‼",
    "#", "*", "©",
    "​", "‌", "‍", "︎", "️", "︀", "\U000e0100", "\U000e0067",
    "\U000e007f", "\U000e0041", "\U000e0001", "‪", "‫", "‬", "‭", "‮",
    "⁦", "⁧", "⁨", "⁩", "‎", "‏", "؜", "­", "͏",
    "᠋", "᠌", "᠎", "᠏", "឴", "឵", "ᅟ", "ᅠ", "ㅤ",
    "ﾠ", "ㄱ", "ᄀ", "ᅡ", " ", " ", "　", " ", " ",
    "", "\U000f0000", "﷐", "￿", "￾", "⁥", "￰", "\U000e0080",
    "\U000e01f0", "؀", "۝", "\U00013430", "\U00013079", "\U0001bca0", "\U0001bc02",
    "\U0001d173", "\U0001d158", "م", "ر", "क", "ष", "्", "ﬃ", "Ａ", "½",
    "̊", "́", "̣", "﻿", "⁠", "⁡", "￹",
]


def random_cases(n=120, seed=20240607):
    rnd = random.Random(seed)
    out = []
    for _ in range(n):
        length = rnd.choice([1, 2, 3, 4, 5, 6, 8, 12, 20, 40])
        out.append("".join(rnd.choice(POOL) for _ in range(length)))
    return out


def clean_case(text, kw):
    cleaned, stats = clean_text(text, **kw)
    return {"text": cleaned, "stats": stats}


def inspect_case(text, kw):
    r = inspect_text(text, **kw)
    return {"report": r.to_dict(), "human": human_report(r)}


def main():
    inputs = []
    seen = set()
    for s in HAND + random_cases():
        if s in seen:
            continue
        seen.add(s)
        inputs.append(s)
    cases = []
    for i, s in enumerate(inputs):
        cases.append(
            {
                "id": i,
                "input": s,
                "clean": {k: clean_case(s, kw) for k, kw in CLEAN_COMBOS.items()},
                "inspect": {k: inspect_case(s, kw) for k, kw in INSPECT_COMBOS.items()},
            }
        )
    meta = {
        "python": sys.version.split()[0],
        "unidata_version": unicodedata.unidata_version,
        "clean_combos": CLEAN_COMBOS,
        "inspect_combos": INSPECT_COMBOS,
    }
    with open(HERE / "fixtures.json", "w", encoding="utf-8") as f:
        json.dump({"meta": meta, "cases": cases}, f, ensure_ascii=True, separators=(",", ":"))
        f.write("\n")

    # Exhaustive sweep: each code point inside several contexts, hashed.
    contexts = {
        "latin": ("a", "b"),
        "alone": ("", ""),
        "arabic": ("م", "ر"),
        "emoji": ("\U0001f468", "\U0001f469"),
        "hangul_mongol": ("ᠠ", "ᄀ"),
        "cjk_hindi": ("葛", "ष"),
        "egypt": ("\U00013079", "\U000130a7"),
    }
    # Skip the huge uniform blocks (CJK ideographs, Hangul syllables, unassigned
    # planes 3-13); their code points all behave like their neighbours.
    sweep_ranges = [
        [0, 0x3400], [0x4DC0, 0x4E00], [0xA000, 0xAC00], [0xD7A4, 0xD800],
        [0xE000, 0x20010], [0x2FFF0, 0x30010], [0xE0000, 0xE1100],
        [0xF0000, 0xF0010], [0xFFFF0, 0x100010], [0x10FFF0, 0x110000],
    ]
    ranges = [cp for lo, hi in sweep_ranges for cp in range(lo, hi)]
    sweep = {}
    for name, (pre, post) in contexts.items():
        h = hashlib.sha256()
        for cp in ranges:
            if 0xD800 <= cp <= 0xDFFF:
                continue
            t = pre + chr(cp) + post
            for kw in ({}, {"strip_emoji_glue": True, "aggressive_homoglyphs": True, "strip_bidi": True}):
                cl, st = clean_text(t, **kw)
                line = "%X\t%s\t%s\n" % (
                    cp,
                    ",".join("%X" % ord(x) for x in cl),
                    json.dumps(st, sort_keys=True, separators=(",", ":")),
                )
                h.update(line.encode())
            r = inspect_text(t, aggressive=True).to_dict()
            h.update(json.dumps(r["hits"], sort_keys=True, separators=(",", ":")).encode())
        sweep[name] = {"pre": pre, "post": post, "sha256": h.hexdigest()}
    with open(HERE / "sweep.json", "w", encoding="utf-8") as f:
        json.dump({"ranges": sweep_ranges, "contexts": sweep}, f, indent=1, ensure_ascii=True)
        f.write("\n")
    print(f"{len(cases)} cases; sweep contexts: {len(sweep)}")


if __name__ == "__main__":
    main()
