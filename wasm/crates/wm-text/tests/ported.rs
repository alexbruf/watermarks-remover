//! Port of `tests/test_clean_text.py` (and the text_unicode cases in
//! `tests/test_audit.py`).

use wm_text::{clean_text, inspect_text, CleanOptions, InspectOptions};

fn clean(s: &str) -> (String, wm_text::CleanStats) {
    let o = clean_text(s, &CleanOptions::default());
    (o.text, o.stats)
}
fn clean_with(s: &str, f: impl FnOnce(&mut CleanOptions)) -> (String, wm_text::CleanStats) {
    let mut o = CleanOptions::default();
    f(&mut o);
    let r = clean_text(s, &o);
    (r.text, r.stats)
}
fn inspect(s: &str) -> wm_text::TextInspectReport {
    inspect_text(s, &InspectOptions::default())
}
fn has_kind(r: &wm_text::TextInspectReport, k: &str) -> bool {
    r.hits.iter().any(|h| h.kind == k)
}
fn strip_glue(s: &str) -> String {
    clean_with(s, |o| o.strip_emoji_glue = true).0
}

#[test]
fn strips_zero_width_and_soft_hyphen() {
    let (c, st) = clean("Hello\u{200b}World\u{00ad}!");
    assert_eq!(c, "HelloWorld!");
    assert!(st.removed_count >= 2);
}

#[test]
fn normalizes_exotic_spaces() {
    let (c, st) = clean("a\u{2003}b\u{3000}c");
    assert_eq!(c, "a b c");
    assert!(st.replaced_count >= 2);
}

#[test]
fn inspect_finds_zwsp_and_audit_cases() {
    let r = inspect("x\u{200b}y");
    assert!(r.suspicious_total >= 1);
    assert!(has_kind(&r, "zwj_family") || has_kind(&r, "strip"));
    assert!(!inspect("a\u{200b}b").hits.is_empty());
    assert!(has_kind(&inspect("a\u{2003}b"), "space"));
}

#[test]
fn inspect_tag_chars() {
    let raw = "hi\u{E0041}there";
    let r = inspect(raw);
    assert!(r.suspicious_total >= 1 && has_kind(&r, "tag_chars"));
    let (c, st) = clean(raw);
    assert!(!c.contains('\u{E0041}'));
    assert!(st.removed_count >= 1);
}

#[test]
fn inspect_bidi() {
    let raw = "ab\u{202e}ef";
    assert!(has_kind(&inspect(raw), "bidi"));
    assert!(!clean(raw).0.contains('\u{202e}'));
}

#[test]
fn preserves_legitimate_bidi_marks_and_isolates_by_default() {
    let raw = "السعر \u{2066}123 USD\u{2069}\u{200f}";
    assert!(has_kind(&inspect(raw), "bidi"));
    assert_eq!(clean(raw).0, raw);
    assert_eq!(clean_with(raw, |o| o.strip_bidi = true).0, "السعر 123 USD");
}

#[test]
fn preserves_legacy_bidi_embeddings_by_default() {
    let raw = "English \u{202b}العربية\u{202c} end";
    assert_eq!(clean(raw).0, raw);
    assert_eq!(clean_with(raw, |o| o.strip_bidi = true).0, "English العربية end");
}

#[test]
fn strips_override_and_orphans() {
    let (c, st) = clean("abc\u{202e}def\u{202c}");
    assert_eq!(c, "abcdef");
    assert_eq!(st.removed_count, 2);
    assert_eq!(clean("abc\u{202c}").0, "abc");
    assert_eq!(clean("abc\u{202b}def").0, "abcdef");
}

#[test]
fn preserves_normal_text() {
    let raw = "Normal ASCII and café — fine.";
    let (c, st) = clean(raw);
    assert_eq!(c, raw);
    assert_eq!(st.removed_count, 0);
}

#[test]
fn aggressive_confusable() {
    let (c, _) = clean_with("p\u{0430}y", |o| o.aggressive_homoglyphs = true);
    assert_eq!(c, "pay");
    assert_eq!(clean("p\u{0430}y").0, "p\u{0430}y");
}

fn assert_untouched(raw: &str) {
    let (c, st) = clean(raw);
    assert_eq!(c, raw);
    assert_eq!(st.removed_count, 0);
}

#[test]
fn preserves_emoji_vs16_variants() {
    assert_untouched("Balance returns. \u{2696}\u{fe0f}");
    assert_untouched("Move \u{2194}\u{fe0f}");
    for base in ["\u{203c}", "\u{2049}", "\u{2139}", "\u{2934}", "\u{2935}"] {
        assert_untouched(&format!("note {base}\u{fe0f} end"));
    }
    let raw = "\u{2139}\u{fe0f}\u{200d}\u{1f4a1}";
    assert_eq!(clean(raw).0, raw);
    assert_eq!(inspect("\u{203c}\u{fe0f} \u{2049}\u{fe0f} \u{2139}\u{fe0f}").suspicious_total, 0);
}

#[test]
fn cjk_variation_selectors() {
    assert_untouched("\u{845b}\u{e0100}");
    let (c, st) = clean("\u{845b}\u{e0100}\u{e0101}");
    assert_eq!(c, "\u{845b}\u{e0100}");
    assert_eq!(st.removed_count, 1);
}

#[test]
fn mongolian_variation_selectors() {
    assert_untouched("\u{1820}\u{180b}");
    for raw in ["\u{1820}\u{180b}\u{1821}", "\u{1820}\u{180c}\u{1821}", "\u{1820}\u{180d}\u{1821}", "\u{1820}\u{180b}\u{180c}\u{1821}"] {
        assert_eq!(clean(raw).0, raw);
    }
    assert_untouched("ᠠ᠏ᠡ");
}

#[test]
fn zwj_sequences_and_floating_glue() {
    assert_untouched("Family time: \u{1f468}\u{200d}\u{1f469}\u{200d}\u{1f467}");
    assert_untouched("\u{2764}\u{fe0f}\u{200d}\u{1f525}");
    let (c, st) = clean("a\u{200d}b\u{fe0f}");
    assert_eq!(c, "ab");
    assert_eq!(st.removed_count, 2);
    let raw = "Balance returns. \u{2696}\u{fe0f} Family time: \u{1f468}\u{200d}\u{1f469}\u{200d}\u{1f467}";
    assert_eq!(inspect(raw).suspicious_total, 0);
    assert!(inspect("a\u{200d}").suspicious_total >= 1);
}

#[test]
fn strip_emoji_glue_flag() {
    let (c, st) = clean_with("\u{2696}\u{fe0f}", |o| o.strip_emoji_glue = true);
    assert_eq!(c, "\u{2696}");
    assert_eq!(st.removed_count, 1);
    let r = inspect_text("\u{2696}\u{fe0f}", &InspectOptions { strip_emoji_glue: true, ..Default::default() });
    assert!(r.suspicious_total >= 1);
}

#[test]
fn script_joiners_and_flags() {
    for raw in ["\u{645}\u{6cc}\u{200c}\u{631}\u{648}\u{645}", "\u{915}\u{94d}\u{200d}\u{937}"] {
        assert_eq!(clean(raw).0, raw);
    }
    let flag = "\u{1f3f4}\u{e0067}\u{e0062}\u{e0073}\u{e0063}\u{e0074}\u{e007f}";
    assert_eq!(clean(flag).0, flag);
    let (c, st) = clean("\u{1f3f4}\u{e0067}\u{e0062}");
    assert_eq!(c, "\u{1f3f4}");
    assert_eq!(st.removed_count, 2);
    let (c, st) = clean("\u{845b}\u{200c}A");
    assert_eq!(c, "\u{845b}A");
    assert_eq!(st.removed_count, 1);
    assert_eq!(clean("x\u{600}y\u{6dd}z").0, "x\u{600}y\u{6dd}z");
    for raw in ["a\u{200d}b", "a\u{200c}b", "ab\u{200c}"] {
        let c = clean(raw).0;
        assert!(!c.contains('\u{200c}') && !c.contains('\u{200d}'));
    }
    assert!(!strip_glue("\u{645}\u{6cc}\u{200c}\u{631}").contains('\u{200c}'));
    assert_eq!(strip_glue("x\u{600}y"), "xy");
}

#[test]
fn nfkc_counting() {
    let (c, st) = clean_with("Ａ", |o| o.nfkc = true);
    assert_eq!(c, "A");
    assert!(st.nfkc_changed);
    assert_eq!(st.replaced_count, 1);

    let (c, st) = clean_with("ＡＢ ﬃ", |o| o.nfkc = true);
    assert_eq!(c, "AB ffi");
    assert_eq!(st.replaced.get("NFKC_normalize"), Some(3));
    assert_eq!(st.replaced_count, 3);

    let (c, st) = clean_with("A\u{30a} A\u{30a}", |o| o.nfkc = true);
    assert_eq!(c, "\u{c5} \u{c5}");
    assert_eq!(st.replaced.get("NFKC_normalize"), Some(4));
}

#[test]
fn missed_default_ignorable_carriers() {
    for cp in [0x180Fu32, 0x3164, 0xFFA0] {
        let raw = format!("word{}word", char::from_u32(cp).unwrap());
        let (c, st) = clean(&raw);
        assert_eq!(c, "wordword");
        assert_eq!(st.removed_count, 1);
        assert!(inspect(&raw).suspicious_total >= 1);
    }
}

fn reserved_ignorable() -> Vec<u32> {
    let mut v = vec![0x2065, 0xE0000];
    v.extend(0xFFF0..0xFFF9);
    v.extend(0xE0080..0xE0100);
    v.extend(0xE01F0..0xE1000);
    v
}

#[test]
fn reserved_ignorables() {
    for cp in reserved_ignorable() {
        let raw = format!("word{}word", char::from_u32(cp).unwrap());
        let (c, st) = clean(&raw);
        assert_eq!(c, "wordword", "U+{cp:04X}");
        assert_eq!(st.removed_count, 1);
        assert!(has_kind(&inspect(&raw), "reserved_ignorable"), "U+{cp:04X}");
    }
    for cp in [0x2064u32, 0xFFF9, 0xE0001, 0xE0100] {
        let raw = format!("word{}word", char::from_u32(cp).unwrap());
        assert!(!has_kind(&inspect(&raw), "reserved_ignorable"), "U+{cp:04X}");
    }
}

#[test]
fn khmer_hangul_script_glue() {
    for raw in ["\u{1780}\u{17b4}\u{1781}", "\u{1780}\u{17b5}\u{1781}", "\u{1100}\u{115f}\u{1161}", "\u{1100}\u{1160}\u{1161}"] {
        assert_eq!(clean(raw).0, raw);
    }
    for raw in ["\u{3131}\u{3164}\u{314f}", "\u{ffa1}\u{ffa0}\u{ffc2}"] {
        assert_untouched(raw);
    }
    for raw in ["a\u{3164}b", "a\u{ffa0}b", "\u{3164}", "\u{ffa0}"] {
        let c = clean(raw).0;
        assert!(!c.contains('\u{3164}') && !c.contains('\u{ffa0}'));
    }
    assert_eq!(clean("a\u{180b}b").0, "ab");
    assert_eq!(clean("a\u{17b4}b").0, "ab");
    assert_eq!(clean("a\u{115f}b").0, "ab");
    assert_eq!(clean("\u{180b}").0, "");
    assert_eq!(clean("\u{1160}").0, "");
    for raw in ["\u{1820}\u{180b}\u{1821}", "\u{1780}\u{17b4}\u{1781}", "\u{1100}\u{115f}\u{1161}"] {
        let c = strip_glue(raw);
        assert!(!c.contains('\u{180b}') && !c.contains('\u{17b4}') && !c.contains('\u{115f}'));
    }
    assert_eq!(inspect("\u{1820}\u{180b}\u{1821}\u{1780}\u{17b4}\u{1781}\u{1100}\u{115f}\u{1161}").suspicious_total, 0);
    for raw in ["a\u{180b}", "a\u{17b4}", "a\u{115f}"] {
        assert!(inspect(raw).suspicious_total >= 1);
    }
}

#[test]
fn private_use() {
    let (c, st) = clean("a\u{e000}b\u{f0000}c\u{10fffd}");
    assert_eq!(c, "abc");
    assert!(st.removed_count >= 3);
    assert!(has_kind(&inspect("a\u{e000}b"), "private_use"));
}

fn noncharacters() -> Vec<u32> {
    let mut v: Vec<u32> = (0xFDD0..0xFDF0).collect();
    for p in 0..0x11u32 {
        v.push(p << 16 | 0xFFFE);
        v.push(p << 16 | 0xFFFF);
    }
    v
}

#[test]
fn noncharacters_handled() {
    let cps = noncharacters();
    assert_eq!(cps.len(), 66);
    for cp in cps {
        let raw = format!("word{}word", char::from_u32(cp).unwrap());
        let (c, st) = clean(&raw);
        assert_eq!(c, "wordword", "U+{cp:04X}");
        assert_eq!(st.removed_count, 1);
        assert!(has_kind(&inspect(&raw), "noncharacter"), "U+{cp:04X}");
    }
    for cp in [0xFDF0u32, 0xFFFD] {
        let raw = format!("word{}word", char::from_u32(cp).unwrap());
        assert_eq!(clean(&raw).0, raw);
        assert!(!has_kind(&inspect(&raw), "noncharacter"));
    }
}

#[test]
fn layout_format_controls() {
    for raw in [
        "\u{13079}\u{13430}\u{130a7}",
        "\u{13437}\u{13079}\u{130a7}\u{13438}",
        "\u{1bc02}\u{1bca0}\u{1bc03}",
        "\u{1bc02}\u{1bca3}",
        "\u{1d158}\u{1d165}\u{1d173}\u{1d158}\u{1d165}\u{1d174}",
    ] {
        assert_untouched(raw);
    }
    for cp in [0x13430u32, 0x13438, 0x1BCA0, 0x1BCA3, 0x1D173, 0x1D17A] {
        let raw = format!("word{}word", char::from_u32(cp).unwrap());
        let (c, st) = clean(&raw);
        assert_eq!(c, "wordword", "U+{cp:04X}");
        assert_eq!(st.removed_count, 1);
    }
    assert_eq!(inspect("\u{13079}\u{13430}\u{130a7}\u{1bc02}\u{1bca0}\u{1bc03}").suspicious_total, 0);
    for cp in [0x13430u32, 0x1BCA0, 0x1D173] {
        let raw = format!("a{}b", char::from_u32(cp).unwrap());
        assert!(inspect(&raw).suspicious_total >= 1);
    }
    assert!(!strip_glue("\u{13079}\u{13430}\u{130a7}").contains('\u{13430}'));
}

#[test]
fn default_options_match_python_defaults() {
    let o = CleanOptions::default();
    assert!(o.normalize_spaces && !o.nfkc && !o.aggressive_homoglyphs && !o.strip_emoji_glue && !o.strip_bidi);
}
