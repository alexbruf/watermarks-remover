//! Layer A: invisible Unicode / homoglyph space detection and cleaning.
//!
//! Faithful port of `service/scripts/text_unicode.py`. Pure functions over
//! `&str`, no I/O, suitable for `wasm32-unknown-unknown`.
//!
//! Offsets and lengths are counted in Unicode scalar values (Python code
//! points). Python strings may hold lone surrogates; Rust `&str` cannot, so
//! that case is out of scope.

use serde::ser::{SerializeMap, SerializeStruct};
use serde::{Serialize, Serializer};
use std::collections::HashMap;
use unicode_general_category::GeneralCategory as Gc;

mod unidata14;

// ---------------------------------------------------------------------------
// Code point tables
// ---------------------------------------------------------------------------

/// Spaces that look like (or substitute for) U+0020.
fn is_space_homoglyph(cp: u32) -> bool {
    matches!(
        cp,
        0x00A0 | 0x1680 | 0x2000..=0x200A | 0x202F | 0x205F | 0x3000
    )
}

/// Optional confusable Latin lookalikes (aggressive mode only).
fn latin_confusable(cp: u32) -> Option<char> {
    Some(match cp {
        0x0410 => 'A',
        0x0412 => 'B',
        0x0415 => 'E',
        0x041A => 'K',
        0x041C => 'M',
        0x041D => 'H',
        0x041E => 'O',
        0x0420 => 'P',
        0x0421 => 'C',
        0x0422 => 'T',
        0x0425 => 'X',
        0x0430 => 'a',
        0x0435 => 'e',
        0x043E => 'o',
        0x0440 => 'p',
        0x0441 => 'c',
        0x0443 => 'y',
        0x0445 => 'x',
        0x0456 => 'i',
        0xFF21..=0xFF3A => (b'A' + (cp - 0xFF21) as u8) as char,
        0xFF41..=0xFF5A => (b'a' + (cp - 0xFF41) as u8) as char,
        _ => return None,
    })
}

/// Explicit strip set (`STRIP_CODEPOINTS`).
fn in_strip_codepoints(cp: u32) -> bool {
    matches!(
        cp,
        0x00AD
            | 0x034F
            | 0x061C
            | 0x115F
            | 0x1160
            | 0x17B4
            | 0x17B5
            | 0x180B..=0x180F
            | 0x200B..=0x200F
            | 0x202A..=0x202E
            | 0x2060..=0x2064
            | 0x2066..=0x206F
            | 0xFEFF
            | 0xFE00..=0xFE0F
            | 0x3164
            | 0xFFA0
            | 0xFFF9..=0xFFFB
    )
}

/// VS17-VS256 (`_VS_SUPPLEMENT`).
fn is_vs_supplement(cp: u32) -> bool {
    (0xE0100..0xE01F0).contains(&cp)
}

fn is_reserved_ignorable(cp: u32) -> bool {
    matches!(cp, 0x2065 | 0xE0000)
        || (0xFFF0..0xFFF9).contains(&cp)
        || (0xE0080..0xE0100).contains(&cp)
        || (0xE01F0..0xE1000).contains(&cp)
}

/// The 66 Unicode noncharacters.
fn is_noncharacter(cp: u32) -> bool {
    (0xFDD0..=0xFDEF).contains(&cp) || (cp & 0xFFFE) == 0xFFFE
}

fn is_bidi_cp(cp: u32) -> bool {
    matches!(cp, 0x061C | 0x200E | 0x200F | 0x202A..=0x202E | 0x2066..=0x2069)
}

fn is_preservable_bidi(cp: u32) -> bool {
    matches!(cp, 0x061C | 0x200E | 0x200F | 0x2066..=0x2069)
}

/// Layout format controls: (controls, script context). Half-open ranges.
const LAYOUT_CF_CONTROLS: [((u32, u32), (u32, u32)); 3] = [
    ((0x13430, 0x13440), (0x13000, 0x14400)),
    ((0x1BCA0, 0x1BCA4), (0x1BC00, 0x1BCA4)),
    ((0x1D173, 0x1D17B), (0x1D100, 0x1D200)),
];

fn layout_cf_script(cp: u32) -> Option<(u32, u32)> {
    LAYOUT_CF_CONTROLS
        .iter()
        .find(|((a, b), _)| (*a..*b).contains(&cp))
        .map(|(_, s)| *s)
}

fn is_zw_family(cp: u32) -> bool {
    matches!(cp, 0x200B | 0x200C | 0x200D | 0x2060 | 0xFEFF | 0x180E)
}

fn is_private_use(cp: u32) -> bool {
    (0xE000..=0xF8FF).contains(&cp)
        || (0xF0000..=0xFFFFD).contains(&cp)
        || (0x100000..=0x10FFFD).contains(&cp)
}

fn is_strip_cp(cp: u32) -> bool {
    in_strip_codepoints(cp)
        || is_vs_supplement(cp)
        || (0xE0001..=0xE007F).contains(&cp)
        || is_noncharacter(cp)
        || is_reserved_ignorable(cp)
        || is_private_use(cp)
}

fn is_mongolian_fvs(cp: u32) -> bool {
    matches!(cp, 0x180B | 0x180C | 0x180D | 0x180F)
}

fn strip_kind(cp: u32) -> &'static str {
    if (0xE0001..=0xE007F).contains(&cp) {
        return "tag_chars";
    }
    if is_noncharacter(cp) {
        return "noncharacter";
    }
    if is_reserved_ignorable(cp) {
        return "reserved_ignorable";
    }
    if is_vs_supplement(cp) || (0xFE00..=0xFE0F).contains(&cp) || is_mongolian_fvs(cp) {
        return "variation_selector";
    }
    if is_bidi_cp(cp) {
        return "bidi";
    }
    if is_zw_family(cp) {
        return "zwj_family";
    }
    if is_private_use(cp) {
        return "private_use";
    }
    "strip"
}

fn is_emoji_glue(cp: u32) -> bool {
    matches!(cp, 0x200D | 0xFE0E | 0xFE0F)
}

fn is_emoji_base(cp: u32) -> bool {
    (0x1F000..=0x1FAFF).contains(&cp)
        || (0x2190..=0x25FF).contains(&cp)
        || (0x2600..=0x27BF).contains(&cp)
        || (0x2B00..=0x2BFF).contains(&cp)
        || matches!(cp, 0x203C | 0x2049 | 0x2139 | 0x2934 | 0x2935)
        || matches!(cp, 0x00A9 | 0x00AE | 0x2122 | 0x3030 | 0x303D | 0x3297 | 0x3299)
        || matches!(cp, 0x0023 | 0x002A)
        || (0x0030..=0x0039).contains(&cp)
}

fn is_script_joiner(cp: u32) -> bool {
    matches!(cp, 0x200C | 0x200D)
}

fn is_tag_range(cp: u32) -> bool {
    (0xE0020..0xE0080).contains(&cp)
}

fn is_orthographic_cf(cp: u32) -> bool {
    matches!(
        cp,
        0x0600..=0x0605 | 0x06DD | 0x070F | 0x08E2 | 0x110BD | 0x110CD
    )
}

fn is_khmer_vowel(cp: u32) -> bool {
    matches!(cp, 0x17B4 | 0x17B5)
}

fn is_hangul_filler(cp: u32) -> bool {
    matches!(cp, 0x115F | 0x1160 | 0x3164 | 0xFFA0)
}

fn is_script_glue(cp: u32) -> bool {
    is_mongolian_fvs(cp) || is_khmer_vowel(cp) || is_hangul_filler(cp)
}

fn category_of(cp: u32) -> Gc {
    unidata14::category(cp)
}

fn is_letter_or_mark(cp: u32) -> bool {
    use Gc::*;
    matches!(
        category_of(cp),
        UppercaseLetter
            | LowercaseLetter
            | TitlecaseLetter
            | ModifierLetter
            | OtherLetter
            | NonspacingMark
            | SpacingMark
            | EnclosingMark
    )
}

fn is_letter(cp: u32) -> bool {
    use Gc::*;
    matches!(
        category_of(cp),
        UppercaseLetter | LowercaseLetter | TitlecaseLetter | ModifierLetter | OtherLetter
    )
}

/// Broad script group where ZWJ/ZWNJ can be orthographic.
fn joining_script(cp: u32) -> Option<u8> {
    let group = match cp {
        0x0600..=0x08FF => 1,
        0x0900..=0x0DFF => 2,
        0x0F00..=0x109F => 3,
        0x1780..=0x17FF => 4,
        0x1800..=0x18AF => 5,
        _ => return None,
    };
    if is_letter_or_mark(cp) {
        Some(group)
    } else {
        None
    }
}

fn is_cjk_ideograph(cp: u32) -> bool {
    (0x3400..=0x4DBF).contains(&cp)
        || (0x4E00..=0x9FFF).contains(&cp)
        || (0xF900..=0xFAFF).contains(&cp)
        || (0x20000..=0x323AF).contains(&cp)
}

fn is_mongolian_base(cp: u32) -> bool {
    (0x1800..=0x18AF).contains(&cp)
}

fn is_variation_selector(cp: u32) -> bool {
    is_vs_supplement(cp) || (0xFE00..=0xFE0F).contains(&cp) || is_mongolian_fvs(cp)
}

fn is_mongolian_letter(cp: u32) -> bool {
    (0x1800..=0x18AF).contains(&cp) && is_letter(cp)
}

fn is_khmer_letter(cp: u32) -> bool {
    (0x1780..=0x17FF).contains(&cp) && is_letter(cp)
}

fn is_hangul_jamo(cp: u32) -> bool {
    (0x1100..=0x11FF).contains(&cp)
        || (0xA960..=0xA97C).contains(&cp)
        || (0xD7B0..=0xD7C6).contains(&cp)
        || (0x3131..=0x318E).contains(&cp)
        || (0xFFA1..=0xFFDC).contains(&cp)
}

fn is_glue(cp: u32) -> bool {
    is_emoji_glue(cp)
        || is_variation_selector(cp)
        || is_script_joiner(cp)
        || is_tag_range(cp)
        || is_script_glue(cp)
}

/// Indices in complete subdivision-flag tag sequences.
fn valid_flag_tag_indices(chars: &[char]) -> Vec<bool> {
    let mut valid = vec![false; chars.len()];
    let mut i = 0;
    while i < chars.len() {
        if chars[i] as u32 != 0x1F3F4 {
            i += 1;
            continue;
        }
        let mut j = i + 1;
        while j < chars.len() && (0xE0020..=0xE007E).contains(&(chars[j] as u32)) {
            j += 1;
        }
        if j > i + 1 && j < chars.len() && chars[j] as u32 == 0xE007F {
            for v in valid.iter_mut().take(j + 1).skip(i + 1) {
                *v = true;
            }
            i = j + 1;
        } else {
            i += 1;
        }
    }
    valid
}

/// Indices belonging to complete LRE/RLE ... PDF pairs, excluding overrides.
fn valid_bidi_embedding_indices(chars: &[char]) -> Vec<bool> {
    let mut valid = vec![false; chars.len()];
    let mut stack: Vec<(u32, usize)> = Vec::new();
    for (index, ch) in chars.iter().enumerate() {
        let cp = *ch as u32;
        if matches!(cp, 0x202A | 0x202B | 0x202D | 0x202E) {
            stack.push((cp, index));
        } else if cp == 0x202C {
            if let Some((opener, opener_index)) = stack.pop() {
                if opener == 0x202A || opener == 0x202B {
                    valid[opener_index] = true;
                    valid[index] = true;
                }
            }
        }
    }
    valid
}

// ---------------------------------------------------------------------------
// Per-character decision
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Action {
    Keep,
    Strip,
    Replace,
}

struct DecideFlags {
    valid_flag_tag: bool,
    valid_bidi_embedding: bool,
    normalize_spaces: bool,
    treat_confusables: bool,
    strip_emoji_glue: bool,
    strip_bidi: bool,
}

/// Returns `(action, out_char, kind)`; `out_char` is meaningful for keep/replace.
fn decide(
    ch: char,
    prev_kept: Option<char>,
    prev_input: Option<char>,
    next_input: Option<char>,
    f: &DecideFlags,
) -> (Action, char, Option<&'static str>) {
    let cp = ch as u32;
    let keep = (Action::Keep, ch, None);
    if f.valid_bidi_embedding && !f.strip_bidi {
        return keep;
    }
    if is_preservable_bidi(cp) && !f.strip_bidi {
        return keep;
    }
    if let Some(p) = prev_input {
        if !f.strip_emoji_glue {
            let prev_cp = p as u32;
            if is_vs_supplement(cp) && is_cjk_ideograph(prev_cp) {
                return keep;
            }
            if is_mongolian_fvs(cp) && is_mongolian_base(prev_cp) {
                return keep;
            }
            if (0xFE00..=0xFE0D).contains(&cp) && is_cjk_ideograph(prev_cp) {
                return keep;
            }
        }
    }
    if is_emoji_glue(cp) && !f.strip_emoji_glue {
        if (cp == 0xFE0E || cp == 0xFE0F) && prev_input.is_some_and(|p| is_emoji_base(p as u32)) {
            return keep;
        }
        if cp == 0x200D {
            if let (Some(pk), Some(ni)) = (prev_kept, next_input) {
                if is_emoji_base(pk as u32) && is_emoji_base(ni as u32) {
                    return keep;
                }
            }
        }
    }
    if !f.strip_emoji_glue {
        if is_script_joiner(cp) {
            if let (Some(p), Some(n)) = (prev_input, next_input) {
                let ps = joining_script(p as u32);
                let ns = joining_script(n as u32);
                if ps.is_some() && ps == ns {
                    return keep;
                }
            }
        }
        if is_tag_range(cp) && f.valid_flag_tag {
            return keep;
        }
        if is_mongolian_fvs(cp) && prev_kept.is_some_and(|p| is_mongolian_letter(p as u32)) {
            return keep;
        }
        if is_khmer_vowel(cp) && prev_kept.is_some_and(|p| is_khmer_letter(p as u32)) {
            return keep;
        }
        if is_hangul_filler(cp) && prev_kept.is_some_and(|p| is_hangul_jamo(p as u32)) {
            return keep;
        }
        if is_orthographic_cf(cp) {
            return keep;
        }
        if let Some((lo, hi)) = layout_cf_script(cp) {
            let inside = |c: Option<char>| c.is_some_and(|c| (lo..hi).contains(&(c as u32)));
            if inside(prev_input) || inside(next_input) {
                return keep;
            }
        }
    }
    if is_strip_cp(cp) {
        return (Action::Strip, '\0', Some(strip_kind(cp)));
    }
    if f.normalize_spaces && is_space_homoglyph(cp) {
        return (Action::Replace, ' ', Some("space"));
    }
    if f.treat_confusables {
        if let Some(c) = latin_confusable(cp) {
            return (Action::Replace, c, Some("confusable"));
        }
    }
    if category_of(cp) == Gc::Format && !is_space_homoglyph(cp) {
        return (Action::Strip, '\0', Some("other_cf"));
    }
    keep
}

fn char_label(ch: char) -> String {
    let cp = ch as u32;
    let name = unidata14::name(ch);
    format!("U+{:04X} {} ({})", cp, name, unidata14::category_abbr(category_of(cp)))
}

fn hit_confidence(kind: &str) -> &'static str {
    if kind == "space" {
        "informational"
    } else {
        "probable"
    }
}

// ---------------------------------------------------------------------------
// Insertion-ordered counter (serialises as a JSON object like Python's dict)
// ---------------------------------------------------------------------------

/// Insertion-ordered `label -> count` map; serialises as a JSON object.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Counts(pub Vec<(String, usize)>);

impl Counts {
    fn add(&mut self, key: String, n: usize) {
        if let Some(e) = self.0.iter_mut().find(|(k, _)| *k == key) {
            e.1 += n;
        } else {
            self.0.push((key, n));
        }
    }
    pub fn get(&self, key: &str) -> Option<usize> {
        self.0.iter().find(|(k, _)| k == key).map(|(_, v)| *v)
    }
    pub fn total(&self) -> usize {
        self.0.iter().map(|(_, v)| *v).sum()
    }
    pub fn len(&self) -> usize {
        self.0.len()
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Serialize for Counts {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut m = s.serialize_map(Some(self.0.len()))?;
        for (k, v) in &self.0 {
            m.serialize_entry(k, v)?;
        }
        m.end()
    }
}

// ---------------------------------------------------------------------------
// Inspect
// ---------------------------------------------------------------------------

/// Options for [`inspect_text`] (Python keyword arguments).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct InspectOptions {
    /// Also flag Latin confusable / fullwidth lookalikes.
    pub aggressive: bool,
    /// Paranoid: flag all load-bearing invisibles too.
    pub strip_emoji_glue: bool,
}

/// One bucket of suspicious characters (`CharHit`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CharHit {
    pub codepoint: u32,
    pub ch: char,
    pub label: String,
    pub count: usize,
    pub kind: &'static str,
    /// Character offsets (first 10 only are serialised; this holds up to 10).
    pub samples: Vec<usize>,
}

impl CharHit {
    pub fn confidence(&self) -> &'static str {
        hit_confidence(self.kind)
    }
}

impl Serialize for CharHit {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut st = s.serialize_struct("CharHit", 6)?;
        st.serialize_field("codepoint", &format!("U+{:04X}", self.codepoint))?;
        st.serialize_field("label", &self.label)?;
        st.serialize_field("count", &self.count)?;
        st.serialize_field("kind", self.kind)?;
        st.serialize_field("confidence", self.confidence())?;
        let n = self.samples.len().min(10);
        st.serialize_field("sample_offsets", &self.samples[..n])?;
        st.end()
    }
}

/// Inspect report; serialises exactly like Python's `TextInspectReport.to_dict()`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TextInspectReport {
    pub length: usize,
    pub suspicious_total: usize,
    pub hits: Vec<CharHit>,
    pub notes: Vec<String>,
}

const NOTE_LAYER_A: &str =
    "Layer A only: invisible/format Unicode and space homoglyphs (edit-based carriers).";
const NOTE_STATISTICAL: &str =
    "Statistical (token-sampling) watermarks are not detectable here; use Layer B rewrite.";
const NOTE_KINDS: &str = "Inspect kinds: strip, bidi, tag_chars, variation_selector, zwj_family, private_use, space, confusable, other_cf.";
const NOTE_PRESERVED: &str = "Load-bearing invisibles are preserved by default during cleaning: emoji glue, CJK/Mongolian variation selectors, script joiners, complete flag tag sequences, same-script fillers/selectors (Mongolian FVS, Khmer inherent vowels, Hangul jamo fillers), RTL directional marks/paired embeddings, orthographic Arabic/Syriac Cf marks, and visible-layout format controls next to their own script (Egyptian hieroglyph quadrat, Duployan shorthand, musical beaming). Inspection still reports bidi controls. Use explicit strip flags only after review.";
const NOTE_NO_HITS: &str = "No deterministic Layer A (invisible Unicode/format) carriers detected; statistical and pixel-domain marks are out of scope here.";

/// Inspect `text` for invisible Unicode / space homoglyphs (Layer A).
pub fn inspect_text(text: &str, opts: &InspectOptions) -> TextInspectReport {
    let chars: Vec<char> = text.chars().collect();
    let valid_flag = valid_flag_tag_indices(&chars);
    let valid_bidi = valid_bidi_embedding_indices(&chars);
    // (cp, kind) -> offsets, in first-seen order.
    let mut buckets: Vec<((u32, &'static str), Vec<usize>)> = Vec::new();
    let mut index: HashMap<(u32, &'static str), usize> = HashMap::new();
    let mut prev_kept: Option<char> = None;
    for (i, &ch) in chars.iter().enumerate() {
        let flags = DecideFlags {
            valid_flag_tag: valid_flag[i],
            valid_bidi_embedding: valid_bidi[i],
            normalize_spaces: true,
            treat_confusables: opts.aggressive,
            strip_emoji_glue: opts.strip_emoji_glue,
            strip_bidi: true,
        };
        let (action, out_char, kind) = decide(
            ch,
            prev_kept,
            if i > 0 { Some(chars[i - 1]) } else { None },
            chars.get(i + 1).copied(),
            &flags,
        );
        let Some(kind) = kind else {
            if !is_glue(ch as u32) {
                prev_kept = Some(out_char);
            }
            continue;
        };
        let key = (ch as u32, kind);
        let slot = *index.entry(key).or_insert_with(|| {
            buckets.push((key, Vec::new()));
            buckets.len() - 1
        });
        buckets[slot].1.push(i);
        if action == Action::Replace {
            prev_kept = Some(out_char);
        }
    }

    buckets.sort_by(|a, b| {
        b.1.len()
            .cmp(&a.1.len())
            .then((a.0).0.cmp(&(b.0).0))
    });
    let mut hits = Vec::with_capacity(buckets.len());
    let mut total = 0;
    for ((cp, kind), offsets) in buckets {
        let ch = char::from_u32(cp).expect("valid scalar");
        total += offsets.len();
        hits.push(CharHit {
            codepoint: cp,
            ch,
            label: char_label(ch),
            count: offsets.len(),
            kind,
            samples: offsets.iter().copied().take(10).collect(),
        });
    }

    let mut notes: Vec<String> = [NOTE_LAYER_A, NOTE_STATISTICAL, NOTE_KINDS, NOTE_PRESERVED]
        .iter()
        .map(|s| s.to_string())
        .collect();
    if hits.is_empty() {
        notes.push(NOTE_NO_HITS.to_string());
    }
    TextInspectReport {
        length: chars.len(),
        suspicious_total: total,
        hits,
        notes,
    }
}

/// Plain-text rendering of a report (Python `human_report`).
pub fn human_report(report: &TextInspectReport) -> String {
    let mut lines = vec![
        format!("Length: {} chars", report.length),
        format!("Suspicious: {}", report.suspicious_total),
    ];
    if !report.hits.is_empty() {
        lines.push("Hits:".to_string());
        for h in &report.hits {
            let n = h.samples.len().min(5);
            let samples: Vec<String> = h.samples[..n].iter().map(|s| s.to_string()).collect();
            lines.push(format!(
                "  [{}/{}] {} x{} @ [{}]",
                h.kind,
                h.confidence(),
                h.label,
                h.count,
                samples.join(", ")
            ));
        }
    }
    for n in &report.notes {
        lines.push(format!("Note: {n}"));
    }
    lines.join("\n")
}

// ---------------------------------------------------------------------------
// Clean
// ---------------------------------------------------------------------------

/// Options for [`clean_text`]. `Default` matches the Python defaults.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CleanOptions {
    /// Apply Unicode NFKC after scrubbing (default false).
    pub nfkc: bool,
    /// Map Cyrillic/fullwidth Latin confusables to ASCII (default false).
    pub aggressive_homoglyphs: bool,
    /// Rewrite exotic spaces to U+0020 (default true).
    pub normalize_spaces: bool,
    /// Paranoid: strip load-bearing invisibles too (default false).
    pub strip_emoji_glue: bool,
    /// Also strip legitimate bidi marks/isolates/embeddings (default false).
    pub strip_bidi: bool,
}

impl Default for CleanOptions {
    fn default() -> Self {
        Self {
            nfkc: false,
            aggressive_homoglyphs: false,
            normalize_spaces: true,
            strip_emoji_glue: false,
            strip_bidi: false,
        }
    }
}

/// Stats dict returned by Python `clean_text`; same keys and order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CleanStats {
    pub input_length: usize,
    pub output_length: usize,
    pub removed: Counts,
    pub replaced: Counts,
    pub removed_count: usize,
    pub replaced_count: usize,
    pub nfkc_changed: bool,
}

/// Cleaned text plus stats.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CleanOutput {
    pub text: String,
    pub stats: CleanStats,
}

/// Number of characters of `a` not covered by `difflib.SequenceMatcher(None, a,
/// b, autojunk=False)` matching blocks (== sum of non-equal opcode spans of `a`).
fn sequence_matcher_changed_a(a: &[char], b: &[char]) -> usize {
    let mut b2j: HashMap<char, Vec<usize>> = HashMap::new();
    for (j, &c) in b.iter().enumerate() {
        b2j.entry(c).or_default().push(j);
    }
    let find_longest = |alo: usize, ahi: usize, blo: usize, bhi: usize| {
        let (mut besti, mut bestj, mut bestsize) = (alo, blo, 0usize);
        let mut j2len: HashMap<usize, usize> = HashMap::new();
        for (i, ac) in a.iter().enumerate().take(ahi).skip(alo) {
            let mut newj2len: HashMap<usize, usize> = HashMap::new();
            if let Some(js) = b2j.get(ac) {
                for &j in js {
                    if j < blo {
                        continue;
                    }
                    if j >= bhi {
                        break;
                    }
                    let k = if j > 0 { j2len.get(&(j - 1)).copied().unwrap_or(0) } else { 0 } + 1;
                    newj2len.insert(j, k);
                    if k > bestsize {
                        besti = i + 1 - k;
                        bestj = j + 1 - k;
                        bestsize = k;
                    }
                }
            }
            j2len = newj2len;
        }
        (besti, bestj, bestsize)
    };
    let mut matched = 0usize;
    let mut queue = vec![(0usize, a.len(), 0usize, b.len())];
    while let Some((alo, ahi, blo, bhi)) = queue.pop() {
        let (i, j, k) = find_longest(alo, ahi, blo, bhi);
        if k > 0 {
            matched += k;
            if alo < i && blo < j {
                queue.push((alo, i, blo, j));
            }
            if i + k < ahi && j + k < bhi {
                queue.push((i + k, ahi, j + k, bhi));
            }
        }
    }
    a.len() - matched
}

/// Clean `text`, returning the cleaned string and stats.
pub fn clean_text(text: &str, opts: &CleanOptions) -> CleanOutput {
    let chars: Vec<char> = text.chars().collect();
    let valid_flag = valid_flag_tag_indices(&chars);
    let valid_bidi = valid_bidi_embedding_indices(&chars);
    let mut removed = Counts::default();
    let mut replaced = Counts::default();
    let mut out = String::with_capacity(text.len());
    let mut prev_kept: Option<char> = None;

    for (i, &ch) in chars.iter().enumerate() {
        let flags = DecideFlags {
            valid_flag_tag: valid_flag[i],
            valid_bidi_embedding: valid_bidi[i],
            normalize_spaces: opts.normalize_spaces,
            treat_confusables: opts.aggressive_homoglyphs,
            strip_emoji_glue: opts.strip_emoji_glue,
            strip_bidi: opts.strip_bidi,
        };
        let (action, out_char, _kind) = decide(
            ch,
            prev_kept,
            if i > 0 { Some(chars[i - 1]) } else { None },
            chars.get(i + 1).copied(),
            &flags,
        );
        match action {
            Action::Keep => {
                out.push(out_char);
                if !is_glue(ch as u32) {
                    prev_kept = Some(out_char);
                }
            }
            Action::Replace => {
                out.push(out_char);
                replaced.add(char_label(ch), 1);
                prev_kept = Some(out_char);
            }
            Action::Strip => removed.add(char_label(ch), 1),
        }
    }

    let mut nfkc_changed = false;
    if opts.nfkc {
        use unicode_normalization::UnicodeNormalization;
        let normalized: String = out.nfkc().collect();
        if normalized != out {
            nfkc_changed = true;
            let before: Vec<char> = out.chars().collect();
            let after: Vec<char> = normalized.chars().collect();
            let changed = sequence_matcher_changed_a(&before, &after);
            replaced.add("NFKC_normalize".to_string(), if changed == 0 { 1 } else { changed });
            out = normalized;
        }
    }

    let stats = CleanStats {
        input_length: chars.len(),
        output_length: out.chars().count(),
        removed_count: removed.total(),
        replaced_count: replaced.total(),
        removed,
        replaced,
        nfkc_changed,
    };
    CleanOutput { text: out, stats }
}

#[doc(hidden)]
pub fn __ucd_probe(c: char) -> (&'static str, String) {
    (unidata14::category_abbr(unidata14::category(c as u32)), unidata14::name(c))
}
