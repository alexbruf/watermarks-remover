//! LaTeX (`.tex` / `.ltx`) provenance handling: `\hypersetup` / `\pdfinfo`
//! metadata and tooling / provenance comment lines.

use crate::common::{FormatInspection, AI_META_NAME_RE};
use crate::pyutil::{char_at, py_isalnum, py_isspace, py_strip};
use crate::re;
use serde_json::json;

re!(C2PA, r"(?i)c2pa|content.?credential|contentcredential");
re!(META_CMD_OPEN, r"\\(hypersetup|pdfinfo)\b\s*\{");
re!(MAGIC_COMMENT, r"%\s*!\s*(?:TEX|TeX|BIB|LaTeX)\b");
re!(VIM_MODELINE, r"(?i)\bvim\s*:");
re!(VERBATIM_BEGIN, r"(?i)\\begin\{(verbatim\*?|lstlisting\*?|minted|Verbatim)\}");
re!(VERBATIM_END, r"(?i)\\end\{(verbatim\*?|lstlisting\*?|minted|Verbatim)\}");
re!(INLINE_VERBATIM, r"(?i)\\(verb\*?|lstinline\*?)(.)");

const CLEAR_HYPER_KEYS: [&str; 7] = [
    "pdfauthor",
    "pdfsubject",
    "pdfcreator",
    "pdfproducer",
    "pdfkeywords",
    "pdfcreationdate",
    "pdfmoddate",
];
const CLEAR_PDFINFO_KEYS: [&str; 7] =
    ["author", "subject", "keywords", "creator", "producer", "creationdate", "moddate"];

/// Index after `text[i]` (a backslash) and the one character it escapes
/// (Python `i += 2` over code points); capped at the text length.
fn skip_escape(text: &str, i: usize) -> usize {
    let n = text.len();
    if i + 1 >= n {
        return n;
    }
    match char_at(text, i + 1) {
        Some(c) => (i + 1 + c.len_utf8()).min(n),
        None => n,
    }
}

fn is_latex_escaped(text: &str, index: usize) -> bool {
    let b = text.as_bytes();
    let mut count = 0usize;
    let mut j = index;
    while j > 0 && b[j - 1] == b'\\' {
        count += 1;
        j -= 1;
    }
    count % 2 == 1
}

type Range = (usize, usize);

fn comment_ranges(text: &str) -> Vec<Range> {
    let b = text.as_bytes();
    let n = b.len();
    let mut ranges = Vec::new();
    let mut i = 0usize;
    while i < n {
        if b[i] == b'%' && !is_latex_escaped(text, i) {
            let start = i;
            let end = text[i..].find('\n').map_or(n, |j| i + j);
            ranges.push((start, end));
            i = end;
        } else {
            i += 1;
        }
    }
    ranges
}

fn verbatim_ranges(text: &str) -> Vec<Range> {
    let n = text.len();
    let b = text.as_bytes();
    let mut ranges = Vec::new();
    for m in VERBATIM_BEGIN.find_iter(text) {
        if let Some(e) = VERBATIM_END.find_at(text, m.end()) {
            ranges.push((m.start(), e.end()));
        }
    }
    for caps in INLINE_VERBATIM.captures_iter(text) {
        let whole = caps.get(0).expect("group 0");
        let g1 = caps.get(1).map_or("", |g| g.as_str());
        let g2 = caps.get(2).expect("group 2");
        let mut delim: char = g2.as_str().chars().next().unwrap_or(' ');
        let mut start = whole.end();
        if g1.starts_with("lstinline") && delim == '[' {
            let mut close: Option<usize> = None;
            let mut depth: i64 = 0;
            let mut j = whole.end();
            while j < n {
                let ch = b[j];
                if ch == b'\\' {
                    j = skip_escape(text, j);
                    continue;
                }
                if ch == b'{' {
                    depth += 1;
                } else if ch == b'}' {
                    depth -= 1;
                } else if ch == b']' && depth == 0 {
                    close = Some(j);
                    break;
                }
                j += 1;
            }
            let Some(close) = close else {
                continue;
            };
            if close + 1 >= n {
                continue;
            }
            delim = char_at(text, close + 1).unwrap_or(' ');
            start = close + 1 + delim.len_utf8();
        }
        if py_isspace(delim) || py_isalnum(delim) || matches!(delim, '\\' | '{' | '}') {
            continue;
        }
        let end = match text.get(start..).and_then(|t| t.find(delim)) {
            Some(k) => start + k + delim.len_utf8(),
            None => n,
        };
        ranges.push((whole.start(), end));
    }
    ranges
}

fn merge_ranges(mut ranges: Vec<Range>) -> Vec<Range> {
    ranges.sort_by_key(|r| r.0);
    let mut merged: Vec<Range> = Vec::new();
    for (start, end) in ranges {
        match merged.last_mut() {
            Some(last) if start <= last.1 => last.1 = last.1.max(end),
            _ => merged.push((start, end)),
        }
    }
    merged
}

/// `(offset, line, in_verbatim)` for each `\n`-split line.
fn lines_with_verbatim(text: &str) -> Vec<(&str, bool)> {
    let ranges = merge_ranges(verbatim_ranges(text));
    let mut out = Vec::new();
    let mut off = 0usize;
    for line in text.split('\n') {
        let idx = ranges.partition_point(|r| r.0 <= off);
        let in_vb = idx > 0 && off < ranges[idx - 1].1;
        out.push((line, in_vb));
        off += line.len() + 1;
    }
    out
}

fn matching_brace(text: &str, open_idx: usize) -> Option<usize> {
    let b = text.as_bytes();
    let n = b.len();
    let mut depth: i64 = 0;
    let mut i = open_idx;
    while i < n {
        let c = b[i];
        if c == b'\\' {
            i = skip_escape(text, i);
            continue;
        }
        if c == b'%' && !is_latex_escaped(text, i) {
            match text[i..].find('\n') {
                None => break,
                Some(j) => {
                    i += j + 1;
                    continue;
                }
            }
        }
        if c == b'{' {
            depth += 1;
        } else if c == b'}' {
            depth -= 1;
            if depth == 0 {
                return Some(i);
            }
        }
        i += 1;
    }
    None
}

fn split_items(s: &str) -> Vec<String> {
    let b = s.as_bytes();
    let n = b.len();
    let mut items = Vec::new();
    let mut depth: i64 = 0;
    let mut cur = String::new();
    let mut i = 0usize;
    while i < n {
        let c = b[i];
        if c == b'\\' {
            let end = skip_escape(s, i);
            cur.push_str(&s[i..end]);
            i = end;
            continue;
        }
        if c == b'%' && !is_latex_escaped(s, i) {
            i = s[i..].find('\n').map_or(n, |j| i + j + 1);
            continue;
        }
        if c == b'{' {
            depth += 1;
        } else if c == b'}' {
            depth -= 1;
        } else if c == b',' && depth == 0 {
            items.push(std::mem::take(&mut cur));
            i += 1;
            continue;
        }
        let ch = char_at(s, i).unwrap_or(' ');
        cur.push(ch);
        i += ch.len_utf8();
    }
    items.push(cur);
    items
}

fn split_key_value(item: &str) -> (String, Option<String>) {
    let b = item.as_bytes();
    let n = b.len();
    let mut depth: i64 = 0;
    let mut i = 0usize;
    while i < n {
        let c = b[i];
        if c == b'\\' {
            i = skip_escape(item, i);
            continue;
        }
        if c == b'{' {
            depth += 1;
        } else if c == b'}' {
            depth -= 1;
        } else if c == b'=' && depth == 0 {
            return (py_strip(&item[..i]).to_string(), Some(py_strip(&item[i + 1..]).to_string()));
        }
        i += 1;
    }
    (py_strip(item).to_string(), None)
}

struct PdfInfoItem<'a> {
    key: &'a str,
    value: &'a str,
}

fn pdfinfo_items(arg: &str) -> Vec<PdfInfoItem<'_>> {
    let b = arg.as_bytes();
    let n = b.len();
    let mut items = Vec::new();
    let mut i = 0usize;
    let skip_space = |mut i: usize| -> usize {
        while i < n {
            match char_at(arg, i) {
                Some(c) if py_isspace(c) => i += c.len_utf8(),
                _ => break,
            }
        }
        i
    };
    while i < n {
        i = skip_space(i);
        if i < n && b[i] == b'%' && !is_latex_escaped(arg, i) {
            i = arg[i..].find('\n').map_or(n, |j| i + j + 1);
            continue;
        }
        if i >= n || b[i] != b'/' {
            i += 1;
            continue;
        }
        let key_start = i;
        i += 1;
        while i < n {
            match char_at(arg, i) {
                Some(c) if !py_isspace(c) => i += c.len_utf8(),
                _ => break,
            }
        }
        let key = &arg[key_start..i];
        i = skip_space(i);
        let value_start = i;
        if i < n && b[i] == b'(' {
            let mut depth: i64 = 0;
            while i < n {
                if b[i] == b'\\' {
                    i = skip_escape(arg, i);
                    continue;
                }
                if b[i] == b'(' {
                    depth += 1;
                } else if b[i] == b')' {
                    depth -= 1;
                    if depth == 0 {
                        i += 1;
                        break;
                    }
                }
                i += 1;
            }
        } else if i < n && b[i] == b'<' {
            i += 1;
            while i < n && b[i] != b'>' {
                i += 1;
            }
            if i < n {
                i += 1;
            }
        } else {
            while i < n {
                match char_at(arg, i) {
                    Some(c) if !py_isspace(c) => i += c.len_utf8(),
                    _ => break,
                }
            }
        }
        let end = i.min(n);
        items.push(PdfInfoItem { key, value: &arg[value_start.min(end)..end] });
    }
    items
}

/// `(ai, c2pa, clear)` for one entry.
fn entry_class(key: &str, value: Option<&str>) -> (bool, bool, bool) {
    let lkey = key.to_lowercase();
    let lkey = lkey.trim_start_matches('/');
    let v = value.unwrap_or("");
    let ai = AI_META_NAME_RE.is_match(key) || AI_META_NAME_RE.is_match(v);
    let c2pa = C2PA.is_match(key) || C2PA.is_match(v);
    let clear = CLEAR_HYPER_KEYS.contains(&lkey) || CLEAR_PDFINFO_KEYS.contains(&lkey);
    (ai, c2pa, clear)
}

type Removed = Vec<(String, bool, bool)>;

fn clean_hypersetup(arg: &str) -> (Option<String>, Removed) {
    let mut kept: Vec<String> = Vec::new();
    let mut removed: Removed = Vec::new();
    for raw in split_items(arg) {
        let item = py_strip(&raw);
        if item.is_empty() {
            continue;
        }
        let (key, value) = split_key_value(item);
        let (ai, c2pa, clear) = entry_class(&key, value.as_deref());
        if ai || c2pa || clear {
            removed.push((key, ai, c2pa));
            continue;
        }
        kept.push(item.to_string());
    }
    if removed.is_empty() {
        return (Some(arg.to_string()), Vec::new());
    }
    if kept.is_empty() {
        return (None, removed);
    }
    (Some(kept.join(", ")), removed)
}

fn clean_pdfinfo(arg: &str) -> (Option<String>, Removed) {
    let mut kept: Vec<String> = Vec::new();
    let mut removed: Removed = Vec::new();
    for it in pdfinfo_items(arg) {
        let (ai, c2pa, clear) = entry_class(it.key, Some(it.value));
        if ai || c2pa || clear {
            removed.push((it.key.to_string(), ai, c2pa));
            continue;
        }
        kept.push(if it.value.is_empty() { it.key.to_string() } else { format!("{} {}", it.key, it.value) });
    }
    if removed.is_empty() {
        return (Some(arg.to_string()), Vec::new());
    }
    if kept.is_empty() {
        return (None, removed);
    }
    (Some(kept.join(" ")), removed)
}

/// `(drop, label, ai)` for a comment line (already left-stripped).
fn comment_class(line: &str) -> (bool, &'static str, bool) {
    if AI_META_NAME_RE.is_match(line) {
        return (true, "AI markers", true);
    }
    if MAGIC_COMMENT.is_match(line) {
        return (true, "magic comment", false);
    }
    if line.contains("-*-") {
        return (true, "editor modeline", false);
    }
    if VIM_MODELINE.is_match(line) {
        return (true, "editor modeline", false);
    }
    (false, "", false)
}

struct MetaCmd<'a> {
    cmd: String,
    arg: &'a str,
    start: usize,
    end: usize,
}

fn iter_meta_commands(text: &str) -> Vec<MetaCmd<'_>> {
    let mut ranges = comment_ranges(text);
    ranges.extend(verbatim_ranges(text));
    let ranges = merge_ranges(ranges);
    let mut out = Vec::new();
    for caps in META_CMD_OPEN.captures_iter(text) {
        let whole = caps.get(0).expect("group 0");
        let pos = whole.start();
        let idx = ranges.partition_point(|r| r.0 <= pos);
        if idx > 0 && pos < ranges[idx - 1].1 {
            continue;
        }
        let cmd = caps.get(1).map_or("", |g| g.as_str()).to_lowercase();
        let brace_idx = whole.end() - 1;
        let Some(close) = matching_brace(text, brace_idx) else {
            continue;
        };
        out.push(MetaCmd { cmd, arg: &text[brace_idx + 1..close], start: whole.start(), end: close + 1 });
    }
    out
}

fn meta_key_values<'a>(cmd: &str, arg: &'a str) -> Vec<(String, Option<String>)> {
    if cmd == "pdfinfo" {
        return pdfinfo_items(arg).into_iter().map(|i| (i.key.to_string(), Some(i.value.to_string()))).collect();
    }
    let mut pairs = Vec::new();
    for raw in split_items(arg) {
        let item = py_strip(&raw);
        if item.is_empty() {
            continue;
        }
        pairs.push(split_key_value(item));
    }
    pairs
}

fn lstrip_py(s: &str) -> &str {
    crate::pyutil::py_lstrip(s)
}

/// `inspect_latex(text)`.
pub fn inspect_latex(text: &str) -> FormatInspection {
    let mut findings: Vec<String> = Vec::new();
    let mut has_ai = false;
    let mut has_c2pa = false;
    let mut keys_dropped = 0usize;
    let mut comments_dropped = 0usize;
    let mut commands = 0usize;
    for mc in iter_meta_commands(text) {
        commands += 1;
        for (key, value) in meta_key_values(&mc.cmd, mc.arg) {
            let (ai, c2pa, clear) = entry_class(&key, value.as_deref());
            if !(ai || c2pa || clear) {
                continue;
            }
            keys_dropped += 1;
            let prefix = if ai || c2pa { "latex ai:" } else { "info: latex" };
            findings.push(format!("{prefix} {} {key}", mc.cmd));
            if c2pa {
                has_c2pa = true;
            }
            if ai || c2pa {
                has_ai = true;
            }
        }
    }
    for (line, in_verbatim) in lines_with_verbatim(text) {
        let stripped = lstrip_py(line);
        if in_verbatim || !stripped.starts_with('%') {
            continue;
        }
        let (drop, label, ai) = comment_class(stripped);
        if drop {
            comments_dropped += 1;
            let prefix = if ai { "latex ai:" } else { "info: latex" };
            findings.push(format!("{prefix} comment ({label})"));
            if ai {
                has_ai = true;
            }
        }
    }
    FormatInspection::new(
        has_c2pa,
        has_ai || has_c2pa,
        findings,
        json!({"commands": commands, "keys_dropped": keys_dropped, "comments_dropped": comments_dropped}),
    )
}

/// `clean_latex(text)`: `(text, actions)`.
pub fn clean_latex(text: &str) -> (String, Vec<String>) {
    let mut actions: Vec<String> = Vec::new();
    let mut out = String::with_capacity(text.len());
    let mut last = 0usize;
    for mc in iter_meta_commands(text) {
        out.push_str(&text[last..mc.start]);
        let (new_arg, removed) =
            if mc.cmd == "hypersetup" { clean_hypersetup(mc.arg) } else { clean_pdfinfo(mc.arg) };
        match new_arg {
            None => actions.push(format!("drop {} block", mc.cmd)),
            Some(a) => {
                out.push_str(&format!("\\{}{{{}}}", mc.cmd, a));
                for (key, _ai, _c2pa) in removed {
                    actions.push(format!("drop {} {}", mc.cmd, key.to_lowercase().trim_start_matches('/')));
                }
            }
        }
        last = mc.end;
    }
    out.push_str(&text[last..]);
    let mut text = out;

    let mut kept_lines: Vec<&str> = Vec::new();
    let mut dropped = 0usize;
    for (line, in_verbatim) in lines_with_verbatim(&text) {
        if in_verbatim {
            kept_lines.push(line);
            continue;
        }
        let stripped = lstrip_py(line);
        let (drop, label, _ai) = if stripped.starts_with('%') { comment_class(stripped) } else { (false, "", false) };
        if drop {
            dropped += 1;
            actions.push(format!("drop comment: {label}"));
            continue;
        }
        kept_lines.push(line);
    }
    if dropped > 0 {
        text = kept_lines.join("\n");
    }
    if actions.is_empty() {
        actions.push("no LaTeX metadata removed".to_string());
    }
    (text, actions)
}
