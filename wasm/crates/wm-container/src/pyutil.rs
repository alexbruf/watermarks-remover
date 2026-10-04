//! Small helpers that reproduce Python `str` / `bytes` / `posixpath` / `base64`
//! / `urllib.parse` semantics the Python source relies on.
//!
//! All offsets are UTF-8 byte offsets into `&str`. Wherever the Python code
//! indexes a `str` by code point and then only ever looks at ASCII delimiters,
//! byte offsets are equivalent; places that look at "the next character"
//! decode it explicitly.

use std::fmt::Write as _;

/// Code points `U+3F080..=U+3F0FF` stand in for undecodable bytes `0x80..=0xFF`
/// (Python's `errors="surrogateescape"`; a Rust `String` cannot hold lone
/// surrogates). They are unassigned (category Cn), neither alphanumeric nor
/// whitespace, exactly like the lone surrogates they replace.
const ESC_BASE: u32 = 0x3F000;

fn esc_char(b: u8) -> char {
    char::from_u32(ESC_BASE + b as u32).unwrap_or('\u{fffd}')
}

fn unesc_byte(c: char) -> Option<u8> {
    let v = c as u32;
    if (ESC_BASE + 0x80..=ESC_BASE + 0xFF).contains(&v) {
        Some((v - ESC_BASE) as u8)
    } else {
        None
    }
}

/// `data.decode("utf-8", errors="surrogateescape")`.
pub fn decode_surrogateescape(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len());
    let mut rest = data;
    loop {
        match std::str::from_utf8(rest) {
            Ok(s) => {
                out.push_str(s);
                return out;
            }
            Err(e) => {
                let good = e.valid_up_to();
                // SAFETY-free: the prefix is valid by construction.
                if let Ok(s) = std::str::from_utf8(&rest[..good]) {
                    out.push_str(s);
                }
                let bad = e.error_len().unwrap_or(rest.len() - good);
                for &b in &rest[good..good + bad] {
                    out.push(esc_char(b));
                }
                rest = &rest[good + bad..];
            }
        }
    }
}

/// `text.encode("utf-8", errors="surrogateescape")`.
pub fn encode_surrogateescape(text: &str) -> Vec<u8> {
    if !text.chars().any(|c| unesc_byte(c).is_some()) {
        return text.as_bytes().to_vec();
    }
    let mut out = Vec::with_capacity(text.len());
    let mut buf = [0u8; 4];
    for c in text.chars() {
        match unesc_byte(c) {
            Some(b) => out.push(b),
            None => out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes()),
        }
    }
    out
}

/// `data.decode("utf-8", errors="replace")`.
pub fn decode_replace(data: &[u8]) -> String {
    String::from_utf8_lossy(data).into_owned()
}

/// `str.isspace()` for one character.
pub fn py_isspace(c: char) -> bool {
    c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c)
}

/// `str.strip()`.
pub fn py_strip(s: &str) -> &str {
    s.trim_matches(py_isspace)
}

/// `str.lstrip()`.
pub fn py_lstrip(s: &str) -> &str {
    s.trim_start_matches(py_isspace)
}

/// `s[:n]` (first `n` characters).
pub fn py_prefix(s: &str, n: usize) -> &str {
    match s.char_indices().nth(n) {
        Some((i, _)) => &s[..i],
        None => s,
    }
}

/// `bytes.lstrip()` (ASCII whitespace).
pub fn bytes_lstrip(b: &[u8]) -> &[u8] {
    let n = b.iter().take_while(|c| matches!(c, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c)).count();
    &b[n..]
}

/// `str.splitlines()` (no `keepends`).
pub fn splitlines(s: &str) -> Vec<&str> {
    let mut lines = Vec::new();
    let mut start = 0;
    let mut iter = s.char_indices().peekable();
    while let Some((i, c)) = iter.next() {
        let is_break = matches!(
            c,
            '\n' | '\r' | '\u{0b}' | '\u{0c}' | '\u{1c}' | '\u{1d}' | '\u{1e}' | '\u{85}' | '\u{2028}' | '\u{2029}'
        );
        if !is_break {
            continue;
        }
        lines.push(&s[start..i]);
        let mut end = i + c.len_utf8();
        if c == '\r' {
            if let Some(&(_, '\n')) = iter.peek() {
                iter.next();
                end += 1;
            }
        }
        start = end;
    }
    if start < s.len() {
        lines.push(&s[start..]);
    }
    lines
}

/// The character starting at byte offset `i`, if any.
pub fn char_at(s: &str, i: usize) -> Option<char> {
    s.get(i..)?.chars().next()
}

/// Regex `\w` for one character (alphanumeric or underscore).
pub fn is_word_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// True when a `\b` boundary sits at byte offset `i` and the character at `i`
/// is a word character.
pub fn word_boundary_before_word_char(s: &str, i: usize) -> bool {
    match s[..i].chars().next_back() {
        Some(p) => !is_word_char(p),
        None => true,
    }
}

/// `str.isalnum()` for one character.
pub fn py_isalnum(c: char) -> bool {
    c.is_alphanumeric()
}

/// ASCII-case-insensitive `haystack[at..].startswith(needle_lower)`.
pub fn starts_with_ci(hay: &str, at: usize, needle_lower: &str) -> bool {
    let b = hay.as_bytes();
    let n = needle_lower.as_bytes();
    match b.get(at..at + n.len()) {
        Some(w) => w.iter().zip(n).all(|(a, b)| a.to_ascii_lowercase() == *b),
        None => false,
    }
}

/// Python `repr()` of a `str` (good enough for error messages).
pub fn py_str_repr(s: &str) -> String {
    let quote = if s.contains('\'') && !s.contains('"') { '"' } else { '\'' };
    let mut out = String::new();
    out.push(quote);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                let _ = write!(out, "\\x{:02x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push(quote);
    out
}

// ---------------------------------------------------------------------------
// posixpath
// ---------------------------------------------------------------------------

/// `posixpath.normpath`.
pub fn normpath(path: &str) -> String {
    if path.is_empty() {
        return ".".to_string();
    }
    let mut initial = 0usize;
    if path.starts_with('/') {
        initial = 1;
        if path.starts_with("//") && !path.starts_with("///") {
            initial = 2;
        }
    }
    let mut comps: Vec<&str> = Vec::new();
    for comp in path.split('/') {
        if comp.is_empty() || comp == "." {
            continue;
        }
        if comp != ".."
            || (initial == 0 && comps.is_empty())
            || comps.last().is_some_and(|c| *c == "..")
        {
            comps.push(comp);
        } else if !comps.is_empty() {
            comps.pop();
        }
    }
    let mut out = "/".repeat(initial);
    out.push_str(&comps.join("/"));
    if out.is_empty() {
        ".".to_string()
    } else {
        out
    }
}

/// `posixpath.join(a, b)`.
pub fn join(a: &str, b: &str) -> String {
    if b.starts_with('/') {
        return b.to_string();
    }
    if a.is_empty() || a.ends_with('/') {
        return format!("{a}{b}");
    }
    format!("{a}/{b}")
}

/// `posixpath.dirname`.
pub fn dirname(p: &str) -> String {
    let i = p.rfind('/').map_or(0, |i| i + 1);
    let head = &p[..i];
    if !head.is_empty() && head.bytes().any(|c| c != b'/') {
        head.trim_end_matches('/').to_string()
    } else {
        head.to_string()
    }
}

/// `pathlib.PurePath(name).suffix` for POSIX names (last component only).
pub fn path_suffix(name: &str) -> &str {
    let last = name.rsplit('/').find(|c| !c.is_empty()).unwrap_or("");
    match last.rfind('.') {
        Some(i) if i > 0 && i + 1 < last.len() => &last[i..],
        _ => "",
    }
}

// ---------------------------------------------------------------------------
// cp437 (zip historical file-name encoding)
// ---------------------------------------------------------------------------

const CP437_HIGH: [char; 128] = [
    'Ç', 'ü', 'é', 'â', 'ä', 'à', 'å', 'ç', 'ê', 'ë', 'è', 'ï', 'î', 'ì', 'Ä', 'Å', 'É', 'æ', 'Æ',
    'ô', 'ö', 'ò', 'û', 'ù', 'ÿ', 'Ö', 'Ü', '¢', '£', '¥', '₧', 'ƒ', 'á', 'í', 'ó', 'ú', 'ñ', 'Ñ',
    'ª', 'º', '¿', '⌐', '¬', '½', '¼', '¡', '«', '»', '░', '▒', '▓', '│', '┤', '╡', '╢', '╖', '╕',
    '╣', '║', '╗', '╝', '╜', '╛', '┐', '└', '┴', '┬', '├', '─', '┼', '╞', '╟', '╚', '╔', '╩', '╦',
    '╠', '═', '╬', '╧', '╨', '╤', '╥', '╙', '╘', '╒', '╓', '╫', '╪', '┘', '┌', '█', '▄', '▌', '▐',
    '▀', 'α', 'ß', 'Γ', 'π', 'Σ', 'σ', 'µ', 'τ', 'Φ', 'Θ', 'Ω', 'δ', '∞', 'φ', 'ε', '∩', '≡', '±',
    '≥', '≤', '⌠', '⌡', '÷', '≈', '°', '∙', '·', '√', 'ⁿ', '²', '■', '\u{a0}',
];

/// `bytes.decode("cp437")`.
pub fn decode_cp437(b: &[u8]) -> String {
    b.iter().map(|&c| if c < 0x80 { c as char } else { CP437_HIGH[(c - 0x80) as usize] }).collect()
}

// ---------------------------------------------------------------------------
// crc32
// ---------------------------------------------------------------------------

const fn crc_table() -> [u32; 256] {
    let mut t = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 { 0xEDB8_8320 ^ (c >> 1) } else { c >> 1 };
            k += 1;
        }
        t[i] = c;
        i += 1;
    }
    t
}

static CRC_TABLE: [u32; 256] = crc_table();

/// `zlib.crc32(data)`.
pub fn crc32(data: &[u8]) -> u32 {
    let mut c = 0xFFFF_FFFFu32;
    for &b in data {
        c = CRC_TABLE[((c ^ b as u32) & 0xFF) as usize] ^ (c >> 8);
    }
    c ^ 0xFFFF_FFFF
}

// ---------------------------------------------------------------------------
// base64 / percent-encoding
// ---------------------------------------------------------------------------

fn b64_val(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// `base64.b64decode(s)` (non-validating) over an already ASCII-only string;
/// `Err` is a `binascii.Error` (the message is not needed by callers).
pub fn b64decode_lenient(s: &[u8]) -> Result<Vec<u8>, ()> {
    let mut out = Vec::with_capacity(s.len() / 4 * 3 + 3);
    let mut quad_pos = 0u8;
    let mut left = 0u8;
    let mut i = 0usize;
    while i < s.len() {
        let c = s[i];
        if c > 0x7f || c == b'\r' || c == b'\n' || c == b' ' {
            i += 1;
            continue;
        }
        if c == b'=' {
            let skip = if quad_pos < 2 {
                true
            } else if quad_pos == 2 {
                // The next *valid* character (alphabet or '=') after this pad
                // must itself be a pad.
                let next_valid = s[i + 1..].iter().copied().find(|&x| x < 0x80 && (x == b'=' || b64_val(x).is_some()));
                next_valid != Some(b'=')
            } else {
                false
            };
            if skip {
                i += 1;
                continue;
            }
            return Ok(out);
        }
        let Some(v) = b64_val(c) else {
            i += 1;
            continue;
        };
        match quad_pos {
            0 => {
                quad_pos = 1;
                left = v;
            }
            1 => {
                quad_pos = 2;
                out.push((left << 2) | (v >> 4));
                left = v & 0x0f;
            }
            2 => {
                quad_pos = 3;
                out.push((left << 4) | (v >> 2));
                left = v & 0x03;
            }
            _ => {
                quad_pos = 0;
                out.push((left << 6) | v);
                left = 0;
            }
        }
        i += 1;
    }
    if quad_pos != 0 {
        return Err(());
    }
    Ok(out)
}

const B64_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// `base64.b64encode(data).decode("ascii")`.
pub fn b64encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(B64_ALPHABET[(n >> 18) as usize & 63] as char);
        out.push(B64_ALPHABET[(n >> 12) as usize & 63] as char);
        if chunk.len() > 1 {
            out.push(B64_ALPHABET[(n >> 6) as usize & 63] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(B64_ALPHABET[n as usize & 63] as char);
        } else {
            out.push('=');
        }
    }
    out
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// `urllib.parse.unquote_to_bytes(s)`.
pub fn unquote_to_bytes(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let (Some(h), Some(l)) = (hex_val(b[i + 1]), hex_val(b[i + 2])) {
                out.push(h * 16 + l);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    out
}

/// `urllib.parse.quote_from_bytes(data)` (default `safe="/"`).
pub fn quote_from_bytes(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len());
    for &c in data {
        if c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.' | b'-' | b'~' | b'/') {
            out.push(c as char);
        } else {
            let _ = write!(out, "%{c:02X}");
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normpath_matches_posixpath() {
        assert_eq!(normpath("a/b/../c"), "a/c");
        assert_eq!(normpath("/a/../.."), "/");
        assert_eq!(normpath("//a"), "//a");
        assert_eq!(normpath("///a"), "/a");
        assert_eq!(normpath("../a"), "../a");
        assert_eq!(normpath(""), ".");
        assert_eq!(normpath("./"), ".");
        assert_eq!(dirname("word/_rels/document.xml.rels"), "word/_rels");
        assert_eq!(dirname("a"), "");
        assert_eq!(dirname("/a"), "/");
        assert_eq!(join("a", "/b"), "/b");
        assert_eq!(join("", "b"), "b");
    }

    #[test]
    fn suffix() {
        assert_eq!(path_suffix("x/y.PDF"), ".PDF");
        assert_eq!(path_suffix(".md"), "");
        assert_eq!(path_suffix("a."), "");
        assert_eq!(path_suffix("a.tar.gz"), ".gz");
    }

    #[test]
    fn splitlines_python() {
        assert_eq!(splitlines("a\r\nb\nc\u{2028}d"), vec!["a", "b", "c", "d"]);
        assert_eq!(splitlines("a\n"), vec!["a"]);
        assert_eq!(splitlines("\n\nx"), vec!["", "", "x"]);
    }

    #[test]
    fn surrogateescape_roundtrip() {
        let raw = b"ab\xff\xfecd\xe2\x82";
        let s = decode_surrogateescape(raw);
        assert_eq!(encode_surrogateescape(&s), raw);
    }

    #[test]
    fn unquote() {
        assert_eq!(unquote_to_bytes("a%41%4g%"), b"aA%4g%".to_vec());
        assert_eq!(unquote_to_bytes("%41"), b"A".to_vec());
    }
}
