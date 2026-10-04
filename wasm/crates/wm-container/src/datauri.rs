//! Embedded `data:image/...` URI scanning, inspection and cleaning.

use crate::media::{dropped_something, inspect_data_uri_payload, strip_data_uri_payload};
use crate::pyutil::{
    b64decode_lenient, b64encode, char_at, py_isspace, quote_from_bytes, unquote_to_bytes,
};

pub(crate) struct DataUri<'a> {
    pub start: usize,
    pub end: usize,
    pub mime: &'a str,
    pub params: &'a str,
    pub payload: &'a str,
}

fn is_mime_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, b'+' | b'-' | b'.')
}

fn is_break(c: u8) -> bool {
    matches!(c, b'"' | b'\'' | b'<' | b'>' | b'(' | b')')
}

fn is_param_break(c: u8) -> bool {
    is_break(c) || c == b',' || c == b';'
}

fn is_payload_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, b'+' | b'/' | b'=' | b'%')
}

fn skip_candidate(b: &[u8], start: usize) -> usize {
    let mut j = start;
    while j < b.len() && !is_break(b[j]) {
        j += 1;
    }
    if j > start + 1 {
        j
    } else {
        start + 1
    }
}

fn find_from(hay: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if from > hay.len() || hay.len() - from < needle.len() {
        return None;
    }
    (from..=hay.len() - needle.len()).find(|&i| &hay[i..i + needle.len()] == needle)
}

/// `_iter_data_uris(text)`.
pub(crate) fn iter_data_uris(text: &str) -> Vec<DataUri<'_>> {
    let b = text.as_bytes();
    let n = b.len();
    let low = text.to_ascii_lowercase();
    let lb = low.as_bytes();
    let mut out = Vec::new();
    let mut pos = 0usize;
    loop {
        let Some(i) = find_from(lb, b"data:image/", pos) else {
            return out;
        };
        let mut k = i + "data:image/".len();
        let mime_start = k;
        while k < n && is_mime_char(b[k]) {
            k += 1;
        }
        let mime = &text[mime_start..k];
        if mime.is_empty() {
            pos = i + 1;
            continue;
        }
        let params_start = k;
        while k < n && b[k] == b';' {
            k += 1;
            while k < n {
                if is_param_break(b[k]) {
                    break;
                }
                match char_at(text, k) {
                    Some(c) if py_isspace(c) => break,
                    Some(c) => k += c.len_utf8(),
                    None => break,
                }
            }
        }
        let params = &text[params_start..k];
        if k >= n || b[k] != b',' {
            pos = skip_candidate(b, i);
            continue;
        }
        k += 1;
        let payload_start = k;
        while k < n {
            if is_payload_char(b[k]) {
                k += 1;
                continue;
            }
            match char_at(text, k) {
                Some(c) if py_isspace(c) => k += c.len_utf8(),
                _ => break,
            }
        }
        let payload = &text[payload_start..k];
        if payload.is_empty() {
            pos = skip_candidate(b, i);
            continue;
        }
        out.push(DataUri { start: i, end: k, mime, params, payload });
        pos = k;
    }
}

/// Decode a data-URI payload exactly like the Python helpers; `None` on any
/// decoding exception or an empty result.
fn decode_payload(params: &str, payload: &str) -> Option<(bool, Vec<u8>)> {
    let is_b64 = params.to_lowercase().contains("base64");
    let data = if is_b64 {
        let mut raw: String = payload.chars().filter(|c| !py_isspace(*c)).collect();
        let pad = raw.chars().count() % 4;
        if pad != 0 {
            for _ in 0..(4 - pad) {
                raw.push('=');
            }
        }
        if !raw.is_ascii() {
            return None;
        }
        b64decode_lenient(raw.as_bytes()).ok()?
    } else {
        unquote_to_bytes(payload)
    };
    if data.is_empty() {
        return None;
    }
    Some((is_b64, data))
}

/// `_inspect_embedded_data_uris(text)`.
pub fn inspect_embedded_data_uris(text: &str) -> (bool, bool, Vec<String>) {
    let mut has_c2pa = false;
    let mut has_ai = false;
    let mut findings = Vec::new();
    for u in iter_data_uris(text) {
        let mime_l = u.mime.to_lowercase();
        let Some((_b64, data)) = decode_payload(u.params, u.payload) else {
            continue;
        };
        let (sub_c2pa, sub_ai, sub_findings) = inspect_data_uri_payload(&data, &mime_l);
        if sub_c2pa {
            has_c2pa = true;
        }
        if sub_ai || sub_c2pa {
            has_ai = true;
        }
        for f in sub_findings {
            findings.push(format!("embedded data:image/{mime_l}: {f}"));
        }
    }
    (has_c2pa, has_ai, findings)
}

/// `_clean_embedded_data_uris(text)` (always `strip_all_metadata=True`).
pub fn clean_embedded_data_uris(text: &str) -> (String, Vec<String>) {
    let mut actions = Vec::new();
    let mut out = String::with_capacity(text.len());
    let mut last = 0usize;
    for u in iter_data_uris(text) {
        out.push_str(&text[last..u.start]);
        let rebuilt = clean_one(u.mime, u.params, u.payload, &mut actions);
        match rebuilt {
            Some(r) => out.push_str(&r),
            None => out.push_str(&text[u.start..u.end]),
        }
        last = u.end;
    }
    out.push_str(&text[last..]);
    (out, actions)
}

fn clean_one(mime: &str, params: &str, payload: &str, actions: &mut Vec<String>) -> Option<String> {
    let (is_b64, data) = decode_payload(params, payload)?;
    let (cleaned, sub_actions) = strip_data_uri_payload(&data, mime)?;
    if !dropped_something(&sub_actions, &cleaned, &data) {
        return None;
    }
    let first: Vec<&str> = sub_actions.iter().take(2).map(String::as_str).collect();
    actions.push(format!("cleaned embedded data:image/{mime} ({})", first.join(", ")));
    if is_b64 {
        Some(format!("data:image/{mime}{params},{}", b64encode(&cleaned)))
    } else {
        Some(format!("data:image/{mime}{params},{}", quote_from_bytes(&cleaned)))
    }
}
