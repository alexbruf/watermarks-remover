//! JPEG: marker-segment walker, inspect and strip.

use crate::common::*;

fn seg_len(data: &[u8], i: usize) -> usize {
    rd_u16(data, i, false).unwrap_or(0) as usize
}

pub fn inspect_jpeg(data: &[u8]) -> Inspection {
    let mut findings: Vec<String> = Vec::new();
    let mut has_c2pa = false;
    let mut has_ai = false;
    if !data.starts_with(JPEG_SOI) {
        return (false, false, vec!["not a JPEG".to_string()]);
    }
    let com_hints: Vec<&[u8]> = JPEG_COM_AI_HINTS.to_vec();
    let mut i = 2usize;
    let n = data.len();
    while i + 4 <= n {
        if data[i] != 0xFF {
            i += 1;
            continue;
        }
        while i < n && data[i] == 0xFF {
            i += 1;
        }
        if i >= n {
            break;
        }
        let marker = data[i];
        i += 1;
        if marker == 0xD8 || marker == 0xD9 {
            continue;
        }
        if marker == 0xDA {
            break;
        }
        if (0xD0..=0xD7).contains(&marker) {
            continue;
        }
        if i + 2 > n {
            break;
        }
        let seglen = seg_len(data, i);
        if seglen < 2 || i + seglen > n {
            findings.push(format!("bad segment length at marker 0x{marker:02X}"));
            break;
        }
        let payload = &data[i + 2..i + seglen];
        i += seglen;

        if marker == 0xFE {
            let hits = contains_any(payload, &com_hints);
            if !hits.is_empty() {
                has_ai = true;
                if any_lower_in(&hits, &["c2pa", "contentcredentials", "jumb", "contentauth"]) {
                    has_c2pa = true;
                }
                findings.push(format!("JPEG COM: {}", join_first(&hits, 8)));
            }
        }
        if marker == 0xEB {
            has_c2pa = true;
            findings.push("JPEG APP11 segment (JUMBF/C2PA common)".to_string());
        }
        if matches!(marker, 0xE1 | 0xE2 | 0xED | 0xEE | 0xEB) {
            let hits = contains_ai_or_c2pa(payload);
            if !hits.is_empty() {
                has_ai = true;
                if any_lower_in(&hits, &["c2pa", "contentcredentials", "jumb", "contentauth"]) {
                    has_c2pa = true;
                }
                findings.push(format!("JPEG APP{}: {}", marker - 0xE0, join_first(&hits, 8)));
            }
        }
    }
    let whole = contains_any(data, &JPEG_C2PA_MARKERS);
    if !whole.is_empty() && !has_c2pa {
        has_c2pa = true;
        findings.push(format!("byte-scan C2PA markers: {}", join_first(&whole, 6)));
    }
    (has_c2pa, has_ai || has_c2pa, findings)
}

/// Port of `strip_jpeg`. `strip_all_app` drops every APPn (except APP0/JFIF)
/// and COM segment; otherwise only those carrying AI/C2PA markers. APP11 is
/// always dropped.
pub fn strip_jpeg(data: &[u8], strip_all_app: bool) -> Stripped {
    if !data.starts_with(JPEG_SOI) {
        return Err(ImageError::new("not JPEG"));
    }
    let com_hints: Vec<&[u8]> = JPEG_COM_AI_HINTS.to_vec();
    let mut actions: Vec<String> = Vec::new();
    let mut out: Vec<u8> = JPEG_SOI.to_vec();
    let mut i = 2usize;
    let n = data.len();
    while i < n {
        if data[i] != 0xFF {
            out.extend_from_slice(&data[i..]);
            actions.push("copied remainder after non-marker byte".to_string());
            break;
        }
        while i < n && data[i] == 0xFF {
            i += 1;
        }
        if i >= n {
            break;
        }
        let marker = data[i];
        i += 1;

        if marker == 0xD9 {
            out.extend_from_slice(b"\xff\xd9");
            break;
        }
        if marker == 0xD8 {
            continue;
        }
        if (0xD0..=0xD7).contains(&marker) {
            out.extend_from_slice(&[0xFF, marker]);
            continue;
        }
        if marker == 0xDA {
            if i + 2 > n {
                break;
            }
            out.extend_from_slice(b"\xff\xda");
            out.extend_from_slice(&data[i..]);
            actions.push("preserved entropy-coded scan (SOS\u{2192}EOF)".to_string());
            break;
        }

        if i + 2 > n {
            break;
        }
        let seglen = seg_len(data, i);
        if seglen < 2 || i + seglen > n {
            // Python: data[i - 2:] -- i >= 3 here (SOI, 0xFF, marker consumed).
            out.extend_from_slice(&data[i - 2..]);
            actions.push("truncated segment; copied remainder".to_string());
            break;
        }
        let payload = &data[i + 2..i + seglen];
        let next_i = i + seglen;

        let mut keep = false;
        let mut drop = false;
        if (0xE0..=0xEF).contains(&marker) {
            if marker == 0xEB {
                drop = true;
                actions.push("drop APP11 (C2PA/JUMBF)".to_string());
            } else if strip_all_app && marker != 0xE0 {
                drop = true;
                actions.push(format!("drop APP{}", marker - 0xE0));
            } else if has_ai_or_c2pa(payload) {
                drop = true;
                actions.push(format!("drop APP{} (AI/C2PA markers)", marker - 0xE0));
            } else {
                keep = true;
            }
        } else if marker == 0xFE {
            let hits = contains_any(payload, &com_hints);
            if strip_all_app || !hits.is_empty() {
                drop = true;
                actions.push("drop COM comment".to_string());
            } else {
                keep = true;
            }
        } else {
            keep = true;
        }

        if keep && !drop {
            out.extend_from_slice(&[0xFF, marker]);
            out.extend_from_slice(&data[i..i + seglen]);
        }
        i = next_i;
    }
    if actions.is_empty() {
        actions.push("no JPEG APP segments removed".to_string());
    }
    Ok((out, actions))
}
