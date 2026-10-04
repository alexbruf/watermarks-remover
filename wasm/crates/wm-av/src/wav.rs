//! WAV (RIFF) chunk inspection / stripping.

use wm_image::common::*;

use crate::id3::inspect_id3v2;
use crate::{classify_c2pa, Inspection};

/// Chunk at `pos`: `(id, csize, cstart, cend)`; `cend` is `None` when it
/// overflows or runs past the data (Python: `cend > len(data)`).
fn chunk_at(data: &[u8], pos: usize) -> (&[u8], usize, usize, Option<usize>) {
    let cid = &data[pos..pos + 4];
    let csize = rd_u32(data, pos + 4, true).unwrap_or(0) as usize;
    let cstart = pos + 8;
    let cend = cstart.checked_add(csize).filter(|&e| e <= data.len());
    (cid, csize, cstart, cend)
}

pub fn inspect_wav(data: &[u8]) -> Inspection {
    let mut findings = Vec::new();
    let (mut has_ai, mut has_c2pa) = (false, false);
    let mut pos = 12usize;
    while pos + 8 <= data.len() {
        let (cid, csize, cstart, cend) = chunk_at(data, pos);
        let Some(cend) = cend else { break };
        let payload = &data[cstart..cend];
        if cid == b"C2PA" {
            has_c2pa = true;
            findings.push("WAV C2PA-related manifest chunk".to_string());
        } else if cid == b"LIST" && payload.starts_with(b"INFO") {
            let hits = contains_any(payload, &AI_META_HINTS);
            if !hits.is_empty() {
                has_ai = true;
                if classify_c2pa(&hits) {
                    has_c2pa = true;
                }
                findings.push(format!("WAV LIST INFO chunk: {}", join_first(&hits, 8)));
            }
        } else if cid == b"id3 " || cid == b"ID3 " {
            let (c2pa, ai, sub) = inspect_id3v2(payload);
            if ai {
                has_ai = true;
                has_c2pa = has_c2pa || c2pa;
                findings.extend(sub.into_iter().map(|f| format!("WAV id3 chunk / {f}")));
            }
        }
        pos = match cend.checked_add(csize & 1) {
            Some(p) => p,
            None => break,
        };
    }
    (has_c2pa, has_ai, findings)
}

pub fn strip_wav(data: &[u8], strip_all_metadata: bool) -> (Vec<u8>, Vec<String>) {
    let mut actions = Vec::new();
    let mut out: Vec<u8> = data[..12.min(data.len())].to_vec();
    let mut pos = 12usize;
    while pos + 8 <= data.len() {
        let (cid, csize, cstart, cend) = chunk_at(data, pos);
        let Some(cend) = cend else {
            out.extend_from_slice(&data[pos..]);
            break;
        };
        let payload = &data[cstart..cend];
        let pad = csize & 1;
        let chunk_total = slice_clamped(data, pos, cend + pad);

        let is_c2pa = cid == b"C2PA";
        let is_info = cid == b"LIST" && payload.starts_with(b"INFO");
        let is_id3 = cid == b"id3 " || cid == b"ID3 ";
        let drop = is_c2pa
            || ((is_info || is_id3)
                && (strip_all_metadata || !contains_any(payload, &AI_META_HINTS).is_empty()));
        if drop {
            let label = if is_c2pa {
                "C2PA"
            } else if is_info {
                "LIST INFO"
            } else {
                "id3"
            };
            actions.push(format!("drop WAV {label} chunk"));
        } else {
            out.extend_from_slice(chunk_total);
        }
        pos = cend + pad;
    }

    if out.len() >= 8 {
        let n = (out.len() - 8) as u32;
        out[4..8].copy_from_slice(&n.to_le_bytes());
    }
    if actions.is_empty() {
        actions.push("no WAV metadata chunks removed (already clean or none matched)".to_string());
    }
    (out, actions)
}
