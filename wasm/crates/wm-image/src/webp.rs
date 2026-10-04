//! WebP (RIFF) container: chunk walker, inspect and strip.

use crate::common::*;

/// One RIFF chunk: `(fourcc, payload, padding)`.
pub type WebpChunk<'a> = ([u8; 4], &'a [u8], &'a [u8]);

fn is_webp(data: &[u8]) -> bool {
    data.len() >= 12 && &data[..4] == WEBP_RIFF && &data[8..12] == WEBP_SIG
}

/// Port of `_webp_chunks`: returns `(chunks, notes)`; `notes == ["not a WebP"]`
/// with no chunks when the RIFF/WEBP signature is missing.
pub fn webp_chunks(data: &[u8]) -> (Vec<WebpChunk<'_>>, Vec<String>) {
    if !is_webp(data) {
        return (Vec::new(), vec!["not a WebP".to_string()]);
    }
    let mut notes: Vec<String> = Vec::new();
    let declared = rd_u32(data, 4, true).unwrap_or(0) as u64;
    if declared + 8 != data.len() as u64 {
        notes.push(format!("RIFF size mismatch: header={} actual={}", declared + 8, data.len()));
    }
    let mut chunks: Vec<WebpChunk<'_>> = Vec::new();
    let mut pos = 12usize;
    while pos + 8 <= data.len() {
        let mut fourcc = [0u8; 4];
        fourcc.copy_from_slice(&data[pos..pos + 4]);
        let length = rd_u32(data, pos + 4, true).unwrap_or(0) as u64;
        let payload_start = pos as u64 + 8;
        let payload_end = payload_start + length;
        let padded_end = payload_end + (length & 1);
        if padded_end > data.len() as u64 {
            notes.push(format!("truncated WebP chunk {}", latin1(&fourcc)));
            break;
        }
        let (ps, pe, pd) = (payload_start as usize, payload_end as usize, padded_end as usize);
        chunks.push((fourcc, &data[ps..pe], &data[pe..pd]));
        pos = pd;
    }
    if pos != data.len() && !notes.iter().any(|n| n.contains("truncated")) {
        notes.push(format!("trailing WebP bytes: {}", data.len() - pos));
    }
    (chunks, notes)
}

pub fn inspect_webp(data: &[u8]) -> Inspection {
    let (chunks, mut findings) = webp_chunks(data);
    if chunks.is_empty() && findings == ["not a WebP"] {
        return (false, false, findings);
    }
    let mut has_c2pa = false;
    let mut has_ai = false;
    for (fourcc, payload, _padding) in &chunks {
        let name = latin1(fourcc);
        if fourcc.eq_ignore_ascii_case(b"C2PA") {
            has_c2pa = true;
            has_ai = true;
            findings.push("WebP C2PA chunk".to_string());
            continue;
        }
        if fourcc == b"XMP " || fourcc == b"EXIF" {
            let hits = contains_ai_or_c2pa(payload);
            if !hits.is_empty() {
                has_ai = true;
                if any_lower_in(&hits, &["c2pa", "contentcredentials", "jumb", "contentauth"]) {
                    has_c2pa = true;
                }
                findings.push(format!("WebP {name}: {}", join_first(&hits, 8)));
            }
        }
    }
    (has_c2pa, has_ai || has_c2pa, findings)
}

/// Port of `strip_webp`. Refuses (Err) anything with notes: wrong signature,
/// size mismatch, truncated or trailing bytes.
pub fn strip_webp(data: &[u8], strip_all_metadata: bool) -> Stripped {
    let (chunks, notes) = webp_chunks(data);
    if chunks.is_empty() && notes == ["not a WebP"] {
        return Err(ImageError::new("not WebP"));
    }
    if !notes.is_empty() {
        return Err(ImageError(format!("malformed WebP: {}", notes.join("; "))));
    }

    let mut actions: Vec<String> = Vec::new();
    let mut kept: Vec<&WebpChunk<'_>> = Vec::new();
    let mut removed_flags: u8 = 0;
    let flag_for = |f: &[u8; 4]| -> Option<u8> {
        match f {
            b"ICCP" => Some(0x20),
            b"EXIF" => Some(0x08),
            b"XMP " => Some(0x04),
            _ => None,
        }
    };

    for chunk in &chunks {
        let (fourcc, payload, _padding) = chunk;
        let mut drop = fourcc.eq_ignore_ascii_case(b"C2PA");
        let flag = flag_for(fourcc);
        if flag.is_some() {
            drop = strip_all_metadata || has_ai_or_c2pa(payload);
        }
        if drop {
            actions.push(format!("drop WebP chunk {}", latin1(fourcc)));
            removed_flags |= flag.unwrap_or(0);
        } else {
            kept.push(chunk);
        }
    }

    let mut body: Vec<u8> = WEBP_SIG.to_vec();
    for (fourcc, payload, padding) in kept {
        let mut chunk: Vec<u8> = payload.to_vec();
        if fourcc == b"VP8X" && !chunk.is_empty() && removed_flags != 0 {
            chunk[0] &= !removed_flags;
        }
        body.extend_from_slice(fourcc);
        body.extend_from_slice(&(chunk.len() as u32).to_le_bytes());
        let odd = chunk.len() & 1 == 1;
        body.extend_from_slice(&chunk);
        if odd {
            body.extend_from_slice(padding);
        }
    }

    if actions.is_empty() {
        actions
            .push("no WebP metadata chunks removed (already clean or none matched)".to_string());
    }
    let mut out: Vec<u8> = WEBP_RIFF.to_vec();
    out.extend_from_slice(&(body.len() as u32).to_le_bytes());
    out.extend_from_slice(&body);
    Ok((out, actions))
}
