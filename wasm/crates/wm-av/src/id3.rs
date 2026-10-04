//! ID3v2 parsing / inspection / stripping (MP3 files; also WAV `id3 ` chunks
//! and FLAC's ID3v2 prefix).

use wm_image::common::*;

use crate::{classify_c2pa, Inspection};

/// A decoded ID3v2 tag at the start of a buffer.
#[derive(Debug, Clone)]
pub struct Id3Tag<'a> {
    /// Total size including the 10-byte header and optional footer.
    pub total: usize,
    pub major: u8,
    /// `(frame_id, payload)` for v2.3/v2.4; empty for v2.2 / empty tags.
    pub frames: Vec<(&'a [u8], &'a [u8])>,
}

pub(crate) fn id3v2_size(data: &[u8], offset: usize) -> Option<usize> {
    let b = data.get(offset..offset.checked_add(4)?)?;
    Some(
        (((b[0] & 0x7F) as usize) << 21)
            | (((b[1] & 0x7F) as usize) << 14)
            | (((b[2] & 0x7F) as usize) << 7)
            | ((b[3] & 0x7F) as usize),
    )
}

pub(crate) fn id3v2_size_bytes(n: usize) -> [u8; 4] {
    [((n >> 21) & 0x7F) as u8, ((n >> 14) & 0x7F) as u8, ((n >> 7) & 0x7F) as u8, (n & 0x7F) as u8]
}

/// Port of `_id3v2_frames_start`; `None` when the extended header is invalid.
pub(crate) fn id3v2_frames_start(data: &[u8], total: usize, major: u8) -> Option<usize> {
    let pos = 10usize;
    if data.get(5)? & 0x40 == 0 {
        return Some(pos);
    }
    if pos + 4 > total {
        return None;
    }
    let ext_size = if major == 4 {
        id3v2_size(data, pos)? as u64
    } else {
        rd_u32(data, pos, false)? as u64 + 4
    };
    let np = pos as u64 + ext_size;
    if np <= total as u64 {
        Some(np as usize)
    } else {
        None
    }
}

/// Port of `_parse_id3v2_frames`.
pub fn parse_id3v2_frames(data: &[u8]) -> Option<Id3Tag<'_>> {
    if data.len() < 10 || &data[..3] != b"ID3" {
        return None;
    }
    let major = data[3];
    let tag_size = id3v2_size(data, 6)?;
    let frames_end = 10 + tag_size;
    let footer_size = if major == 4 && data[5] & 0x10 != 0 { 10 } else { 0 };
    let total = frames_end + footer_size;
    if total > data.len() {
        return None;
    }
    if footer_size != 0 {
        let mut want = b"3DI".to_vec();
        want.extend_from_slice(&data[3..10]);
        if data[frames_end..total] != want[..] {
            return None;
        }
    }
    if major < 3 {
        return Some(Id3Tag { total, major, frames: Vec::new() });
    }

    let mut frames = Vec::new();
    let mut pos = id3v2_frames_start(data, frames_end, major)?;
    while pos + 10 <= frames_end {
        let frame_id = &data[pos..pos + 4];
        if frame_id == [0, 0, 0, 0] {
            break;
        }
        let frame_size = if major == 4 {
            id3v2_size(data, pos + 4)?
        } else {
            rd_u32(data, pos + 4, false)? as usize
        };
        let frame_start = pos + 10;
        let frame_end = frame_start.checked_add(frame_size)?;
        if frame_end > frames_end {
            return None;
        }
        frames.push((frame_id, &data[frame_start..frame_end]));
        pos = frame_end;
    }
    if data[pos..frames_end].iter().any(|&b| b != 0) {
        return None;
    }
    Some(Id3Tag { total, major, frames })
}

/// Port of `_inspect_id3v2`.
pub fn inspect_id3v2(data: &[u8]) -> Inspection {
    if data.len() >= 10 && &data[..3] == b"ID3" {
        let major = data[3];
        if let Some(ts) = id3v2_size(data, 6) {
            let total = 10 + ts;
            if total > data.len() {
                let hits = contains_any(data, &AI_META_HINTS);
                let has_c2pa = classify_c2pa(&hits);
                let mut findings = vec![format!(
                    "truncated ID3v2.{major} tag detected ({} bytes present, {total} declared) \u{2014} metadata may be incomplete",
                    data.len()
                )];
                if !hits.is_empty() {
                    findings.push(format!(
                        "partial ID3v2.{major} tag markers: {}",
                        join_first(&hits, 8)
                    ));
                }
                return (has_c2pa, !hits.is_empty(), findings);
            }
        }
    }

    let Some(tag) = parse_id3v2_frames(data) else {
        return (false, false, Vec::new());
    };
    let mut findings = Vec::new();
    let mut has_ai = false;
    let mut has_c2pa = false;

    if tag.frames.is_empty() {
        let hits = contains_any(slice_clamped(data, 0, tag.total), &AI_META_HINTS);
        if !hits.is_empty() {
            has_ai = true;
            has_c2pa = classify_c2pa(&hits);
            findings.push(format!("ID3v2.{} tag: {}", tag.major, join_first(&hits, 8)));
        }
        return (has_c2pa, has_ai, findings);
    }

    for (frame_id, payload) in &tag.frames {
        let hits = contains_any(payload, &AI_META_HINTS);
        if !hits.is_empty() {
            has_ai = true;
            if classify_c2pa(&hits) {
                has_c2pa = true;
            }
            findings.push(format!("ID3v2 frame {}: {}", latin1(frame_id), join_first(&hits, 8)));
        }
    }
    (has_c2pa, has_ai, findings)
}

/// Port of `_is_valid_mp3_frame_header`.
pub fn is_valid_mp3_frame_header(data: &[u8], offset: usize) -> bool {
    let Some(h) = offset.checked_add(4).and_then(|e| data.get(offset..e)) else {
        return false;
    };
    let (b0, b1, b2, b3) = (h[0], h[1], h[2], h[3]);
    if b0 != 0xFF || (b1 & 0xE0) != 0xE0 {
        return false;
    }
    let version = (b1 >> 3) & 0x03;
    let layer = (b1 >> 1) & 0x03;
    if version == 1 || layer == 0 {
        return false;
    }
    let bitrate_idx = (b2 >> 4) & 0x0F;
    if bitrate_idx == 0 || bitrate_idx == 0x0F {
        return false;
    }
    if (b2 >> 2) & 0x03 == 0x03 {
        return false;
    }
    b3 & 0x03 != 0x02
}

/// Port of `_strip_id3v2`.
pub fn strip_id3v2(data: &[u8], strip_all_metadata: bool) -> (Vec<u8>, Vec<String>) {
    if data.len() >= 10 && &data[..3] == b"ID3" {
        let major = data[3];
        if let Some(ts) = id3v2_size(data, 6) {
            let total = 10 + ts;
            if total > data.len() {
                let last = data.len().saturating_sub(3);
                let audio_pos = (10..last).find(|&i| is_valid_mp3_frame_header(data, i));
                return match audio_pos {
                    Some(p) => (
                        data[p..].to_vec(),
                        vec![format!(
                            "drop truncated ID3v2.{major} tag (found audio frame at offset {p})"
                        )],
                    ),
                    None => (
                        data.to_vec(),
                        vec![format!(
                            "cannot locate valid audio frame in truncated ID3v2.{major} tag; preserving file"
                        )],
                    ),
                };
            }
        }
    }

    let Some(tag) = parse_id3v2_frames(data) else {
        return (data.to_vec(), Vec::new());
    };
    let (total, major) = (tag.total, tag.major);
    let rest = &data[total..];

    if tag.frames.is_empty() {
        if !strip_all_metadata && contains_any(&data[..total], &AI_META_HINTS).is_empty() {
            return (
                data.to_vec(),
                vec!["no ID3v2 tag removed (no AI/C2PA markers found)".to_string()],
            );
        }
        return (rest.to_vec(), vec![format!("drop ID3v2.{major} tag ({total} bytes)")]);
    }

    if strip_all_metadata {
        return (rest.to_vec(), vec![format!("drop ID3v2.{major} tag ({total} bytes)")]);
    }

    let mut kept: Vec<u8> = Vec::new();
    let mut actions = Vec::new();
    for (frame_id, payload) in &tag.frames {
        let hits = contains_any(payload, &AI_META_HINTS);
        if !hits.is_empty() {
            actions.push(format!(
                "drop ID3v2 frame {}: {}",
                latin1(frame_id),
                join_first(&hits, 8)
            ));
            continue;
        }
        kept.extend_from_slice(frame_id);
        if major == 4 {
            kept.extend_from_slice(&id3v2_size_bytes(payload.len()));
        } else {
            kept.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        }
        kept.extend_from_slice(&[0, 0]);
        kept.extend_from_slice(payload);
    }

    if actions.is_empty() {
        return (
            data.to_vec(),
            vec!["no ID3v2 frames removed (already clean or none matched)".to_string()],
        );
    }

    let mut out = vec![b'I', b'D', b'3', major, 0, 0];
    out.extend_from_slice(&id3v2_size_bytes(kept.len()));
    out.extend_from_slice(&kept);
    out.extend_from_slice(rest);
    (out, actions)
}
