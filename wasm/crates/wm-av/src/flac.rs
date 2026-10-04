//! FLAC: C2PA's standardized ID3v2 `GEOB` carrier only (native FLAC metadata
//! blocks are left untouched, as in the Python reference).

use crate::id3::*;
use crate::Inspection;

fn geob_text_end(payload: &[u8], start: usize, encoding: u8) -> Option<usize> {
    let step = if encoding == 0 || encoding == 3 { 1 } else { 2 };
    let mut pos = start;
    while pos + step <= payload.len() {
        if payload[pos..pos + step].iter().all(|&b| b == 0) {
            return Some(pos + step);
        }
        pos += step;
    }
    None
}

/// Port of `_is_c2pa_geob`.
pub fn is_c2pa_geob(frame_id: &[u8], payload: &[u8]) -> bool {
    if frame_id != b"GEOB" || payload.is_empty() || payload[0] >= 4 {
        return false;
    }
    let Some(rel) = payload.iter().skip(1).position(|&b| b == 0) else {
        return false;
    };
    let mime_end = rel + 1;
    if !payload[1..mime_end].eq_ignore_ascii_case(b"application/c2pa") {
        return false;
    }
    let Some(filename_end) = geob_text_end(payload, mime_end + 1, payload[0]) else {
        return false;
    };
    match geob_text_end(payload, filename_end, payload[0]) {
        Some(d) => d < payload.len(),
        None => false,
    }
}

pub fn inspect_flac(data: &[u8]) -> Inspection {
    let Some(tag) = parse_id3v2_frames(data) else {
        return (false, false, Vec::new());
    };
    if tag.frames.iter().any(|(id, p)| is_c2pa_geob(id, p)) {
        return (
            true,
            true,
            vec!["C2PA-related manifest in ID3v2 frame GEOB: application/c2pa".to_string()],
        );
    }
    (false, false, Vec::new())
}

pub fn strip_flac(data: &[u8], strip_all_metadata: bool) -> (Vec<u8>, Vec<String>) {
    let Some(tag) = parse_id3v2_frames(data) else {
        return (
            data.to_vec(),
            vec!["no FLAC ID3v2 metadata removed (already clean or none matched)".to_string()],
        );
    };
    let (total, major) = (tag.total, tag.major);
    let rest = &data[total..];
    if strip_all_metadata {
        return (rest.to_vec(), vec![format!("drop FLAC ID3v2.{major} tag ({total} bytes)")]);
    }

    let Some(mut pos) = id3v2_frames_start(data, total, major) else {
        return (
            data.to_vec(),
            vec!["no FLAC C2PA metadata removed (invalid ID3v2 extended header)".to_string()],
        );
    };
    let mut kept: Vec<u8> = Vec::new();
    let mut actions = Vec::new();
    for (frame_id, payload) in &tag.frames {
        let frame_end = pos + 10 + payload.len();
        if is_c2pa_geob(frame_id, payload) {
            actions.push("drop FLAC ID3v2 frame GEOB: application/c2pa".to_string());
        } else {
            kept.extend_from_slice(&data[pos..frame_end]);
        }
        pos = frame_end;
    }

    if actions.is_empty() {
        return (
            data.to_vec(),
            vec!["no FLAC C2PA metadata removed (already clean or none matched)".to_string()],
        );
    }
    if kept.is_empty() {
        return (rest.to_vec(), actions);
    }
    let mut out = data[..5].to_vec();
    out.push(data[5] & !0x50);
    out.extend_from_slice(&id3v2_size_bytes(kept.len()));
    out.extend_from_slice(&kept);
    out.extend_from_slice(rest);
    (out, actions)
}
