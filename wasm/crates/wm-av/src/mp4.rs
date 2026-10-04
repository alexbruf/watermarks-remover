//! MP4 / MOV / M4A / M4V: top-level C2PA/XMP handling reuses
//! `wm_image::isobmff`; `moov/udta` is handled here.

use wm_image::common::*;
use wm_image::isobmff::*;

use crate::{classify_c2pa, Inspection};

/// Port of `_inspect_moov_udta`.
pub fn inspect_moov_udta(data: &[u8]) -> Inspection {
    let (mut has_c2pa, mut has_ai) = (false, false);
    let mut findings = Vec::new();
    for b in parse_isobmff_boxes(data, 0, None).0 {
        if &b.fourcc != b"moov" {
            continue;
        }
        for s in parse_isobmff_boxes(b.payload, 0, None).0 {
            if &s.fourcc != b"udta" {
                continue;
            }
            let hits = contains_any(s.payload, &AI_META_HINTS);
            if !hits.is_empty() {
                has_ai = true;
                if classify_c2pa(&hits) {
                    has_c2pa = true;
                }
                findings.push(format!("MP4 moov/udta box: {}", join_first(&hits, 8)));
            }
        }
    }
    (has_c2pa, has_ai, findings)
}

/// Port of `_strip_moov_udta`: `(bytes, actions, inspection_incomplete)`.
pub fn strip_moov_udta(data: &[u8], strip_all_metadata: bool) -> (Vec<u8>, Vec<String>, bool) {
    let mut actions = Vec::new();
    let mut out: Vec<u8> = Vec::new();
    let (boxes, scanned_end) = parse_isobmff_boxes(data, 0, None);
    for b in &boxes {
        if &b.fourcc != b"moov" {
            out.extend(build_isobmff_box(&b.fourcc, b.payload, b.header_size));
            continue;
        }
        let mut new_moov: Vec<u8> = Vec::new();
        for s in parse_isobmff_boxes(b.payload, 0, None).0 {
            if &s.fourcc == b"udta"
                && (strip_all_metadata || !contains_any(s.payload, &AI_META_HINTS).is_empty())
            {
                actions.push("drop moov/udta box (generator/user-data tags)".to_string());
                new_moov.extend(isobmff_free_box(s.size, s.header_size));
                continue;
            }
            new_moov.extend(build_isobmff_box(&s.fourcc, s.payload, s.header_size));
        }
        out.extend(build_isobmff_box(b"moov", &new_moov, b.header_size));
    }
    out.extend_from_slice(&data[scanned_end..]);
    let incomplete = data.len() - scanned_end >= 8;
    (out, actions, incomplete)
}

pub fn inspect_mp4(data: &[u8]) -> Inspection {
    let (c, a, mut f) = inspect_isobmff(data, "mp4");
    let (uc, ua, uf) = inspect_moov_udta(data);
    f.extend(uf);
    (c || uc, a || ua, f)
}

pub fn strip_mp4(
    data: &[u8],
    strip_all_metadata: bool,
) -> Result<(Vec<u8>, Vec<String>, bool), crate::AvError> {
    let (cleaned, actions) = strip_isobmff(data, "mp4", strip_all_metadata)?;
    let (cleaned, udta_actions, incomplete) = strip_moov_udta(&cleaned, strip_all_metadata);
    let mut actions: Vec<String> =
        actions.into_iter().filter(|a| !a.starts_with("no MP4 metadata")).collect();
    actions.extend(udta_actions);
    if actions.is_empty() {
        actions = vec!["no MP4 metadata boxes removed (already clean or none matched)".to_string()];
    }
    Ok((cleaned, actions, incomplete))
}
