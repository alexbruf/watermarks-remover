//! ISOBMFF (AVIF/HEIC; also reusable for MP4/MOV): box parse/build helpers,
//! C2PA content-provenance box recognition, inspect and strip.

use crate::common::*;

pub const XMP_UUID: [u8; 16] = [
    0xbe, 0x7a, 0xcf, 0xcb, 0x97, 0xa9, 0x42, 0xe8, 0x9c, 0x71, 0x99, 0x94, 0x91, 0xe3, 0xaf, 0xac,
];

/// C2PA stores its manifest in BMFF containers as a top-level `uuid` box whose
/// user type is this ContentProvenanceBox UUID (`d8fec3d6-...`).
pub const C2PA_BMFF_UUID: [u8; 16] = [
    0xd8, 0xfe, 0xc3, 0xd6, 0x1b, 0x0e, 0x48, 0x3c, 0x92, 0x97, 0x58, 0x28, 0x87, 0x7e, 0xc4, 0x81,
];

/// One parsed box: the Python `(fourcc, payload, total_box_size, header_size)`.
#[derive(Debug, Clone, Copy)]
pub struct IsoBox<'a> {
    pub fourcc: [u8; 4],
    pub payload: &'a [u8],
    pub size: usize,
    pub header_size: usize,
}

/// Port of `_parse_isobmff_boxes`. Returns `(boxes, scanned_end)`:
/// `scanned_end` is where the walk stopped (the start of the first box that
/// could not be parsed, or `end` when the whole range parsed). `end` defaults
/// to `data.len()` (clamped to it).
pub fn parse_isobmff_boxes(
    data: &[u8],
    start: usize,
    end: Option<usize>,
) -> (Vec<IsoBox<'_>>, usize) {
    let end = end.unwrap_or(data.len()).min(data.len());
    let mut boxes = Vec::new();
    let mut pos = start;
    while pos.checked_add(8).is_some_and(|p| p <= end) {
        let mut size = rd_u32(data, pos, false).unwrap_or(0) as u64;
        let mut fourcc = [0u8; 4];
        fourcc.copy_from_slice(&data[pos + 4..pos + 8]);
        let mut header_size = 8usize;
        if size == 1 {
            if pos + 16 > end {
                break;
            }
            size = rd_u64(data, pos + 8, false).unwrap_or(0);
            header_size = 16;
        } else if size == 0 {
            size = (end - pos) as u64;
        }
        if size < header_size as u64 || size > (end - pos) as u64 {
            break;
        }
        let size = size as usize;
        boxes.push(IsoBox { fourcc, payload: &data[pos + header_size..pos + size], size, header_size });
        pos += size;
    }
    (boxes, pos)
}

/// Port of `_build_isobmff_box`: serialize a box preserving its header width.
pub fn build_isobmff_box(fourcc: &[u8; 4], payload: &[u8], header_size: usize) -> Vec<u8> {
    let size = payload.len() as u64 + header_size as u64;
    let mut out = Vec::with_capacity(payload.len() + header_size);
    if header_size == 16 {
        out.extend_from_slice(&1u32.to_be_bytes());
        out.extend_from_slice(fourcc);
        out.extend_from_slice(&size.to_be_bytes());
    } else {
        out.extend_from_slice(&(size.min(u32::MAX as u64) as u32).to_be_bytes());
        out.extend_from_slice(fourcc);
    }
    out.extend_from_slice(payload);
    out
}

/// Port of `_isobmff_free_box`: an equal-size `free` box so later absolute
/// offsets stay valid.
pub fn isobmff_free_box(size: usize, header_size: usize) -> Vec<u8> {
    build_isobmff_box(b"free", &vec![0u8; size.saturating_sub(header_size)], header_size)
}

/// True when a `uuid` box payload starts with the C2PA user type, at offset 0
/// or (after a 4-byte FullBox prefix) offset 4.
pub fn is_c2pa_bmff_prov_box(payload: &[u8]) -> bool {
    payload.get(..16) == Some(&C2PA_BMFF_UUID[..]) || payload.get(4..20) == Some(&C2PA_BMFF_UUID[..])
}

/// Port of `_contains_c2pa_prov_box`: whole-file fallback requiring the UUID
/// to follow a `uuid` fourcc (optionally after a 4-byte prefix).
pub fn contains_c2pa_prov_box(data: &[u8]) -> bool {
    let mut pos = 0usize;
    while let Some(idx) = find_subslice_from(data, b"uuid", pos) {
        let after = slice_clamped(data, idx + 4, idx + 24);
        if after.get(..16) == Some(&C2PA_BMFF_UUID[..]) || after.get(4..20) == Some(&C2PA_BMFF_UUID[..]) {
            return true;
        }
        pos = idx + 4;
    }
    false
}

/// `name.lower().startswith("c2")` for a fourcc.
pub fn fourcc_starts_with_c2(fourcc: &[u8; 4]) -> bool {
    fourcc[0].eq_ignore_ascii_case(&b'c') && fourcc[1] == b'2'
}

fn is_c2pa_box_type(fourcc: &[u8; 4]) -> bool {
    fourcc == b"jumb" || fourcc == b"c2pa" || fourcc_starts_with_c2(fourcc)
}

const C2PA_SET_4: [&str; 4] = ["c2pa", "contentcredentials", "jumb", "contentauth"];
const C2PA_SET_3: [&str; 3] = ["c2pa", "contentcredentials", "jumb"];

pub fn inspect_isobmff(data: &[u8], fmt: &str) -> Inspection {
    let mut findings: Vec<String> = Vec::new();
    let mut has_c2pa = false;
    let mut has_ai = false;
    let up = fmt.to_uppercase();

    let (boxes, scanned_end) = parse_isobmff_boxes(data, 0, None);
    if boxes.is_empty() {
        let whole = contains_any(data, &C2PA_MARKERS);
        if !whole.is_empty() {
            findings.push(format!("byte-scan C2PA markers: {}", join_first(&whole, 6)));
            has_c2pa = true;
        }
        findings.push(format!("not a valid {up} (no ISOBMFF boxes found)"));
        return (has_c2pa, has_ai || has_c2pa, findings);
    }

    for bx in &boxes {
        let (fourcc, payload) = (&bx.fourcc, bx.payload);
        let name = latin1(fourcc);
        if is_c2pa_box_type(fourcc) {
            has_c2pa = true;
            findings.push(format!("{up} top-level box {name} (C2PA/JUMBF manifest)"));
        } else if fourcc == b"uuid" {
            if payload.starts_with(&XMP_UUID) {
                has_ai = true;
                let hits = contains_ai_or_c2pa(&payload[16..]);
                if !hits.is_empty() {
                    findings.push(format!("{up} XMP uuid box: {}", join_first(&hits, 8)));
                } else {
                    findings.push(format!("{up} XMP uuid box"));
                }
                if any_lower_in(&hits, &C2PA_SET_4) {
                    has_c2pa = true;
                }
            } else if is_c2pa_bmff_prov_box(payload) {
                has_c2pa = true;
                findings.push(format!(
                    "{up} uuid box (C2PA content-provenance manifest, user type d8fec3d6...)"
                ));
            } else {
                let hits = contains_ai_or_c2pa(payload);
                if !hits.is_empty() {
                    has_ai = true;
                    findings.push(format!("{up} uuid box: {}", join_first(&hits, 8)));
                    if any_lower_in(&hits, &C2PA_SET_3) {
                        has_c2pa = true;
                    }
                }
            }
        } else if fourcc == b"meta" {
            let (meta_sub, _) = parse_isobmff_boxes(payload, 4, None);
            for sb in &meta_sub {
                let (s_fourcc, s_payload) = (&sb.fourcc, sb.payload);
                let s_name = latin1(s_fourcc);
                if is_c2pa_box_type(s_fourcc) {
                    has_c2pa = true;
                    findings.push(format!("{up} meta sub-box {s_name} (C2PA/JUMBF container)"));
                } else if s_fourcc == b"uuid" {
                    if s_payload.starts_with(&XMP_UUID) {
                        has_ai = true;
                        let hits = contains_ai_or_c2pa(&s_payload[16..]);
                        if !hits.is_empty() {
                            findings.push(format!("{up} meta XMP uuid: {}", join_first(&hits, 8)));
                        } else {
                            findings.push(format!("{up} meta XMP uuid box"));
                        }
                        if any_lower_in(&hits, &C2PA_SET_3) {
                            has_c2pa = true;
                        }
                    } else if is_c2pa_bmff_prov_box(s_payload) {
                        has_c2pa = true;
                        findings.push(format!(
                            "{up} meta uuid box (C2PA content-provenance manifest)"
                        ));
                    } else {
                        let hits = contains_ai_or_c2pa(s_payload);
                        if !hits.is_empty() {
                            has_ai = true;
                            findings.push(format!("{up} meta uuid: {}", join_first(&hits, 8)));
                        }
                    }
                } else if matches!(
                    s_fourcc.as_slice(),
                    b"iinf" | b"infe" | b"iref" | b"iloc" | b"xml " | b"bxml"
                ) {
                    let hits = contains_ai_or_c2pa(s_payload);
                    if !hits.is_empty() {
                        has_ai = true;
                        if any_lower_in(&hits, &C2PA_SET_3) {
                            has_c2pa = true;
                        }
                        findings.push(format!("{up} meta/{s_name}: {}", join_first(&hits, 8)));
                    }
                }
            }
        }
    }

    let whole = contains_any(data, &C2PA_MARKERS);
    if !whole.is_empty() && !has_c2pa && scanned_end < data.len() {
        has_c2pa = true;
        findings.push(format!("byte-scan C2PA markers: {}", join_first(&whole, 6)));
    } else if scanned_end < data.len() && contains_c2pa_prov_box(data) && !has_c2pa {
        has_c2pa = true;
        findings.push("byte-scan C2PA BMFF content-provenance user type".to_string());
    }

    (has_c2pa, has_ai || has_c2pa, findings)
}

pub fn strip_isobmff(data: &[u8], fmt: &str, strip_all_metadata: bool) -> Stripped {
    let (boxes, scanned_end) = parse_isobmff_boxes(data, 0, None);
    if boxes.is_empty() {
        return Err(ImageError(format!(
            "not a valid {} (no ISOBMFF boxes)",
            fmt.to_uppercase()
        )));
    }

    let mut actions: Vec<String> = Vec::new();
    let mut out: Vec<u8> = Vec::new();

    for bx in &boxes {
        let (fourcc, payload, size, header_size) = (&bx.fourcc, bx.payload, bx.size, bx.header_size);
        let name = latin1(fourcc);
        if is_c2pa_box_type(fourcc) {
            actions.push(format!("drop top-level {name} box (C2PA/JUMBF)"));
            out.extend(isobmff_free_box(size, header_size));
            continue;
        }

        if fourcc == b"uuid" {
            if payload.starts_with(&XMP_UUID) {
                actions.push(format!("drop top-level {name} box (XMP metadata)"));
                out.extend(isobmff_free_box(size, header_size));
                continue;
            }
            if is_c2pa_bmff_prov_box(payload) {
                actions.push(format!("drop top-level {name} box (C2PA content-provenance manifest)"));
                out.extend(isobmff_free_box(size, header_size));
                continue;
            }
            if strip_all_metadata || has_ai_or_c2pa(payload) {
                actions.push(format!("drop top-level {name} box (UUID metadata)"));
                out.extend(isobmff_free_box(size, header_size));
                continue;
            }
        }

        if fourcc == b"meta" {
            let meta_verflags: [u8; 4] = match payload.get(..4) {
                Some(v) => [v[0], v[1], v[2], v[3]],
                None => [0; 4],
            };
            let (sub_boxes, _) = parse_isobmff_boxes(payload, 4, None);
            let mut clean_sub: Vec<u8> = Vec::new();
            for sb in &sub_boxes {
                let (s_fourcc, s_payload, s_size, s_hdr) =
                    (&sb.fourcc, sb.payload, sb.size, sb.header_size);
                let s_name = latin1(s_fourcc);
                if is_c2pa_box_type(s_fourcc) {
                    actions.push(format!("drop meta sub-box {s_name} (C2PA/JUMBF)"));
                    clean_sub.extend(isobmff_free_box(s_size, s_hdr));
                    continue;
                }
                if s_fourcc == b"uuid" {
                    if s_payload.starts_with(&XMP_UUID) {
                        actions.push(format!("drop meta sub-box {s_name} (XMP metadata)"));
                        clean_sub.extend(isobmff_free_box(s_size, s_hdr));
                        continue;
                    }
                    if is_c2pa_bmff_prov_box(s_payload) {
                        actions.push(format!(
                            "drop meta sub-box {s_name} (C2PA content-provenance manifest)"
                        ));
                        clean_sub.extend(isobmff_free_box(s_size, s_hdr));
                        continue;
                    }
                    if strip_all_metadata || has_ai_or_c2pa(s_payload) {
                        actions.push(format!("drop meta sub-box {s_name} (UUID metadata)"));
                        clean_sub.extend(isobmff_free_box(s_size, s_hdr));
                        continue;
                    }
                }
                if (s_fourcc == b"xml " || s_fourcc == b"bxml")
                    && (strip_all_metadata || has_ai_or_c2pa(s_payload))
                {
                    actions.push(format!("drop meta sub-box {s_name} (XML metadata)"));
                    clean_sub.extend(isobmff_free_box(s_size, s_hdr));
                    continue;
                }
                clean_sub.extend(build_isobmff_box(s_fourcc, s_payload, s_hdr));
            }

            let mut new_meta_payload = meta_verflags.to_vec();
            new_meta_payload.extend(clean_sub);
            out.extend(build_isobmff_box(b"meta", &new_meta_payload, header_size));
            continue;
        }

        out.extend(build_isobmff_box(fourcc, payload, header_size));
    }

    if scanned_end < data.len() {
        let tail = &data[scanned_end..];
        out.extend_from_slice(tail);
        if tail.len() >= 8 {
            actions.push(format!("kept {} bytes of truncated tail (file truncated)", tail.len()));
        }
    }

    if actions.is_empty() {
        actions.push(format!(
            "no {} metadata boxes removed (already clean or none matched)",
            fmt.to_uppercase()
        ));
    }

    Ok((out, actions))
}
