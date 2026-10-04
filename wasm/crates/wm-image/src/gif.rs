//! GIF: extension/image block walker, inspect and strip.

use crate::common::*;

/// `(end, label, payload)` for the extension block at `start` (0x21): the
/// payload is the concatenation of all sub-blocks; `end` is just past the
/// terminating 0x00.
pub fn gif_extension_info(data: &[u8], start: usize, n: usize) -> Option<(usize, u8, Vec<u8>)> {
    if start + 2 > n {
        return None;
    }
    let label = data[start + 1];
    let mut pos = start + 2;
    let mut payload = Vec::new();
    while pos < n {
        let size = data[pos] as usize;
        pos += 1;
        if size == 0 {
            return Some((pos, label, payload));
        }
        if pos + size > n {
            return None;
        }
        payload.extend_from_slice(&data[pos..pos + size]);
        pos += size;
    }
    None
}

/// Offset just past the image block starting at `start` (0x2C).
pub fn gif_image_end(data: &[u8], start: usize, n: usize) -> Option<usize> {
    let mut pos = start + 1;
    if pos + 9 > n {
        return None;
    }
    let packed = data[pos + 8];
    pos += 9;
    if packed & 0x80 != 0 {
        pos += 3 * (1usize << ((packed & 0x07) + 1));
    }
    if pos >= n {
        return None;
    }
    pos += 1; // LZW minimum code size
    while pos < n {
        let size = data[pos] as usize;
        pos += 1;
        if size == 0 {
            return Some(pos);
        }
        if pos + size > n {
            return None;
        }
        pos += size;
    }
    None
}

pub const GIF_XMP_APPLICATION_ID: &[u8] = b"XMP DataXMP";
/// Rendering-control application extensions that are kept on strip.
pub const GIF_CONTROL_APPLICATION_IDS: [&[u8]; 2] = [b"NETSCAPE2.0", b"ICCRGBG1012"];

fn is_gif(data: &[u8]) -> bool {
    data.len() >= 6 && GIF_SIGS.contains(&&data[..6])
}

pub fn inspect_gif(data: &[u8]) -> Inspection {
    let mut findings: Vec<String> = Vec::new();
    let mut has_c2pa = false;
    let mut has_ai = false;
    if !is_gif(data) {
        return (false, false, vec!["not a GIF".to_string()]);
    }
    let n = data.len();
    let mut pos = 6usize;
    if pos + 7 > n {
        return (false, false, vec!["truncated GIF header".to_string()]);
    }
    let packed = data[pos + 4];
    pos += 7;
    if packed & 0x80 != 0 {
        pos += 3 * (1usize << ((packed & 0x07) + 1));
    }
    while pos < n {
        let block = data[pos];
        if block == 0x3B {
            break;
        }
        if block == 0x21 {
            let Some((end, label, payload)) = gif_extension_info(data, pos, n) else {
                findings.push("truncated GIF extension".to_string());
                break;
            };
            if label == 0xFE {
                findings.push("GIF comment extension present".to_string());
                let hits = contains_ai_or_c2pa(&payload);
                if !hits.is_empty() {
                    has_ai = true;
                    findings.push(format!("GIF comment: {}", join_first(&hits, 6)));
                }
            } else if label == 0xFF {
                if payload.starts_with(GIF_XMP_APPLICATION_ID) {
                    findings.push("GIF XMP application extension present".to_string());
                    let hits = contains_ai_or_c2pa(&payload);
                    if !hits.is_empty() {
                        has_ai = true;
                        findings.push(format!("GIF XMP: {}", join_first(&hits, 6)));
                    }
                } else {
                    let head = &payload[..payload.len().min(11)];
                    if [&b"c2pa"[..], b"jumb", b"C2PA", b"JUMB"].iter().any(|m| contains_bytes(head, m)) {
                        has_c2pa = true;
                        findings.push("GIF application extension (possible C2PA)".to_string());
                    }
                }
            }
            pos = end;
        } else if block == 0x2C {
            let Some(end) = gif_image_end(data, pos, n) else {
                findings.push("truncated GIF image block".to_string());
                break;
            };
            pos = end;
        } else {
            pos += 1;
        }
    }
    let whole = contains_any(data, &C2PA_MARKERS);
    if !whole.is_empty() && !has_c2pa {
        has_c2pa = true;
        findings.push(format!("byte-scan C2PA markers: {}", join_first(&whole, 6)));
    }
    if findings.is_empty() {
        findings.push("no GIF metadata extensions found".to_string());
    }
    (has_c2pa, has_ai || has_c2pa, findings)
}

pub fn strip_gif(data: &[u8], strip_all_metadata: bool) -> Stripped {
    if !is_gif(data) {
        return Err(ImageError::new("not GIF"));
    }
    let mut actions: Vec<String> = Vec::new();
    let mut out: Vec<u8> = data[..6].to_vec();
    let n = data.len();
    let mut pos = 6usize;
    if pos + 7 > n {
        return Err(ImageError::new("truncated GIF header"));
    }
    let packed = data[pos + 4];
    out.extend_from_slice(&data[pos..pos + 7]);
    pos += 7;
    if packed & 0x80 != 0 {
        let gct_size = 3 * (1usize << ((packed & 0x07) + 1));
        out.extend_from_slice(slice_clamped(data, pos, pos + gct_size));
        pos += gct_size;
    }

    while pos < n {
        let block = data[pos];
        if block == 0x3B {
            out.extend_from_slice(&data[pos..]);
            break;
        }
        if block == 0x21 {
            let Some((end, label, payload)) = gif_extension_info(data, pos, n) else {
                out.extend_from_slice(&data[pos..]);
                break;
            };
            let mut drop = false;
            let mut name = "extension";
            if label == 0xFE {
                name = "comment";
                drop = strip_all_metadata || has_ai_or_c2pa(&payload);
            } else if label == 0xFF {
                let ident = &payload[..payload.len().min(11)];
                let marker_hit = has_ai_or_c2pa(&payload);
                if ident == GIF_XMP_APPLICATION_ID {
                    name = "XMP application";
                    drop = strip_all_metadata || marker_hit;
                } else if GIF_CONTROL_APPLICATION_IDS.contains(&ident) {
                    name = "control application";
                    drop = marker_hit;
                } else {
                    name = "application";
                    drop = strip_all_metadata || marker_hit;
                }
            }
            if drop {
                actions.push(format!("drop GIF {name} extension"));
            } else {
                out.extend_from_slice(&data[pos..end]);
            }
            pos = end;
        } else if block == 0x2C {
            let Some(end) = gif_image_end(data, pos, n) else {
                out.extend_from_slice(&data[pos..]);
                break;
            };
            out.extend_from_slice(&data[pos..end]);
            pos = end;
        } else {
            out.push(block);
            pos += 1;
        }
    }

    if actions.is_empty() {
        actions.push("no GIF metadata blocks removed (already clean or none matched)".to_string());
    }
    Ok((out, actions))
}
