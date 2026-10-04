//! BMP: payload extent detection, trailing-metadata inspect and strip.

use crate::common::*;

/// Port of `_bmp_payload_extent`: `(pixel_offset, pixel_size)` or `None`.
///
/// Sizes are computed in 128-bit arithmetic because Python's integers cannot
/// overflow (`row_size * abs(height)` can exceed 64 bits for hostile headers).
pub fn bmp_payload_extent(data: &[u8]) -> Option<(u128, u128)> {
    if data.len() < 30 || &data[..2] != BMP_SIG {
        return None;
    }
    let pixel_offset = rd_u32(data, 10, true)? as u128;
    let dib_size = rd_u32(data, 14, true)? as u128;
    if dib_size < 40 || 14 + dib_size > data.len() as u128 {
        return None;
    }
    let width = rd_u32(data, 18, true)? as i32 as i128;
    let height = rd_u32(data, 22, true)? as i32 as i128;
    let bpp = rd_u16(data, 28, true)? as i128;
    let compression = rd_u32(data, 30, true)?;
    let size_image = rd_u32(data, 34, true)?;
    if width <= 0 || bpp == 0 || pixel_offset > data.len() as u128 {
        return None;
    }
    let size = if compression == 0 {
        let row_size = ((width * bpp + 31) / 32) * 4;
        (row_size * height.abs()) as u128
    } else if size_image != 0 {
        size_image as u128
    } else {
        return None;
    };
    Some((pixel_offset, size))
}

/// Bytes after the image payload (where non-standard BMP metadata lives).
pub fn bmp_trailing(data: &[u8]) -> &[u8] {
    match bmp_payload_extent(data) {
        None => &[],
        Some((off, size)) => {
            let end = off + size;
            if end < data.len() as u128 {
                &data[end as usize..]
            } else {
                &[]
            }
        }
    }
}

pub fn inspect_bmp(data: &[u8]) -> Inspection {
    let mut findings: Vec<String> = Vec::new();
    if data.len() < 14 || &data[..2] != BMP_SIG {
        return (false, false, vec!["not a BMP".to_string()]);
    }
    let trailing = bmp_trailing(data);
    let mut has_c2pa = false;
    let mut has_ai = false;
    if !trailing.is_empty() {
        let hits = contains_ai_or_c2pa(trailing);
        if !hits.is_empty() {
            has_ai = true;
            if any_lower_in(&hits, &["c2pa", "contentcredentials", "jumb", "contentauth"]) {
                has_c2pa = true;
            }
            findings.push(format!("BMP trailing metadata: {}", join_first(&hits, 6)));
        } else {
            findings.push(format!("BMP has {} unrecognized trailing byte(s)", trailing.len()));
        }
    } else {
        findings.push("BMP has no metadata (header-only raster format)".to_string());
    }
    (has_c2pa, has_ai || has_c2pa, findings)
}

pub fn strip_bmp(data: &[u8], strip_all_metadata: bool) -> Stripped {
    if data.len() < 14 || &data[..2] != BMP_SIG {
        return Err(ImageError::new("not BMP"));
    }
    let Some((off, size)) = bmp_payload_extent(data) else {
        return Ok((data.to_vec(), vec!["BMP header not fully parsed; left unchanged".to_string()]));
    };
    let end = off + size;
    if end >= data.len() as u128 {
        return Ok((data.to_vec(), vec!["no BMP trailing metadata to strip".to_string()]));
    }
    let end = end as usize;
    let trailing = &data[end..];
    let hits = contains_ai_or_c2pa(trailing);
    if !strip_all_metadata && hits.is_empty() {
        return Ok((data.to_vec(), vec!["BMP trailing bytes kept (keep-non-ai-metadata)".to_string()]));
    }
    let mut out = data[..end].to_vec();
    // `end < data.len()` so it fits in u32 for any sane file; guard anyway.
    let end32 = u32::try_from(end).unwrap_or(u32::MAX);
    out[2..6].copy_from_slice(&end32.to_le_bytes());
    let reason = if hits.is_empty() { String::new() } else { format!(" ({})", join_first(&hits, 4)) };
    Ok((out, vec![format!("drop {} BMP trailing byte(s){reason}", trailing.len())]))
}
