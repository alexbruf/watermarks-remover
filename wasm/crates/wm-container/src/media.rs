//! Image dispatch shared by the data-URI, OOXML and EPUB code paths: route
//! bytes to the `wm-image` inspectors/strippers (or the SVG handlers).

use crate::common::blob_hits;
use crate::pyutil::bytes_lstrip;
use crate::svg::{clean_svg, inspect_svg};
use wm_image::{
    detect_format, inspect_bmp, inspect_gif, inspect_isobmff, inspect_jpeg, inspect_png,
    inspect_tiff, inspect_webp, strip_bmp, strip_gif, strip_isobmff, strip_jpeg, strip_png,
    strip_tiff, strip_webp,
};

fn looks_like_svg(data: &[u8]) -> bool {
    bytes_lstrip(data).starts_with(b"<")
}

/// Data-URI inspection dispatch (`_inspect_embedded_data_uris`).
pub fn inspect_data_uri_payload(data: &[u8], mime_l: &str) -> (bool, bool, Vec<String>) {
    let fmt = detect_format(data);
    match fmt {
        "png" => inspect_png(data),
        "jpeg" => inspect_jpeg(data),
        "webp" => inspect_webp(data),
        "avif" | "heic" => inspect_isobmff(data, fmt),
        _ if mime_l.contains("svg") || looks_like_svg(data) => {
            let r = inspect_svg(data);
            (r.has_c2pa, r.has_ai_metadata, r.findings)
        }
        _ => blob_hits(data),
    }
}

/// OOXML media-part inspection dispatch (`_inspect_ooxml_zip`).
pub fn inspect_media_part(raw: &[u8], name: &str) -> (bool, bool, Vec<String>) {
    let fmt = detect_format(raw);
    match fmt {
        "png" => inspect_png(raw),
        "jpeg" => inspect_jpeg(raw),
        "webp" => inspect_webp(raw),
        "avif" | "heic" => inspect_isobmff(raw, fmt),
        "gif" => inspect_gif(raw),
        "tiff" => inspect_tiff(raw),
        "bmp" => inspect_bmp(raw),
        _ if name.to_lowercase().ends_with(".svg") || looks_like_svg(raw) => {
            let r = inspect_svg(raw);
            (r.has_c2pa, r.has_ai_metadata, r.findings)
        }
        _ => (false, false, Vec::new()),
    }
}

/// Data-URI strip dispatch; `None` when the stripper raised (Python
/// `except Exception: return None`).
pub fn strip_data_uri_payload(data: &[u8], mime: &str) -> Option<(Vec<u8>, Vec<String>)> {
    let fmt = detect_format(data);
    let r = match fmt {
        "png" => strip_png(data, true),
        "jpeg" => strip_jpeg(data, true),
        "webp" => strip_webp(data, true),
        "avif" | "heic" => strip_isobmff(data, fmt, true),
        _ if mime.to_lowercase().contains("svg") || looks_like_svg(data) => Ok(clean_svg(data)),
        _ => Ok((data.to_vec(), Vec::new())),
    };
    r.ok()
}

/// OOXML / EPUB media strip dispatch. A stripper error leaves the part as is.
pub fn strip_media_part(raw: &[u8], name: &str) -> (Vec<u8>, Vec<String>) {
    let fmt = detect_format(raw);
    let r = match fmt {
        "png" => strip_png(raw, true),
        "jpeg" => strip_jpeg(raw, true),
        "webp" => strip_webp(raw, true),
        "avif" | "heic" => strip_isobmff(raw, fmt, true),
        "gif" => strip_gif(raw, true),
        "bmp" => strip_bmp(raw, true),
        "tiff" => strip_tiff(raw, true),
        _ if name.to_lowercase().ends_with(".svg") || looks_like_svg(raw) => Ok(clean_svg(raw)),
        _ => Ok((raw.to_vec(), Vec::new())),
    };
    r.unwrap_or_else(|_| (raw.to_vec(), Vec::new()))
}

/// The "did the strip actually change something" gate used by every caller:
/// `any("drop" in a.lower() for a in actions) and cleaned != raw`.
pub fn dropped_something(actions: &[String], cleaned: &[u8], raw: &[u8]) -> bool {
    actions.iter().any(|a| a.to_lowercase().contains("drop")) && cleaned != raw
}
