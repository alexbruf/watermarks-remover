//! Pure-Rust port of the stdlib (non-subprocess, non-ML) parts of
//! `service/scripts/image_meta.py`: detect and strip C2PA / AI-related
//! metadata from PNG, JPEG, WebP, AVIF/HEIC (ISOBMFF), BMP, GIF and TIFF
//! (classic and BigTIFF). Pure functions over `&[u8]`; no filesystem, threads
//! or subprocesses, and no panics on malformed input.
//!
//! # Differences from the Python reports
//!
//! `run_optional_tools` (c2patool/exiftool), SynthID scoring, CtrlRegen,
//! MarkDiffusion and everything touching paths are intentionally not ported,
//! so the corresponding report fields are omitted: `path`, `tools`, `synthid`
//! on [`ImageInspectReport`]; `input`, `output`, `synthid_before`,
//! `synthid_after`, `pixel_removal` on [`ImageCleanReport`]. Consequently the
//! c2patool-derived finding ("c2patool reports a C2PA-related manifest") and
//! note ("c2patool unavailable ...") never appear, and the exiftool
//! `"exiftool -all= pass"` action is never added. The Rust results equal the
//! Python results with those tools stubbed out.

pub mod bmp;
pub mod common;
pub mod gif;
pub mod isobmff;
pub mod jpeg;
pub mod png;
pub mod tiff;
pub mod webp;
pub mod zlib;

use serde::Serialize;

pub use bmp::{inspect_bmp, strip_bmp};
pub use common::{
    classify_finding_confidence, contains_any, ImageError, Inspection, Stripped, AI_META_HINTS,
    C2PA_MARKERS,
};
pub use gif::{inspect_gif, strip_gif};
pub use isobmff::{inspect_isobmff, strip_isobmff};
pub use jpeg::{inspect_jpeg, strip_jpeg};
pub use png::{inspect_png, strip_png};
pub use tiff::{inspect_tiff, strip_tiff};
pub use webp::{inspect_webp, strip_webp};

use common::*;

/// Sniff the container format: `png | jpeg | webp | avif | heic | bmp | gif |
/// tiff | unknown`.
pub fn detect_format(data: &[u8]) -> &'static str {
    if data.starts_with(PNG_SIG) {
        return "png";
    }
    if data.starts_with(JPEG_SOI) {
        return "jpeg";
    }
    if data.len() >= 12 && &data[..4] == WEBP_RIFF && &data[8..12] == WEBP_SIG {
        return "webp";
    }
    if data.len() >= 12 && &data[4..8] == b"ftyp" {
        let box_size = rd_u32(data, 0, false).unwrap_or(0) as usize;
        let hi = if box_size >= 8 {
            box_size.min(data.len()).min(64)
        } else {
            data.len().min(64)
        };
        let header_chunk = slice_clamped(data, 8, hi);
        if [&b"avif"[..], b"avis", b"avio"].iter().any(|b| contains_bytes(header_chunk, b)) {
            return "avif";
        }
        if [&b"heic"[..], b"heix", b"hevc", b"heim", b"heis", b"mif1", b"msf1", b"heif"]
            .iter()
            .any(|b| contains_bytes(header_chunk, b))
        {
            return "heic";
        }
    }
    if data.starts_with(BMP_SIG) {
        return "bmp";
    }
    if data.len() >= 6 && GIF_SIGS.contains(&&data[..6]) {
        return "gif";
    }
    if [TIFF_LE_SIG, TIFF_BE_SIG, TIFF_LE_BIG_SIG, TIFF_BE_BIG_SIG]
        .iter()
        .any(|s| data.starts_with(s))
    {
        return "tiff";
    }
    "unknown"
}

/// Bytes-level port of `ImageInspectReport.to_dict()` (see crate docs for the
/// omitted tool fields).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ImageInspectReport {
    pub format: String,
    pub has_c2pa: bool,
    pub has_ai_metadata: bool,
    pub findings: Vec<String>,
    pub findings_confidence: Vec<String>,
    pub notes: Vec<String>,
}

/// Port of `inspect_image` over bytes.
pub fn inspect_image(data: &[u8]) -> ImageInspectReport {
    let fmt = detect_format(data);
    let (has_c2pa, has_ai, findings) = match fmt {
        "png" => inspect_png(data),
        "jpeg" => inspect_jpeg(data),
        "webp" => inspect_webp(data),
        "avif" | "heic" => inspect_isobmff(data, fmt),
        "bmp" => inspect_bmp(data),
        "gif" => inspect_gif(data),
        "tiff" => inspect_tiff(data),
        _ => (
            false,
            false,
            vec!["unsupported format (PNG/JPEG/WebP/AVIF/HEIC/BMP/GIF/TIFF)".to_string()],
        ),
    };
    let mut notes = Vec::new();
    if fmt == "unknown" {
        notes.push(
            "format not fully inspected; only PNG/JPEG/WebP/AVIF/HEIC/BMP/GIF/TIFF are supported"
                .to_string(),
        );
    }
    let findings_confidence =
        findings.iter().map(|f| classify_finding_confidence(f).to_string()).collect();
    ImageInspectReport {
        format: fmt.to_string(),
        has_c2pa,
        has_ai_metadata: has_ai,
        findings,
        findings_confidence,
        notes,
    }
}

/// Options for [`clean_image`]. `strip_all_metadata: false` is the Python
/// `--keep-non-ai-metadata` mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImageCleanOptions {
    pub strip_all_metadata: bool,
}

impl Default for ImageCleanOptions {
    fn default() -> Self {
        ImageCleanOptions { strip_all_metadata: true }
    }
}

/// Bytes-level port of the dict returned by `clean_image`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ImageCleanReport {
    pub format: String,
    pub actions: Vec<String>,
    pub bytes_in: usize,
    pub bytes_out: usize,
    pub changed: bool,
    pub still_has_c2pa: bool,
    pub still_has_ai_metadata: bool,
    pub post_findings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageCleanResult {
    pub cleaned: Vec<u8>,
    pub report: ImageCleanReport,
}

/// Port of `clean_image`: detect format, strip, then re-inspect the result.
/// Errors carry the Python `ValueError` message (unsupported format, or a
/// malformed file a stripper refuses, e.g. a WebP with a RIFF size mismatch).
pub fn clean_image(data: &[u8], opts: &ImageCleanOptions) -> Result<ImageCleanResult, ImageError> {
    let all = opts.strip_all_metadata;
    let fmt = detect_format(data);
    let (cleaned, actions) = match fmt {
        "png" => strip_png(data, all)?,
        "jpeg" => strip_jpeg(data, all)?,
        "webp" => strip_webp(data, all)?,
        "avif" | "heic" => strip_isobmff(data, fmt, all)?,
        "bmp" => strip_bmp(data, all)?,
        "gif" => strip_gif(data, all)?,
        "tiff" => strip_tiff(data, all)?,
        _ => return Err(ImageError(format!("unsupported format: {fmt}"))),
    };
    let after = inspect_image(&cleaned);
    let report = ImageCleanReport {
        format: fmt.to_string(),
        actions,
        bytes_in: data.len(),
        bytes_out: cleaned.len(),
        changed: cleaned != data,
        still_has_c2pa: after.has_c2pa,
        still_has_ai_metadata: after.has_ai_metadata,
        post_findings: after.findings,
    };
    Ok(ImageCleanResult { cleaned, report })
}
