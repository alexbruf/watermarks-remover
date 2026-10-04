//! Pure-Rust port of `service/scripts/av_meta.py`: detect and strip AI / C2PA
//! provenance metadata from MP4/MOV/M4A/M4V (ISOBMFF), WAV (RIFF), MP3
//! (ID3v2) and FLAC (ID3v2 GEOB C2PA carrier). Pure functions over `&[u8]`; no
//! filesystem, threads or subprocesses, and no panics on malformed input.
//! Reuses the ISOBMFF walker and needle tables from `wm-image`.
//!
//! # Differences from the Python reports
//!
//! Path-only fields are omitted: `path` on [`AvInspectReport`]; `input` and
//! `output` on [`AvCleanReport`]. `inspect_av(path)` / `clean_av(path, dest)`
//! (file read / `safe_write_bytes`) become byte-slice functions. The Python
//! `ValueError` messages are carried by [`AvError`]. The post-clean
//! re-inspection runs on the cleaned bytes (Python re-reads `dest`).

mod flac;
mod id3;
mod mp4;
mod wav;

use std::fmt;

use serde::Serialize;
use wm_image::common::classify_finding_confidence;
use wm_image::ImageError;

pub use flac::{inspect_flac, is_c2pa_geob, strip_flac};
pub use id3::{
    inspect_id3v2, is_valid_mp3_frame_header, parse_id3v2_frames, strip_id3v2, Id3Tag,
};
pub use mp4::{inspect_moov_udta, inspect_mp4, strip_moov_udta, strip_mp4};
pub use wav::{inspect_wav, strip_wav};

/// Recognised audio/video extensions (lower-case, with the dot).
pub const AV_EXTS: [&str; 7] = [".mp4", ".mov", ".m4a", ".m4v", ".wav", ".mp3", ".flac"];

/// `(has_c2pa, has_ai_metadata, findings)`.
pub type Inspection = (bool, bool, Vec<String>);

/// Where the Python raises `ValueError`; the message is the Python text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AvError(pub String);

impl fmt::Display for AvError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for AvError {}

impl From<ImageError> for AvError {
    fn from(e: ImageError) -> Self {
        AvError(e.0)
    }
}

pub(crate) fn classify_c2pa(hits: &[String]) -> bool {
    hits.iter().any(|h| {
        let l = h.to_lowercase();
        matches!(l.as_str(), "c2pa" | "contentcredentials" | "jumb" | "contentauth")
    })
}

/// Sniff `mp4 | wav | mp3 | flac | unknown` from magic bytes.
pub fn detect_av_format(data: &[u8]) -> &'static str {
    if data.len() >= 12 && &data[4..8] == b"ftyp" {
        return "mp4";
    }
    if data.len() >= 12 && &data[..4] == b"RIFF" && &data[8..12] == b"WAVE" {
        return "wav";
    }
    if data.starts_with(b"fLaC") {
        return "flac";
    }
    if data.len() >= 10 && &data[..3] == b"ID3" {
        if let Some(tag) = parse_id3v2_frames(data) {
            if data.get(tag.total..).is_some_and(|r| r.starts_with(b"fLaC")) {
                return "flac";
            }
        }
        return "mp3";
    }
    if data.len() >= 2 && data[0] == 0xFF && (data[1] & 0xE0) == 0xE0 {
        return "mp3";
    }
    "unknown"
}

/// Port of `AVInspectReport.to_dict()` (no `path`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AvInspectReport {
    pub format: String,
    pub has_c2pa: bool,
    pub has_ai_metadata: bool,
    pub findings: Vec<String>,
    pub findings_confidence: Vec<String>,
    pub notes: Vec<String>,
}

/// Port of `inspect_av` over bytes.
pub fn inspect_av(data: &[u8]) -> AvInspectReport {
    let fmt = detect_av_format(data);
    let (has_c2pa, has_ai, findings) = match fmt {
        "mp4" => inspect_mp4(data),
        "wav" => inspect_wav(data),
        "mp3" => inspect_id3v2(data),
        "flac" => inspect_flac(data),
        _ => (false, false, vec!["unsupported format (MP4/MOV/M4A/WAV/MP3/FLAC)".to_string()]),
    };
    let mut notes = Vec::new();
    if fmt == "unknown" {
        notes.push(
            "format not fully inspected; only MP4/MOV/M4A/WAV/MP3/FLAC are supported".to_string(),
        );
    }
    let findings_confidence =
        findings.iter().map(|f| classify_finding_confidence(f).to_string()).collect();
    AvInspectReport {
        format: fmt.to_string(),
        has_c2pa,
        has_ai_metadata: has_ai,
        findings,
        findings_confidence,
        notes,
    }
}

/// Options for [`clean_av`]; `strip_all_metadata: false` is keep-non-AI mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AvCleanOptions {
    pub strip_all_metadata: bool,
}

impl Default for AvCleanOptions {
    fn default() -> Self {
        AvCleanOptions { strip_all_metadata: true }
    }
}

/// Port of the dict returned by `clean_av` (no `input` / `output`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AvCleanReport {
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
pub struct AvCleanResult {
    pub cleaned: Vec<u8>,
    pub report: AvCleanReport,
}

/// Port of `clean_av`: detect, strip, then re-inspect the result.
pub fn clean_av(data: &[u8], opts: &AvCleanOptions) -> Result<AvCleanResult, AvError> {
    let all = opts.strip_all_metadata;
    let fmt = detect_av_format(data);
    let mut incomplete = false;
    let (cleaned, actions) = match fmt {
        "mp4" => {
            let (c, a, inc) = strip_mp4(data, all)?;
            incomplete = inc;
            (c, a)
        }
        "wav" => strip_wav(data, all),
        "mp3" => strip_id3v2(data, all),
        "flac" => strip_flac(data, all),
        _ => return Err(AvError(format!("unsupported audio/video format for cleaning: {fmt}"))),
    };
    let after = inspect_av(&cleaned);
    let mut post_findings = after.findings.clone();
    if incomplete {
        post_findings.push("MP4 not fully inspected: preserved a truncated top-level box tail".to_string());
    }
    let report = AvCleanReport {
        format: fmt.to_string(),
        actions,
        bytes_in: data.len(),
        bytes_out: cleaned.len(),
        changed: cleaned != data,
        still_has_c2pa: after.has_c2pa,
        still_has_ai_metadata: after.has_ai_metadata || incomplete,
        post_findings,
    };
    Ok(AvCleanResult { cleaned, report })
}
