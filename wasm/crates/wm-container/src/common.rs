//! Shared tables, regexes and result types.

use regex::Regex;
use serde::Serialize;
use std::fmt;
use std::sync::LazyLock;
use wm_image::common::{
    ascii_replace, find_subslice, AI_GENERATOR_PRODUCTS, AI_META_HINTS, C2PA_MARKERS,
};

/// Declare a lazily compiled, process-wide regex.
#[macro_export]
macro_rules! re {
    ($name:ident, $pat:expr) => {
        pub(crate) static $name: std::sync::LazyLock<regex::Regex> =
            std::sync::LazyLock::new(|| regex::Regex::new($pat).expect("static regex is valid"));
    };
}

/// Error where the Python code raises. `kind` is the Python exception class
/// name (`ValueError`, `BadZipFile`, `RuntimeError`, `ZipBudgetExceeded`, ...)
/// and `message` is `str(exc)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerError {
    pub kind: &'static str,
    pub message: String,
}

impl ContainerError {
    pub fn new(kind: &'static str, message: impl Into<String>) -> Self {
        ContainerError { kind, message: message.into() }
    }
}

impl fmt::Display for ContainerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ContainerError {}

impl From<crate::zipio::ZipError> for ContainerError {
    fn from(e: crate::zipio::ZipError) -> Self {
        ContainerError { kind: e.class, message: e.message }
    }
}

impl From<crate::zipio::ZipFail> for ContainerError {
    fn from(e: crate::zipio::ZipFail) -> Self {
        match e {
            crate::zipio::ZipFail::Parse(z) => z.into(),
            crate::zipio::ZipFail::Budget(m) => ContainerError { kind: "ZipBudgetExceeded", message: m },
        }
    }
}

/// The Python `(has_c2pa, has_ai, findings, details)` tuple returned by every
/// `inspect_<format>` function.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct FormatInspection {
    pub has_c2pa: bool,
    pub has_ai_metadata: bool,
    pub findings: Vec<String>,
    pub details: serde_json::Value,
}

impl FormatInspection {
    pub fn new(has_c2pa: bool, has_ai: bool, findings: Vec<String>, details: serde_json::Value) -> Self {
        FormatInspection { has_c2pa, has_ai_metadata: has_ai, findings, details }
    }
    pub fn empty_details() -> serde_json::Value {
        serde_json::Value::Object(serde_json::Map::new())
    }
}

// ---------------------------------------------------------------------------
// Needle tables / regexes
// ---------------------------------------------------------------------------

pub(crate) static AI_META_NAME_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)generator|ai[-_ ]?generated|claude|anthropic|openai|gemini|synthid|c2pa|content.?credential|provenance|digital.?source|aigc",
    )
    .expect("static regex")
});

pub(crate) static AI_FREE_TEXT_MARKER_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)\bc2pa\b|\bcontent[-_ ]?credentials?\b|\bcontentauth\b|\bcai:|\bsynthid\b|\baigc\b|\bdigital[-_ ]?source[-_ ]?type\b|\b(?:trained[-_ ]?)?algorithmic[-_ ]?media\b|\b(?:generated|created|made|written|produced|authored)\s+(?:with|by|using)\b",
    )
    .expect("static regex")
});

pub const AI_FRONTMATTER_KEYS: [&str; 19] = [
    "generator",
    "ai",
    "ai_generated",
    "ai-generated",
    "claude",
    "anthropic",
    "openai",
    "gemini",
    "synthid",
    "c2pa",
    "content_credentials",
    "contentcredentials",
    "provenance",
    "digital_source_type",
    "digitalsourcetype",
    "created_with",
    "createdwith",
    "model",
    "llm",
];

pub const GENERATOR_NAME_KEYS: [&str; 27] = [
    "generator",
    "generated_by",
    "generatedby",
    "generated-by",
    "generated_with",
    "generatedwith",
    "generated-with",
    "created_with",
    "createdwith",
    "created-with",
    "made_with",
    "madewith",
    "made-with",
    "written_by",
    "writtenby",
    "written-by",
    "produced_by",
    "producedby",
    "produced-by",
    "authored_by",
    "authoredby",
    "authored-by",
    "creator",
    "producer",
    "software",
    "tool",
    "engine",
];

/// `named_value_is_ai(name, value)`.
pub fn named_value_is_ai(name: &str, value: &str) -> bool {
    let lname = name.to_lowercase();
    if GENERATOR_NAME_KEYS.contains(&lname.as_str()) {
        if AI_META_NAME_RE.is_match(value) {
            return true;
        }
        let lv = value.to_lowercase();
        return AI_GENERATOR_PRODUCTS.iter().any(|p| lv.contains(&ascii_replace(p).to_lowercase()));
    }
    AI_FREE_TEXT_MARKER_RE.is_match(value)
}

/// `_blob_hits(blob)`: `(has_c2pa, has_ai, findings)`.
pub fn blob_hits(blob: &[u8]) -> (bool, bool, Vec<String>) {
    let lower = blob.to_ascii_lowercase();
    let mut findings: Vec<String> = Vec::new();
    let mut has_c2pa = false;
    let mut has_ai = false;
    for n in C2PA_MARKERS.iter() {
        if find_subslice(&lower, &n.to_ascii_lowercase()).is_some() {
            has_c2pa = true;
            findings.push(format!("marker:{}", ascii_replace(n)));
        }
    }
    for n in AI_META_HINTS.iter() {
        if find_subslice(&lower, &n.to_ascii_lowercase()).is_some() {
            has_ai = true;
            let label = ascii_replace(n);
            let seen = findings.iter().any(|f| f.split_once(':').map_or(f.as_str(), |x| x.1) == label);
            if !seen {
                findings.push(format!("ai:{label}"));
            }
        }
    }
    findings.truncate(30);
    (has_c2pa, has_ai || has_c2pa, findings)
}

/// `', '.join(hits[:n])`.
pub fn join_first(hits: &[String], n: usize) -> String {
    hits.iter().take(n).cloned().collect::<Vec<_>>().join(", ")
}

/// The image-name pattern shared by the OOXML and EPUB media scans
/// (Python `$` also matches before a final newline).
pub(crate) static OOXML_MEDIA_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)^(?:word|xl|ppt)/media/.+\.(?:png|jpe?g|webp|avif|heic|gif|bmp|tiff?|svg)\n?\z")
        .expect("static regex")
});

pub(crate) static EPUB_MEDIA_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\.(?:png|jpe?g|webp|avif|heic|gif|bmp|tiff?|svg)\n?\z").expect("static regex")
});

/// Which image strippers/inspectors a dispatch site supports.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ImageSet {
    /// PNG, JPEG, WebP, AVIF/HEIC, SVG (data URIs).
    DataUri,
    /// Everything (OOXML / EPUB media parts).
    All,
}
