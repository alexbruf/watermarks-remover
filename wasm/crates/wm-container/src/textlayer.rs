//! Layer A (invisible / format Unicode) helpers over `wm-text`.

use wm_text::{clean_text, inspect_text, CleanOptions, InspectOptions, TextInspectReport};

/// `clean_text(text, normalize_spaces=...)`; returns
/// `(text, removed_count, replaced_count)`.
pub fn clean(text: &str, normalize_spaces: bool) -> (String, usize, usize) {
    let opts = CleanOptions { normalize_spaces, ..CleanOptions::default() };
    let out = clean_text(text, &opts);
    (out.text, out.stats.removed_count, out.stats.replaced_count)
}

/// `inspect_text(text)`.
pub fn inspect(text: &str) -> TextInspectReport {
    inspect_text(text, &InspectOptions::default())
}
