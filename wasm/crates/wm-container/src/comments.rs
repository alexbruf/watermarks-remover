//! HTML / Markdown provenance comments (`<!-- ... -->`).

use crate::blocks::{drop_blocks_if, iter_tag_blocks};
use crate::re;

re!(
    PROVENANCE_COMMENT,
    r"(?i)claude|anthropic|openai|chat\s?gpt|\bgpt-?\d|gemini|synthid|copilot|midjourney|dall.?e|stable.?diffusion|\bai[-_ ]?generated|c2pa|content.?credential"
);
re!(MARKUP_COMMENT_OPEN, r"<!--");
re!(MARKUP_COMMENT_CLOSE, r"--!?>");
re!(MD_FENCE, r"(?m)^[ \t]{0,3}(`{3,}|~{3,})([^\n]*)$");

pub fn comment_is_provenance(block: &str) -> bool {
    PROVENANCE_COMMENT.is_match(block)
}

/// `_md_prose_spans`: `[start, end)` spans of Markdown outside fenced code.
pub fn md_prose_spans(text: &str) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    let mut fence: Option<String> = None;
    let mut start = 0usize;
    for m in MD_FENCE.captures_iter(text) {
        let whole = m.get(0).expect("group 0");
        let marker = m.get(1).map_or("", |g| g.as_str());
        let suffix = m.get(2).map_or("", |g| g.as_str());
        match &fence {
            None => {
                if marker.starts_with('`') && suffix.contains('`') {
                    continue;
                }
                spans.push((start, whole.start()));
                fence = Some(marker.to_string());
            }
            Some(f) => {
                let same_kind = marker.as_bytes()[0] == f.as_bytes()[0];
                if same_kind
                    && marker.len() >= f.len()
                    && suffix.trim_matches(|c| c == ' ' || c == '\t' || c == '\r').is_empty()
                {
                    fence = None;
                    start = whole.end();
                }
            }
        }
    }
    if fence.is_none() {
        spans.push((start, text.len()));
    }
    spans
}

/// `_provenance_comments(text, spans)` (spans default: the whole text).
pub fn provenance_comments(text: &str, spans: Option<&[(usize, usize)]>) -> Vec<String> {
    let whole = [(0usize, text.len())];
    let spans = spans.unwrap_or(&whole);
    let mut found = Vec::new();
    for &(a, b) in spans {
        let seg = &text[a..b];
        for (os, _oe, _cs, ce) in iter_tag_blocks(seg, &MARKUP_COMMENT_OPEN, &MARKUP_COMMENT_CLOSE) {
            if comment_is_provenance(&seg[os..ce]) {
                found.push(seg[os..ce].to_string());
            }
        }
    }
    found
}

/// `_drop_provenance_comments(text, spans)`: `(text, count)`.
pub fn drop_provenance_comments(text: &str, spans: Option<&[(usize, usize)]>) -> (String, usize) {
    let whole = [(0usize, text.len())];
    let spans = spans.unwrap_or(&whole);
    let mut out = String::with_capacity(text.len());
    let mut total = 0usize;
    let mut last = 0usize;
    for &(a, b) in spans {
        out.push_str(&text[last..a]);
        let (new, n) = drop_blocks_if(&text[a..b], &MARKUP_COMMENT_OPEN, &MARKUP_COMMENT_CLOSE, comment_is_provenance);
        out.push_str(&new);
        total += n;
        last = b;
    }
    out.push_str(&text[last..]);
    (out, total)
}
