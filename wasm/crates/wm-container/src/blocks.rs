//! Linear tag-block scanning (port of `_iter_tag_blocks`, `_drop_tag_blocks`,
//! `_drop_blocks_if`): every opening and closing tag is located once and paired
//! with a forward pointer, so the cost is O(n) whatever the input shape.

use regex::{bytes::Regex as BRegex, Regex};

/// `(open_start, open_end, close_start, close_end)`.
pub type Block = (usize, usize, usize, usize);

fn pair(opens: &[(usize, usize)], closes: &[(usize, usize)]) -> Vec<Block> {
    let mut out = Vec::new();
    let mut ci = 0usize;
    let mut last_end = 0usize;
    for &(os, oe) in opens {
        if os < last_end {
            continue;
        }
        while ci < closes.len() && closes[ci].0 < oe {
            ci += 1;
        }
        if ci >= closes.len() {
            break;
        }
        let (cs, ce) = closes[ci];
        out.push((os, oe, cs, ce));
        last_end = ce;
    }
    out
}

/// `_iter_tag_blocks` over a `str`.
pub fn iter_tag_blocks(text: &str, open: &Regex, close: &Regex) -> Vec<Block> {
    let closes: Vec<(usize, usize)> = close.find_iter(text).map(|m| (m.start(), m.end())).collect();
    let opens: Vec<(usize, usize)> = open.find_iter(text).map(|m| (m.start(), m.end())).collect();
    pair(&opens, &closes)
}

/// `_iter_tag_blocks` over bytes.
pub fn iter_tag_blocks_bytes(data: &[u8], open: &BRegex, close: &BRegex) -> Vec<Block> {
    let closes: Vec<(usize, usize)> = close.find_iter(data).map(|m| (m.start(), m.end())).collect();
    let opens: Vec<(usize, usize)> = open.find_iter(data).map(|m| (m.start(), m.end())).collect();
    pair(&opens, &closes)
}

/// `_drop_tag_blocks`: remove every open...close block.
pub fn drop_tag_blocks(text: &str, open: &Regex, close: &Regex) -> (String, usize) {
    drop_blocks_if(text, open, close, |_| true)
}

/// `_drop_blocks_if`: drop blocks whose full text satisfies `pred`.
pub fn drop_blocks_if(
    text: &str,
    open: &Regex,
    close: &Regex,
    mut pred: impl FnMut(&str) -> bool,
) -> (String, usize) {
    let mut out = String::new();
    let mut last = 0usize;
    let mut count = 0usize;
    for (os, _oe, _cs, ce) in iter_tag_blocks(text, open, close) {
        if !pred(&text[os..ce]) {
            continue;
        }
        out.push_str(&text[last..os]);
        last = ce;
        count += 1;
    }
    if count == 0 {
        return (text.to_string(), 0);
    }
    out.push_str(&text[last..]);
    (out, count)
}
