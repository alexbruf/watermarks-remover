//! PNG: chunk walker, tEXt/zTXt/iTXt parsing, inspect and strip.

use crate::common::*;
use crate::zlib::{zlib_decompress_bounded, InflateError};

/// Decompressed PNG zTXt/iTXt exceeded [`MAX_PNG_TEXT_DECOMPRESSED_BYTES`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PngTextBudgetExceeded;

fn partition(b: &[u8], sep: u8) -> Option<(&[u8], &[u8])> {
    let i = b.iter().position(|&c| c == sep)?;
    Some((&b[..i], &b[i + 1..]))
}

fn inflate_text(data: &[u8]) -> Result<Option<Vec<u8>>, PngTextBudgetExceeded> {
    match zlib_decompress_bounded(data) {
        Ok(v) => Ok(Some(v)),
        Err(InflateError::Corrupt) => Ok(None),
        Err(InflateError::BudgetExceeded) => Err(PngTextBudgetExceeded),
    }
}

/// Parse a PNG text-chunk payload into (key, value) pairs (tEXt latin-1,
/// zTXt zlib text, iTXt UTF-8 optionally compressed). Malformed chunks yield
/// whatever is recoverable; over-budget compressed text is an `Err`.
pub fn png_text_entries(
    payload: &[u8],
    ctype: &[u8],
) -> Result<Vec<(String, String)>, PngTextBudgetExceeded> {
    let mut entries = Vec::new();
    if ctype == b"tEXt" {
        if let Some((key, text)) = partition(payload, 0) {
            entries.push((latin1(key), latin1(text)));
        }
    } else if ctype == b"zTXt" {
        let Some((key, rest)) = partition(payload, 0) else {
            return Ok(entries);
        };
        if rest.len() < 2 {
            return Ok(entries);
        }
        let Some(text) = inflate_text(&rest[1..])? else {
            return Ok(entries);
        };
        entries.push((latin1(key), latin1(&text)));
    } else if ctype == b"iTXt" {
        let Some((key, rest)) = partition(payload, 0) else {
            return Ok(entries);
        };
        if rest.len() < 4 {
            return Ok(entries);
        }
        let comp_flag = rest[0];
        let rest = &rest[2..];
        let Some((_lang, rest)) = partition(rest, 0) else {
            return Ok(entries);
        };
        let Some((_tkey, text)) = partition(rest, 0) else {
            return Ok(entries);
        };
        let text: Vec<u8> = if comp_flag == 1 {
            match inflate_text(text)? {
                Some(t) => t,
                None => return Ok(entries),
            }
        } else {
            text.to_vec()
        };
        entries.push((latin1(key), String::from_utf8_lossy(&text).into_owned()));
    }
    Ok(entries)
}

/// Python `str.strip()` (Unicode whitespace plus \x1c-\x1f).
fn py_strip(s: &str) -> &str {
    s.trim_matches(|c: char| c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c))
}

/// Product-name hits scoped to generator-bearing text-chunk keys, as labels
/// like `Software=ChatGPT`.
pub fn generator_product_hits(entries: &[(String, String)]) -> Vec<String> {
    let mut hits = Vec::new();
    for (key, value) in entries {
        let k = py_strip(key);
        let kl = k.to_lowercase();
        if !GENERATOR_TEXT_KEYS.contains(&kl.as_str()) {
            continue;
        }
        let low = value.to_lowercase();
        for product in AI_GENERATOR_PRODUCTS.iter() {
            let label = ascii_replace(product);
            if low.contains(&label.to_lowercase()) {
                hits.push(format!("{k}={label}"));
            }
        }
    }
    hits
}

/// Flat-marker hits and product-name hits from a PNG text chunk.
pub fn png_text_hits(
    payload: &[u8],
    ctype: &[u8],
) -> Result<(Vec<String>, Vec<String>), PngTextBudgetExceeded> {
    let entries = png_text_entries(payload, ctype)?;
    let decoded = entries.iter().map(|(_, v)| v.as_str()).collect::<Vec<_>>().join("\n");
    let mut blob = payload.to_vec();
    blob.push(b'\n');
    blob.extend_from_slice(decoded.as_bytes());
    let hits = contains_any_groups(&blob, &[&AI_META_HINTS, &C2PA_MARKERS]);
    Ok((hits, generator_product_hits(&entries)))
}

/// True when a PNG text chunk carries AI/C2PA markers.
pub fn text_chunk_is_ai(payload: &[u8], ctype: &[u8]) -> Result<bool, PngTextBudgetExceeded> {
    let (hits, products) = png_text_hits(payload, ctype)?;
    Ok(!hits.is_empty() || !products.is_empty())
}

/// Chunk geometry at `pos`: `(length, ctype, chunk_start, chunk_end)` or
/// `None` when the chunk (payload + CRC) overruns the data.
struct Chunk<'a> {
    length: u32,
    ctype: &'a [u8],
    start: usize,
    end: usize,
}

enum Next<'a> {
    Chunk(Chunk<'a>),
    Truncated(&'a [u8]),
}

fn next_chunk(data: &[u8], pos: usize) -> Next<'_> {
    let length = rd_u32(data, pos, false).unwrap_or(0);
    let ctype = &data[pos + 4..pos + 8];
    let start = pos + 8;
    let end64 = start as u64 + length as u64;
    if end64 + 4 > data.len() as u64 {
        return Next::Truncated(ctype);
    }
    Next::Chunk(Chunk { length, ctype, start, end: end64 as usize })
}

pub fn inspect_png(data: &[u8]) -> Inspection {
    let mut findings: Vec<String> = Vec::new();
    let mut has_c2pa = false;
    let mut has_ai = false;
    if !data.starts_with(PNG_SIG) {
        return (false, false, vec!["not a PNG".to_string()]);
    }
    let mut pos = 8usize;
    while pos + 8 <= data.len() {
        let ck = match next_chunk(data, pos) {
            Next::Truncated(ctype) => {
                findings.push(format!("truncated chunk {}", py_bytes_repr(ctype)));
                break;
            }
            Next::Chunk(c) => c,
        };
        let payload = &data[ck.start..ck.end];
        let ctype = ck.ctype;
        let name = latin1(ctype);
        if ctype == b"caBX" || ctype == b"juMB" || ctype == b"jumb" || ctype.starts_with(b"c2") {
            has_c2pa = true;
            findings.push(format!("PNG chunk {name} (possible C2PA container)"));
        }
        if ctype == b"tEXt" || ctype == b"zTXt" || ctype == b"iTXt" || ctype == b"eXIf" {
            let (hits, product_hits) = if ctype != b"eXIf" {
                match png_text_hits(payload, ctype) {
                    Ok(v) => v,
                    Err(PngTextBudgetExceeded) => {
                        findings.push(format!(
                            "PNG {name}: not fully inspected (decompressed text exceeds cap)"
                        ));
                        (Vec::new(), Vec::new())
                    }
                }
            } else {
                (contains_ai_or_c2pa(payload), Vec::new())
            };
            if !hits.is_empty() || !product_hits.is_empty() {
                has_ai = true;
                if any_lower_in(&hits, &["c2pa", "contentcredentials", "jumb"]) {
                    has_c2pa = true;
                }
                let mut parts: Vec<String> = Vec::new();
                if !hits.is_empty() {
                    parts.push(join_first(&hits, 8));
                }
                if !product_hits.is_empty() {
                    parts.push(format!("AI generator ({})", join_first(&product_hits, 8)));
                }
                findings.push(format!("PNG {name}: {}", parts.join("; ")));
            }
        }
        if ctype == b"IEND" {
            break;
        }
        pos = ck.end + 4;
    }
    let whole = contains_any(data, &C2PA_MARKERS);
    if !whole.is_empty() && !has_c2pa {
        has_c2pa = true;
        findings.push(format!("byte-scan C2PA markers: {}", join_first(&whole, 6)));
    }
    (has_c2pa, has_ai || has_c2pa, findings)
}

/// Port of `strip_png`. `strip_all_text` drops every tEXt/zTXt/iTXt chunk;
/// otherwise only those carrying AI/C2PA markers.
pub fn strip_png(data: &[u8], strip_all_text: bool) -> Stripped {
    if !data.starts_with(PNG_SIG) {
        return Err(ImageError::new("not PNG"));
    }
    let mut actions: Vec<String> = Vec::new();
    let mut out: Vec<u8> = PNG_SIG.to_vec();
    let mut pos = 8usize;
    while pos + 8 <= data.len() {
        let ck = match next_chunk(data, pos) {
            Next::Truncated(ctype) => {
                out.extend_from_slice(&data[pos..]);
                actions.push(format!(
                    "kept {} bytes of truncated chunk {} tail (file truncated)",
                    data.len() - pos,
                    latin1(ctype)
                ));
                break;
            }
            Next::Chunk(c) => c,
        };
        let payload = &data[ck.start..ck.end];
        let crc_bytes = &data[ck.end..ck.end + 4];
        let ctype = ck.ctype;
        pos = ck.end + 4;
        let name = latin1(ctype);

        let mut drop = false;
        if ctype == b"eXIf" || ctype == b"caBX" || ctype.starts_with(b"c2") {
            drop = true;
            actions.push(format!("drop chunk {name}"));
        } else if ctype == b"tEXt" || ctype == b"zTXt" || ctype == b"iTXt" {
            // `strip_all_text or _text_chunk_is_ai(...)` short-circuits.
            if strip_all_text {
                drop = true;
                actions.push(format!("drop chunk {name}"));
            } else {
                match text_chunk_is_ai(payload, ctype) {
                    Ok(v) => {
                        drop = v;
                        if drop {
                            actions.push(format!("drop chunk {name}"));
                        }
                    }
                    Err(PngTextBudgetExceeded) => {
                        drop = true;
                        actions.push(format!("drop chunk {name} (decompressed text exceeds cap)"));
                    }
                }
            }
        } else {
            let mut blob = ctype.to_vec();
            blob.extend_from_slice(payload);
            const STRUCTURAL: [&[u8]; 10] = [
                b"IHDR", b"IDAT", b"IEND", b"PLTE", b"tRNS", b"gAMA", b"pHYs", b"sRGB", b"cHRM",
                b"iCCP",
            ];
            if !contains_any(&blob, &C2PA_MARKERS).is_empty() && !STRUCTURAL.contains(&ctype) {
                drop = true;
                actions.push(format!("drop chunk {name} (C2PA marker in payload)"));
            }
        }

        if !drop {
            out.extend_from_slice(&ck.length.to_be_bytes());
            out.extend_from_slice(ctype);
            out.extend_from_slice(payload);
            out.extend_from_slice(crc_bytes);
        }
        if ctype == b"IEND" {
            break;
        }
    }
    if actions.is_empty() {
        actions.push("no PNG metadata chunks removed (already clean or none matched)".to_string());
    }
    Ok((out, actions))
}
