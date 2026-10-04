//! SVG inspection and cleaning (`inspect_svg`, `clean_svg`).

use crate::blocks::{drop_blocks_if, drop_tag_blocks};
use crate::common::{blob_hits, FormatInspection, AI_META_NAME_RE};
use crate::datauri::{clean_embedded_data_uris, inspect_embedded_data_uris};
use crate::pyutil::{decode_replace, decode_surrogateescape, encode_surrogateescape, py_isalnum};
use crate::re;

re!(SVG_METADATA_OPEN, r"(?i)<metadata\b[^>]*>");
re!(SVG_METADATA_CLOSE, r"(?i)</metadata\s*>");
re!(SVG_XMPMETA_OPEN, r"(?i)<x:xmpmeta\b[^>]*>");
re!(SVG_XMPMETA_CLOSE, r"(?i)</x:xmpmeta\s*>");
re!(SVG_COMMENT_OPEN, r"<!--");
re!(SVG_COMMENT_CLOSE, r"--!?>");
re!(SVG_METADATA_PRESENT, r"(?i)<metadata[\s>]");
re!(SVG_XMP_RDF, r"(?i)xmpmeta|rdf:RDF|contentcredentials");
re!(SVG_C2PA_JUMBF, r"(?i)c2pa|jumbf");
re!(
    ROOT_ATTRS,
    r#"(?i)\s(?:inkscape:version|sodipodi:docname|generator)\s*=\s*("[^"]*"|'[^']*')"#
);

/// `inspect_svg(data)`.
pub fn inspect_svg(data: &[u8]) -> FormatInspection {
    let mut findings: Vec<String> = Vec::new();
    let (mut has_c2pa, mut has_ai, hits) = blob_hits(data);
    findings.extend(hits);
    let text = decode_replace(data);
    if SVG_METADATA_PRESENT.is_match(&text) {
        findings.push("svg <metadata> present".to_string());
        has_ai = true;
    }
    if SVG_XMP_RDF.is_match(&text) {
        has_ai = true;
        findings.push("XMP/RDF-like content in SVG".to_string());
    }
    if SVG_C2PA_JUMBF.is_match(&text) {
        has_c2pa = true;
    }
    let (uri_c2pa, uri_ai, uri_findings) = inspect_embedded_data_uris(&text);
    if uri_c2pa {
        has_c2pa = true;
    }
    if uri_ai {
        has_ai = true;
    }
    findings.extend(uri_findings);
    FormatInspection::new(has_c2pa, has_ai || has_c2pa, findings, FormatInspection::empty_details())
}

fn xml_decl_keyword(text: &str, i: usize) -> Option<&'static str> {
    let b = text.as_bytes();
    if b.get(i..i + 2) != Some(b"<!") {
        return None;
    }
    let rest = i + 2;
    for kw in ["doctype", "entity"] {
        if crate::pyutil::starts_with_ci(text, rest, kw) {
            if let Some(nxt) = crate::pyutil::char_at(text, rest + kw.len()) {
                if py_isalnum(nxt) || nxt == '_' || nxt == ':' {
                    return None;
                }
            }
            return Some(kw);
        }
    }
    None
}

fn xml_decl_end(text: &str, i: usize, keyword: &str) -> Option<usize> {
    let b = text.as_bytes();
    let n = b.len();
    let mut j = i + 2 + keyword.len();
    let mut quote: Option<u8> = None;
    let mut subset_depth = 0usize;
    while j < n {
        let c = b[j];
        if let Some(q) = quote {
            if c == q {
                quote = None;
            }
            j += 1;
            continue;
        }
        if b[j..].starts_with(b"<!--") {
            let end = text[j..].find("-->")?;
            j += end + 3;
            continue;
        }
        if c == b'"' || c == b'\'' {
            quote = Some(c);
            j += 1;
            continue;
        }
        if c == b'[' {
            subset_depth += 1;
            j += 1;
            continue;
        }
        if c == b']' {
            if subset_depth > 0 {
                subset_depth -= 1;
            }
            j += 1;
            continue;
        }
        if c == b'>' && subset_depth == 0 {
            return Some(j + 1);
        }
        j += 1;
    }
    None
}

/// `_strip_xml_declarations`.
fn strip_xml_declarations(text: &str) -> (String, usize) {
    let b = text.as_bytes();
    let n = b.len();
    let mut out: Vec<u8> = Vec::with_capacity(n);
    let mut removed = 0usize;
    let mut in_tag = false;
    let mut quote: Option<u8> = None;
    let mut i = 0usize;
    while i < n {
        let c = b[i];
        if in_tag {
            if let Some(q) = quote {
                out.push(c);
                if c == q {
                    quote = None;
                }
            } else if c == b'"' || c == b'\'' {
                quote = Some(c);
                out.push(c);
            } else if c == b'>' {
                in_tag = false;
                out.push(c);
            } else {
                out.push(c);
            }
            i += 1;
            continue;
        }
        if b[i..].starts_with(b"<![CDATA[") {
            match text[i..].find("]]>") {
                None => {
                    out.extend_from_slice(&b[i..]);
                    break;
                }
                Some(e) => {
                    let end = i + e;
                    out.extend_from_slice(&b[i..end + 3]);
                    i = end + 3;
                    continue;
                }
            }
        }
        if b[i..].starts_with(b"<!--") {
            match text[i..].find("-->") {
                None => {
                    out.extend_from_slice(&b[i..]);
                    break;
                }
                Some(e) => {
                    let end = i + e;
                    out.extend_from_slice(&b[i..end + 3]);
                    i = end + 3;
                    continue;
                }
            }
        }
        if let Some(kw) = xml_decl_keyword(text, i) {
            match xml_decl_end(text, i, kw) {
                None => {
                    out.push(c);
                    i += 1;
                    continue;
                }
                Some(end) => {
                    removed += 1;
                    i = end;
                    continue;
                }
            }
        }
        out.push(c);
        if c == b'<' {
            in_tag = true;
        }
        i += 1;
    }
    (String::from_utf8(out).unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned()), removed)
}

/// `_strip_root_svg_attrs`.
fn strip_root_svg_attrs(text: &str) -> (String, usize) {
    let b = text.as_bytes();
    let n = b.len();
    let mut i = 0usize;
    let mut start: Option<usize> = None;
    while i < n {
        if b[i..].starts_with(b"<![CDATA[") {
            match text[i..].find("]]>") {
                None => return (text.to_string(), 0),
                Some(e) => {
                    i += e + 3;
                    continue;
                }
            }
        }
        if b[i..].starts_with(b"<!--") {
            match text[i..].find("-->") {
                None => return (text.to_string(), 0),
                Some(e) => {
                    i += e + 3;
                    continue;
                }
            }
        }
        if b[i..].starts_with(b"<?") {
            match text[i..].find("?>") {
                None => return (text.to_string(), 0),
                Some(e) => {
                    i += e + 2;
                    continue;
                }
            }
        }
        if crate::pyutil::starts_with_ci(text, i, "<svg") {
            let ok = match crate::pyutil::char_at(text, i + 4) {
                Some(nxt) => !(py_isalnum(nxt) || matches!(nxt, '_' | ':' | '.' | '-')),
                None => true,
            };
            if ok {
                start = Some(i);
                break;
            }
        }
        i += 1;
    }
    let Some(start) = start else {
        return (text.to_string(), 0);
    };
    let mut j = start + 4;
    let mut quote: Option<u8> = None;
    let mut close: Option<usize> = None;
    while j < n {
        let c = b[j];
        if let Some(q) = quote {
            if c == q {
                quote = None;
            }
            j += 1;
            continue;
        }
        if c == b'"' || c == b'\'' {
            quote = Some(c);
            j += 1;
            continue;
        }
        if c == b'>' {
            close = Some(j);
            break;
        }
        j += 1;
    }
    let Some(j) = close else {
        return (text.to_string(), 0);
    };
    let tag = &text[start..=j];
    let cnt = ROOT_ATTRS.find_iter(tag).count();
    if cnt == 0 {
        return (text.to_string(), 0);
    }
    let new_tag = ROOT_ATTRS.replace_all(tag, "");
    (format!("{}{}{}", &text[..start], new_tag, &text[j + 1..]), cnt)
}

/// `clean_svg(data)`: `(cleaned_bytes, actions)`.
pub fn clean_svg(data: &[u8]) -> (Vec<u8>, Vec<String>) {
    let mut actions: Vec<String> = Vec::new();
    let mut text = decode_surrogateescape(data);
    let (new, n) = drop_tag_blocks(&text, &SVG_METADATA_OPEN, &SVG_METADATA_CLOSE);
    if n > 0 {
        actions.push(format!("drop <metadata> x{n}"));
        text = new;
    }
    let (new, n) = drop_tag_blocks(&text, &SVG_XMPMETA_OPEN, &SVG_XMPMETA_CLOSE);
    if n > 0 {
        actions.push(format!("drop xmpmeta x{n}"));
        text = new;
    }
    let (new, decl_count) = strip_xml_declarations(&text);
    text = new;
    if decl_count > 0 {
        actions.push(format!("drop DOCTYPE/entity declarations x{decl_count}"));
    }
    let (new, n) = drop_blocks_if(&text, &SVG_COMMENT_OPEN, &SVG_COMMENT_CLOSE, |b| {
        AI_META_NAME_RE.is_match(b)
    });
    if n > 0 {
        for _ in 0..n {
            actions.push("drop SVG comment with AI markers".to_string());
        }
        text = new;
    }
    let (new, uri_actions) = clean_embedded_data_uris(&text);
    text = new;
    actions.extend(uri_actions);
    let (new, n) = strip_root_svg_attrs(&text);
    text = new;
    if n > 0 {
        actions.push(format!("drop generator-like attrs x{n}"));
    }
    if actions.is_empty() {
        actions.push("no SVG metadata removed".to_string());
    }
    (encode_surrogateescape(&text), actions)
}
