//! Markdown / MDX frontmatter and provenance-comment handling.

use crate::comments::{drop_provenance_comments, md_prose_spans, provenance_comments};
use crate::common::{
    named_value_is_ai, FormatInspection, AI_FRONTMATTER_KEYS, AI_META_NAME_RE,
};
use crate::datauri::{clean_embedded_data_uris, inspect_embedded_data_uris};
use crate::pyutil::{py_prefix, py_strip, splitlines};
use crate::re;
use serde_json::json;

re!(FM, r"(?s)\A---\r?\n(.*?)\r?\n---\r?\n?");
re!(YAML_KEY, r"^([A-Za-z0-9_.-]+)\s*:");

const AGENT_CONFIG_KEYS: [&str; 5] = ["model", "tools", "allowed-tools", "name", "description"];

/// `_parse_simple_yaml_keys`: `(key, full_line)` for top-level keys.
fn parse_simple_yaml_keys(block: &str) -> Vec<(&str, &str)> {
    let mut rows = Vec::new();
    for line in splitlines(block) {
        let st = py_strip(line);
        if st.is_empty() || st.starts_with('#') {
            continue;
        }
        if matches!(line.as_bytes()[0], b' ' | b'\t' | b'-') {
            continue;
        }
        if let Some(m) = YAML_KEY.captures(line) {
            rows.push((m.get(1).map_or("", |g| g.as_str()), line));
        }
    }
    rows
}

fn is_agent_frontmatter(keys: &[&str]) -> bool {
    let lowered: Vec<String> = keys.iter().map(|k| k.to_lowercase()).collect();
    let has = |names: &[&str]| lowered.iter().any(|k| names.contains(&k.as_str()));
    has(&["name"]) && has(&["description"]) && has(&["tools", "allowed-tools"])
}

fn value_after_colon(line: &str) -> &str {
    line.split_once(':').map_or("", |x| x.1)
}

fn is_ai_key(key: &str) -> bool {
    AI_FRONTMATTER_KEYS.contains(&key.to_lowercase().as_str()) || AI_META_NAME_RE.is_match(key)
}

/// `inspect_markdown(text)`.
pub fn inspect_markdown(text: &str) -> FormatInspection {
    let mut findings: Vec<String> = Vec::new();
    let mut has_ai = false;
    let mut has_fm = false;
    let mut keys: Vec<String> = Vec::new();
    if let Some(m) = FM.captures(text) {
        has_fm = true;
        let block = m.get(1).map_or("", |g| g.as_str());
        let rows = parse_simple_yaml_keys(block);
        let names: Vec<&str> = rows.iter().map(|r| r.0).collect();
        let is_agent = is_agent_frontmatter(&names);
        for (key, line) in &rows {
            keys.push((*key).to_string());
            if is_agent && AGENT_CONFIG_KEYS.contains(&key.to_lowercase().as_str()) {
                // agent configuration, not provenance -- value still checked below
            } else if is_ai_key(key) {
                has_ai = true;
                findings.push(format!("frontmatter key: {key}"));
            }
            if named_value_is_ai(key, value_after_colon(line)) {
                has_ai = true;
                findings.push(format!("frontmatter value hit on {key}"));
            }
        }
    }
    let spans = md_prose_spans(text);
    for block in provenance_comments(text, Some(&spans)) {
        has_ai = true;
        findings.push(format!("comment: {}", py_prefix(&block, 120)));
    }
    let (uri_c2pa, uri_ai, uri_findings) = inspect_embedded_data_uris(text);
    if uri_c2pa || uri_ai {
        has_ai = true;
    }
    findings.extend(uri_findings);
    let c2pa = uri_c2pa
        || findings.iter().any(|f| {
            let l = f.to_lowercase();
            l.contains("c2pa") || l.contains("content")
        });
    FormatInspection::new(c2pa, has_ai, findings, json!({"has_frontmatter": has_fm, "keys": keys}))
}

/// `clean_markdown(text)`: `(text, actions)`.
pub fn clean_markdown(text: &str) -> (String, Vec<String>) {
    let mut actions: Vec<String> = Vec::new();
    let mut out: String;
    if let Some(m) = FM.captures(text) {
        let whole = m.get(0).expect("group 0");
        let block = m.get(1).map_or("", |g| g.as_str());
        let body = &text[whole.end()..];
        let mut kept: Vec<&str> = Vec::new();
        let mut dropping = false;
        let rows = parse_simple_yaml_keys(block);
        let names: Vec<&str> = rows.iter().map(|r| r.0).collect();
        let is_agent = is_agent_frontmatter(&names);
        for line in splitlines(block) {
            let stripped = py_strip(line);
            if stripped.is_empty() || stripped.starts_with('#') {
                if !dropping {
                    kept.push(line);
                }
                continue;
            }
            if matches!(line.as_bytes()[0], b' ' | b'\t' | b'-') {
                if !dropping {
                    kept.push(line);
                }
                continue;
            }
            let Some(km) = YAML_KEY.captures(line) else {
                dropping = false;
                kept.push(line);
                continue;
            };
            let key = km.get(1).map_or("", |g| g.as_str());
            let val = value_after_colon(line);
            if is_agent && AGENT_CONFIG_KEYS.contains(&key.to_lowercase().as_str()) {
                // fall through to the value check
            } else if is_ai_key(key) {
                actions.push(format!("drop frontmatter key: {key}"));
                dropping = true;
                continue;
            }
            if named_value_is_ai(key, val) {
                actions.push(format!("drop frontmatter key (value hit): {key}"));
                dropping = true;
                continue;
            }
            dropping = false;
            kept.push(line);
        }
        let joined = kept.join("\n");
        let new_block = joined.trim_matches('\n');
        if !new_block.is_empty() {
            out = format!("---\n{new_block}\n---\n{body}");
        } else {
            out = body.trim_start_matches('\n').to_string();
            actions.push("removed empty frontmatter block".to_string());
        }
    } else {
        out = text.to_string();
    }

    let spans = md_prose_spans(&out);
    let (new, n) = drop_provenance_comments(&out, Some(&spans));
    out = new;
    if n > 0 {
        actions.push(format!("drop AI provenance comment x{n}"));
    }
    let (new, uri_actions) = clean_embedded_data_uris(&out);
    out = new;
    actions.extend(uri_actions);
    if actions.is_empty() {
        actions.push("no AI frontmatter keys or embedded data URIs removed".to_string());
    }
    (out, actions)
}
