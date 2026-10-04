//! Replays tests/data/parity.json (recorded from service/scripts/av_meta.py
//! by tests/gen_parity.py) through the Rust crate: reports, actions and
//! sha256 of every strip output must match.

mod common;

use common::*;
use serde_json::{json, Value};
use wm_av::*;

fn load() -> Value {
    let p = data_dir().join("parity.json");
    serde_json::from_slice(&std::fs::read(p).expect("parity.json (run tests/gen_parity.py)"))
        .expect("valid json")
}

fn input_bytes(c: &Value) -> Vec<u8> {
    let mut b = read_data(c["file"].as_str().unwrap());
    if let Some(edits) = c.get("edits") {
        for e in edits.as_array().unwrap() {
            let off = e[0].as_u64().unwrap() as usize;
            b[off] = e[1].as_u64().unwrap() as u8;
        }
    }
    if let Some(n) = c.get("len") {
        b.truncate(n.as_u64().unwrap() as usize);
    }
    b
}

/// A Python exception other than ValueError only requires that Rust does not
/// panic; a ValueError requires the same message.
fn expect_err(exp: &Value) -> Option<(String, String)> {
    exp.get("error").map(|e| {
        (e["type"].as_str().unwrap().to_string(), e["msg"].as_str().unwrap().to_string())
    })
}

fn ins_json(t: (bool, bool, Vec<String>)) -> Value {
    json!({"c2pa": t.0, "ai": t.1, "findings": t.2})
}

fn strip_json(out: &[u8], actions: &[String], incomplete: Option<bool>) -> Value {
    let mut v = json!({"sha": sha256_hex(out), "len": out.len(), "actions": actions});
    if let Some(i) = incomplete {
        v["incomplete"] = json!(i);
    }
    v
}

fn cmp(name: &str, what: &str, exp: &Value, got: Value, fails: &mut Vec<String>) {
    if exp.get("error").is_some() {
        return; // python raised something other than a comparable result
    }
    if *exp != got {
        fails.push(format!("{name} [{what}]\n  py:   {exp}\n  rust: {got}"));
    }
}

#[test]
fn parity_json() {
    let root = load();
    let cases = root["cases"].as_array().unwrap();
    assert!(cases.len() > 1500, "too few cases: {}", cases.len());
    let mut fails: Vec<String> = Vec::new();
    for c in cases {
        let name = c["name"].as_str().unwrap();
        let d = input_bytes(c);
        let ctx = |w: &str| format!("{name}/{w}");

        assert_eq!(detect_av_format(&d), c["detect"].as_str().unwrap(), "{name} detect");

        let rep = serde_json::to_value(inspect_av(&d)).unwrap();
        cmp(name, "inspect", &c["inspect"], rep, &mut fails);

        for (key, all) in [("clean_all", true), ("clean_keep", false)] {
            let exp = &c[key];
            let res = clean_av(&d, &AvCleanOptions { strip_all_metadata: all });
            if let Some((ty, msg)) = expect_err(exp) {
                if ty == "ValueError" {
                    match &res {
                        Err(e) if e.0 == msg => {}
                        other => fails.push(format!("{} error mismatch: {other:?} vs {msg}", ctx(key))),
                    }
                }
                continue;
            }
            match res {
                Err(e) => fails.push(format!("{} rust Err({e}) but python Ok", ctx(key))),
                Ok(r) => {
                    let mut got = serde_json::to_value(&r.report).unwrap();
                    got["sha"] = json!(sha256_hex(&r.cleaned));
                    cmp(name, key, exp, got, &mut fails);
                }
            }
        }

        if let Some(dr) = c.get("direct") {
            let parsed = match parse_id3v2_frames(&d) {
                None => Value::Null,
                Some(t) => json!({
                    "total": t.total,
                    "major": t.major,
                    "frames": t.frames.iter()
                        .map(|(i, p)| json!([hex(i), sha256_hex(p), p.len()])).collect::<Vec<_>>(),
                }),
            };
            if dr["parse_id3"].get("error").is_none() && dr["parse_id3"] != parsed {
                fails.push(format!("{} py {} rust {parsed}", ctx("parse_id3"), dr["parse_id3"]));
            }
            cmp(name, "inspect_id3v2", &dr["inspect_id3v2"], ins_json(inspect_id3v2(&d)), &mut fails);
            cmp(name, "inspect_mp4", &dr["inspect_mp4"], ins_json(inspect_mp4(&d)), &mut fails);
            cmp(name, "inspect_wav", &dr["inspect_wav"], ins_json(inspect_wav(&d)), &mut fails);
            cmp(name, "inspect_flac", &dr["inspect_flac"], ins_json(inspect_flac(&d)), &mut fails);
            cmp(name, "inspect_udta", &dr["inspect_udta"], ins_json(inspect_moov_udta(&d)), &mut fails);
            for (i, all) in [true, false].into_iter().enumerate() {
                let (o, a) = strip_id3v2(&d, all);
                cmp(name, "strip_id3v2", &dr["strip_id3v2"][i], strip_json(&o, &a, None), &mut fails);
                let (o, a) = strip_wav(&d, all);
                let exp = &dr["strip_wav"][i];
                // python raises struct.error when the input is shorter than 8 bytes
                cmp(name, "strip_wav", exp, strip_json(&o, &a, None), &mut fails);
                let (o, a) = strip_flac(&d, all);
                cmp(name, "strip_flac", &dr["strip_flac"][i], strip_json(&o, &a, None), &mut fails);
                let (o, a, inc) = strip_moov_udta(&d, all);
                cmp(name, "strip_udta", &dr["strip_udta"][i], strip_json(&o, &a, Some(inc)), &mut fails);
                let exp = &dr["strip_mp4"][i];
                match (strip_mp4(&d, all), expect_err(exp)) {
                    (Ok((o, a, inc)), None) => {
                        cmp(name, "strip_mp4", exp, strip_json(&o, &a, Some(inc)), &mut fails)
                    }
                    (Err(e), Some((ty, msg))) if ty == "ValueError" && e.0 == msg => {}
                    (_, Some((ty, _))) if ty != "ValueError" => {}
                    (r, e) => fails.push(format!("{} mismatch {r:?} vs {e:?}", ctx("strip_mp4"))),
                }
            }
        }
    }
    assert!(fails.is_empty(), "{} parity failures, first 5:\n{}", fails.len(), fails.iter().take(5).cloned().collect::<Vec<_>>().join("\n"));
}

#[test]
fn parity_json_has_all_formats() {
    let root = load();
    let mut seen = std::collections::BTreeSet::new();
    for c in root["cases"].as_array().unwrap() {
        seen.insert(c["detect"].as_str().unwrap().to_string());
    }
    for f in ["mp4", "wav", "mp3", "flac", "unknown"] {
        assert!(seen.contains(f), "missing {f}");
    }
}
