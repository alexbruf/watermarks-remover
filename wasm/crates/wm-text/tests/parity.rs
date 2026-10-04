//! Byte-for-byte parity with `service/scripts/text_unicode.py`, using
//! fixtures produced by `tests/gen_fixtures.py`.

use serde_json::Value;
use sha2::{Digest, Sha256};
use wm_text::{clean_text, human_report, inspect_text, CleanOptions, InspectOptions};

fn b(v: &Value, k: &str, default: bool) -> bool {
    v.get(k).and_then(Value::as_bool).unwrap_or(default)
}

fn clean_opts(v: &Value) -> CleanOptions {
    CleanOptions {
        nfkc: b(v, "nfkc", false),
        aggressive_homoglyphs: b(v, "aggressive_homoglyphs", false),
        normalize_spaces: b(v, "normalize_spaces", true),
        strip_emoji_glue: b(v, "strip_emoji_glue", false),
        strip_bidi: b(v, "strip_bidi", false),
    }
}

fn inspect_opts(v: &Value) -> InspectOptions {
    InspectOptions {
        aggressive: b(v, "aggressive", false),
        strip_emoji_glue: b(v, "strip_emoji_glue", false),
    }
}

fn fixtures() -> Value {
    serde_json::from_str(include_str!("fixtures.json")).expect("fixtures.json")
}

#[test]
fn clean_matches_python_fixtures() {
    let fx = fixtures();
    let meta = &fx["meta"];
    let mut checked = 0;
    for case in fx["cases"].as_array().unwrap() {
        let input = case["input"].as_str().unwrap();
        for (name, expected) in case["clean"].as_object().unwrap() {
            let opts = clean_opts(&meta["clean_combos"][name]);
            let got = clean_text(input, &opts);
            let ctx = format!("case {} combo {name} input {input:?}", case["id"]);
            assert_eq!(got.text, expected["text"].as_str().unwrap(), "text: {ctx}");
            assert_eq!(serde_json::to_value(&got.stats).unwrap(), expected["stats"], "stats: {ctx}");
            checked += 1;
        }
    }
    assert!(checked > 1500, "only {checked} clean comparisons");
}

#[test]
fn inspect_matches_python_fixtures() {
    let fx = fixtures();
    let meta = &fx["meta"];
    let mut checked = 0;
    for case in fx["cases"].as_array().unwrap() {
        let input = case["input"].as_str().unwrap();
        for (name, expected) in case["inspect"].as_object().unwrap() {
            let opts = inspect_opts(&meta["inspect_combos"][name]);
            let got = inspect_text(input, &opts);
            let ctx = format!("case {} combo {name} input {input:?}", case["id"]);
            assert_eq!(serde_json::to_value(&got).unwrap(), expected["report"], "report: {ctx}");
            assert_eq!(human_report(&got), expected["human"].as_str().unwrap(), "human: {ctx}");
            checked += 1;
        }
    }
    assert!(checked > 800, "only {checked} inspect comparisons");
}

#[test]
fn report_json_text_is_identical_for_key_order() {
    // Key order of the serialised report/stats equals Python's dict order.
    let r = inspect_text("a\u{200b}b", &InspectOptions::default());
    let s = serde_json::to_string(&r).unwrap();
    assert!(s.starts_with(r#"{"length":3,"suspicious_total":1,"hits":[{"codepoint":"U+200B","label":"U+200B ZERO WIDTH SPACE (Cf)","count":1,"kind":"zwj_family","confidence":"probable","sample_offsets":[1]}],"notes":["#));
    let c = clean_text("a\u{200b}\u{00a0}b", &CleanOptions::default());
    let s = serde_json::to_string(&c.stats).unwrap();
    assert_eq!(
        s,
        r#"{"input_length":4,"output_length":3,"removed":{"U+200B ZERO WIDTH SPACE (Cf)":1},"replaced":{"U+00A0 NO-BREAK SPACE (Zs)":1},"removed_count":1,"replaced_count":1,"nfkc_changed":false}"#
    );
}

/// Every code point (sans surrogates) in several contexts, hashed, vs Python.
#[test]
fn exhaustive_codepoint_sweep_matches_python() {
    let sweep: Value = serde_json::from_str(include_str!("sweep.json")).unwrap();
    let ranges: Vec<(u32, u32)> = sweep["ranges"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| (r[0].as_u64().unwrap() as u32, r[1].as_u64().unwrap() as u32))
        .collect();
    let strict = CleanOptions {
        strip_emoji_glue: true,
        aggressive_homoglyphs: true,
        strip_bidi: true,
        ..CleanOptions::default()
    };
    let insp = InspectOptions { aggressive: true, strip_emoji_glue: false };
    for (name, ctx) in sweep["contexts"].as_object().unwrap() {
        let (pre, post) = (ctx["pre"].as_str().unwrap(), ctx["post"].as_str().unwrap());
        let mut h = Sha256::new();
        for &(lo, hi) in &ranges {
            for cp in lo..hi {
                let Some(c) = char::from_u32(cp) else { continue };
                let t = format!("{pre}{c}{post}");
                for o in [CleanOptions::default(), strict] {
                    let out = clean_text(&t, &o);
                    let cps: Vec<String> = out.text.chars().map(|x| format!("{:X}", x as u32)).collect();
                    let st = serde_json::to_value(&out.stats).unwrap().to_string();
                    h.update(format!("{:X}\t{}\t{}\n", cp, cps.join(","), st).as_bytes());
                }
                let r = serde_json::to_value(inspect_text(&t, &insp)).unwrap();
                h.update(r["hits"].to_string().as_bytes());
            }
        }
        let got: String = h.finalize().iter().map(|x| format!("{x:02x}")).collect();
        assert_eq!(got, ctx["sha256"].as_str().unwrap(), "sweep context {name}");
    }
}
