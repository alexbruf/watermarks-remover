//! Replays tests/data/parity.json (recorded from service/scripts/image_meta.py
//! by tests/gen_parity.py) through the Rust crate: reports, actions and
//! sha256 of every strip output must match.

mod common;

use common::*;
use serde_json::Value;
use wm_image::*;

fn load() -> Value {
    let p = data_dir().join("parity.json");
    serde_json::from_slice(&std::fs::read(p).expect("parity.json (run tests/gen_parity.py)"))
        .expect("valid json")
}

fn input_bytes(spec: &Value) -> Vec<u8> {
    let mut b = read_data(spec["file"].as_str().unwrap());
    if let Some(edits) = spec.get("edits") {
        for e in edits.as_array().unwrap() {
            let off = e[0].as_u64().unwrap() as usize;
            b[off] = e[1].as_u64().unwrap() as u8;
        }
    }
    if let Some(n) = spec.get("len") {
        b.truncate(n.as_u64().unwrap() as usize);
    }
    b
}

fn strs(v: &[String]) -> Value {
    Value::Array(v.iter().map(|s| Value::String(s.clone())).collect())
}

/// Compare a recorded Python result against an `Option` Rust result; `Err`
/// strings describe the mismatch. Python exceptions other than ValueError
/// only require that Rust does not panic (the call returning is enough).
fn check_result(
    expected: &Value,
    got: Result<Vec<(&str, Value)>, ImageError>,
    skip: &[&str],
) -> Result<(), String> {
    if let Some(e) = expected.get("error") {
        let ty = e["type"].as_str().unwrap();
        if ty != "ValueError" {
            return Ok(());
        }
        return match got {
            Err(g) if g.0 == e["msg"].as_str().unwrap() => Ok(()),
            Err(g) => Err(format!("error msg {:?} != {:?}", g.0, e["msg"])),
            Ok(_) => Err(format!("python raised {e}, rust returned Ok")),
        };
    }
    let fields = got.map_err(|g| format!("rust returned Err({g}) but python succeeded"))?;
    for (k, v) in fields {
        if skip.contains(&k) {
            continue;
        }
        match expected.get(k) {
            None => {}
            Some(exp) if *exp == v => {}
            Some(exp) => return Err(format!("field {k}: expected {exp}, got {v}")),
        }
    }
    Ok(())
}

fn inspection_fields(i: Inspection) -> Result<Vec<(&'static str, Value)>, ImageError> {
    Ok(vec![
        ("has_c2pa", Value::Bool(i.0)),
        ("has_ai", Value::Bool(i.1)),
        ("findings", strs(&i.2)),
    ])
}

fn strip_fields(s: Stripped) -> Result<Vec<(&'static str, Value)>, ImageError> {
    let (out, actions) = s?;
    Ok(vec![
        ("sha256", Value::String(sha256_hex(&out))),
        ("n", Value::from(out.len())),
        ("actions", strs(&actions)),
    ])
}

fn run_inspector(name: &str, d: &[u8]) -> Inspection {
    match name {
        "png" => inspect_png(d),
        "jpeg" => inspect_jpeg(d),
        "webp" => inspect_webp(d),
        "avif" => inspect_isobmff(d, "avif"),
        "heic" => inspect_isobmff(d, "heic"),
        "bmp" => inspect_bmp(d),
        "gif" => inspect_gif(d),
        "tiff" => inspect_tiff(d),
        _ => panic!("inspector {name}"),
    }
}

fn run_stripper(name: &str, d: &[u8], all: bool) -> Stripped {
    match name {
        "png" => strip_png(d, all),
        "jpeg" => strip_jpeg(d, all),
        "webp" => strip_webp(d, all),
        "avif" => strip_isobmff(d, "avif", all),
        "heic" => strip_isobmff(d, "heic", all),
        "bmp" => strip_bmp(d, all),
        "gif" => strip_gif(d, all),
        "tiff" => strip_tiff(d, all),
        _ => panic!("stripper {name}"),
    }
}

fn check_case(case: &Value) -> Vec<String> {
    let id = case["id"].as_str().unwrap();
    let data = input_bytes(&case["input"]);
    let res = &case["result"];
    let mut fails = Vec::new();
    let mut fail = |what: &str, msg: String| fails.push(format!("{id}: {what}: {msg}"));

    if res["detect"].as_str().unwrap() != detect_format(&data) {
        fail("detect", format!("expected {} got {}", res["detect"], detect_format(&data)));
    }

    // inspect_image
    let ii = &res["inspect_image"];
    let rep = inspect_image(&data);
    let got = Ok(vec![
        ("format", Value::String(rep.format.clone())),
        ("has_c2pa", Value::Bool(rep.has_c2pa)),
        ("has_ai_metadata", Value::Bool(rep.has_ai_metadata)),
        ("findings", strs(&rep.findings)),
        ("findings_confidence", strs(&rep.findings_confidence)),
        ("notes", strs(&rep.notes)),
    ]);
    if let Err(m) = check_result(ii, got, &[]) {
        fail("inspect_image", m);
    }

    // per-format inspectors / strippers
    for (name, exp) in res["inspectors"].as_object().unwrap() {
        if let Err(m) = check_result(exp, inspection_fields(run_inspector(name, &data)), &[]) {
            fail(&format!("inspect_{name}"), m);
        }
    }
    for (key, exp) in res["strip"].as_object().unwrap() {
        let (name, mode) = key.rsplit_once('_').unwrap();
        let got = strip_fields(run_stripper(name, &data, mode == "all"));
        if let Err(m) = check_result(exp, got, &[]) {
            fail(&format!("strip_{key}"), m);
        }
    }

    // clean_image
    for (mode, exp) in res["clean"].as_object().unwrap() {
        let opts = ImageCleanOptions { strip_all_metadata: mode == "all" };
        let got = clean_image(&data, &opts).map(|r| {
            let rep = r.report;
            vec![
                ("format", Value::String(rep.format)),
                ("actions", strs(&rep.actions)),
                ("bytes_in", Value::from(rep.bytes_in)),
                ("bytes_out", Value::from(rep.bytes_out)),
                ("changed", Value::Bool(rep.changed)),
                ("still_has_c2pa", Value::Bool(rep.still_has_c2pa)),
                ("still_has_ai_metadata", Value::Bool(rep.still_has_ai_metadata)),
                ("post_findings", strs(&rep.post_findings)),
                ("sha256", Value::String(sha256_hex(&r.cleaned))),
            ]
        });
        if let Err(m) = check_result(exp, got, &[]) {
            fail(&format!("clean_{mode}"), m);
        }
    }
    fails
}

fn report(fails: Vec<String>, total: usize, what: &str) {
    if !fails.is_empty() {
        for f in fails.iter().take(25) {
            eprintln!("{f}");
        }
        panic!("{} of {total} {what} mismatched (first 25 shown)", fails.len());
    }
}

#[test]
fn base_cases_match_python() {
    let v = load();
    let cases = v["cases"].as_array().unwrap();
    assert!(cases.len() > 200);
    let fails: Vec<String> = cases.iter().flat_map(check_case).collect();
    report(fails, cases.len(), "base cases");
}

#[test]
fn truncated_and_mutated_cases_match_python() {
    let v = load();
    let cases = v["fuzz"].as_array().unwrap();
    assert!(cases.len() > 1000);
    let fails: Vec<String> = cases.iter().flat_map(check_case).collect();
    report(fails, cases.len(), "fuzz cases");
}

#[test]
fn zlib_bounded_matches_python() {
    use wm_image::zlib::{zlib_decompress_bounded, InflateError};
    let v = load();
    let cases = v["zlib"].as_array().unwrap();
    assert!(cases.len() > 500);
    let mut fails = Vec::new();
    for c in cases {
        let id = c["id"].as_str().unwrap();
        let input = unhex(c["hex"].as_str().unwrap());
        let exp = &c["expect"];
        let got = zlib_decompress_bounded(&input);
        let ok = match (&got, exp.get("ok"), exp.get("budget"), exp.get("corrupt")) {
            (Ok(out), Some(o), _, _) => {
                o["n"].as_u64().unwrap() as usize == out.len() && o["sha256"] == sha256_hex(out)
            }
            (Err(InflateError::BudgetExceeded), _, Some(_), _) => true,
            (Err(InflateError::Corrupt), _, _, Some(_)) => true,
            _ => false,
        };
        if !ok {
            fails.push(format!("{id}: expected {exp}, got {:?}", got.as_ref().map(|v| v.len())));
        }
    }
    report(fails, cases.len(), "zlib cases");
}

#[test]
fn repo_fixtures_are_in_sync() {
    // The two repo fixture images are copied into tests/data; make sure the
    // copies are still identical when the repo checkout is available.
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../tests/fixtures");
    for name in ["sample_c2pa.avif", "sample_c2pa.heic"] {
        let src = root.join(name);
        if let Ok(bytes) = std::fs::read(&src) {
            assert_eq!(bytes, read_data(&format!("fixture_{name}")), "{name} drifted; rerun gen_parity.py");
        }
    }
}

/// Every prefix of every stored input (incl. the repo fixtures) through every
/// function: nothing may panic.
#[test]
fn truncated_prefixes_never_panic() {
    let mut files: Vec<_> = std::fs::read_dir(data_dir())
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e != "json"))
        .collect();
    files.sort();
    assert!(files.len() > 200);
    let all_names = ["png", "jpeg", "webp", "avif", "heic", "bmp", "gif", "tiff"];
    let mut runs = 0usize;
    for path in files {
        let data = std::fs::read(&path).unwrap();
        let n = data.len();
        let step = (n / 120).max(1);
        let mut lens: Vec<usize> = (0..=n).step_by(step).collect();
        lens.push(n);
        for len in lens {
            let d = &data[..len];
            let _ = detect_format(d);
            let _ = inspect_image(d);
            for name in all_names {
                let _ = run_inspector(name, d);
                for all in [true, false] {
                    let _ = run_stripper(name, d, all);
                }
            }
            for all in [true, false] {
                let _ = clean_image(d, &ImageCleanOptions { strip_all_metadata: all });
            }
            runs += 1;
        }
    }
    assert!(runs > 5000);
}

/// Deterministic xorshift byte-mutation fuzz over every stored input: nothing
/// may panic (the parity fuzz cases above already pin Python-equal results for
/// a recorded subset).
#[test]
fn random_mutations_never_panic() {
    let mut files: Vec<_> = std::fs::read_dir(data_dir())
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e != "json"))
        .collect();
    files.sort();
    let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let all_names = ["png", "jpeg", "webp", "avif", "heic", "bmp", "gif", "tiff"];
    for path in files {
        let base = std::fs::read(&path).unwrap();
        if base.is_empty() {
            continue;
        }
        for _ in 0..25 {
            let mut d = base.clone();
            for _ in 0..(1 + next() % 4) {
                let i = (next() % d.len() as u64) as usize;
                d[i] = match next() % 4 {
                    0 => 0x00,
                    1 => 0xFF,
                    2 => 0x80,
                    _ => (next() & 0xFF) as u8,
                };
            }
            if next() % 3 == 0 {
                let cut = (next() % (d.len() as u64 + 1)) as usize;
                d.truncate(cut);
            }
            let _ = inspect_image(&d);
            for name in all_names {
                let _ = run_inspector(name, &d);
                let _ = run_stripper(name, &d, true);
                let _ = run_stripper(name, &d, false);
            }
            let _ = clean_image(&d, &ImageCleanOptions::default());
        }
    }
}
