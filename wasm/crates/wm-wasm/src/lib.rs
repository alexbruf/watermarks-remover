//! WASM facade: the JS-facing API over the wm-* crates.
//!
//! Every function takes plain JS values (strings, Uint8Array, option objects)
//! and returns plain JSON-compatible objects, so the same build runs in
//! browsers, Cloudflare Workers, Deno and Node.

use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

fn to_js<T: Serialize>(value: &T) -> Result<JsValue, JsError> {
    value
        .serialize(&serde_wasm_bindgen::Serializer::json_compatible())
        .map_err(|e| JsError::new(&e.to_string()))
}

fn opts<T: for<'de> Deserialize<'de> + Default>(value: JsValue) -> Result<T, JsError> {
    if value.is_undefined() || value.is_null() {
        return Ok(T::default());
    }
    serde_wasm_bindgen::from_value(value).map_err(|e| JsError::new(&e.to_string()))
}

#[derive(Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct TextCleanOpts {
    nfkc: bool,
    aggressive_homoglyphs: bool,
    normalize_spaces: bool,
    strip_emoji_glue: bool,
    strip_bidi: bool,
}

impl Default for TextCleanOpts {
    fn default() -> Self {
        let d = wm_text::CleanOptions::default();
        Self {
            nfkc: d.nfkc,
            aggressive_homoglyphs: d.aggressive_homoglyphs,
            normalize_spaces: d.normalize_spaces,
            strip_emoji_glue: d.strip_emoji_glue,
            strip_bidi: d.strip_bidi,
        }
    }
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
struct TextInspectOpts {
    aggressive: bool,
    strip_emoji_glue: bool,
}

#[derive(Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct FileCleanOpts {
    strip_all_metadata: bool,
}

impl Default for FileCleanOpts {
    fn default() -> Self {
        Self { strip_all_metadata: true }
    }
}

/// Strip invisible Unicode / normalize exotic spaces. Returns `{text, stats}`.
#[wasm_bindgen(js_name = cleanText)]
pub fn clean_text(text: &str, options: JsValue) -> Result<JsValue, JsError> {
    let o: TextCleanOpts = opts(options)?;
    let out = wm_text::clean_text(
        text,
        &wm_text::CleanOptions {
            nfkc: o.nfkc,
            aggressive_homoglyphs: o.aggressive_homoglyphs,
            normalize_spaces: o.normalize_spaces,
            strip_emoji_glue: o.strip_emoji_glue,
            strip_bidi: o.strip_bidi,
        },
    );
    to_js(&out)
}

/// Report suspicious code points without changing the text.
#[wasm_bindgen(js_name = inspectText)]
pub fn inspect_text(text: &str, options: JsValue) -> Result<JsValue, JsError> {
    let o: TextInspectOpts = opts(options)?;
    let report = wm_text::inspect_text(
        text,
        &wm_text::InspectOptions { aggressive: o.aggressive, strip_emoji_glue: o.strip_emoji_glue },
    );
    to_js(&report)
}

/// Sniff the image format from magic bytes ("png", "jpeg", ..., "unknown").
#[wasm_bindgen(js_name = detectImageFormat)]
pub fn detect_image_format(data: &[u8]) -> String {
    wm_image::detect_format(data).to_string()
}

#[wasm_bindgen(js_name = inspectImage)]
pub fn inspect_image(data: &[u8]) -> Result<JsValue, JsError> {
    to_js(&wm_image::inspect_image(data))
}

/// Build `{data: Uint8Array, report}` for the clean* functions.
fn cleaned_file<R: Serialize>(data: &[u8], report: &R) -> Result<JsValue, JsError> {
    let obj = js_sys::Object::new();
    let set = |k: &str, v: &JsValue| {
        js_sys::Reflect::set(&obj, &JsValue::from_str(k), v)
            .map_err(|_| JsError::new("failed to build result object"))
    };
    set("data", &js_sys::Uint8Array::from(data).into())?;
    set("report", &to_js(report)?)?;
    Ok(obj.into())
}

/// Strip C2PA / AI metadata from an image. Returns `{data: Uint8Array, report}`.
#[wasm_bindgen(js_name = cleanImage)]
pub fn clean_image(data: &[u8], options: JsValue) -> Result<JsValue, JsError> {
    let o: FileCleanOpts = opts(options)?;
    let res = wm_image::clean_image(
        data,
        &wm_image::ImageCleanOptions { strip_all_metadata: o.strip_all_metadata },
    )
    .map_err(|e| JsError::new(&e.to_string()))?;
    cleaned_file(&res.cleaned, &res.report)
}
