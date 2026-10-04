//! Ports of the relevant cases from tests/test_clean_image.py,
//! test_image_formats_bmp_gif_tiff.py, test_avif_heic.py,
//! test_isobmff_truncated_bytescan.py and test_ai_generator_hints.py.

mod common;

use common::*;
use wm_image::common::AI_GENERATOR_PRODUCTS;
use wm_image::isobmff::XMP_UUID;
use wm_image::*;

fn has(v: &[String], needle: &str) -> bool {
    v.iter().any(|f| f.contains(needle))
}

// ---------------------------------------------------------------------------
// builders
// ---------------------------------------------------------------------------

fn png_chunk(ctype: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut v = (payload.len() as u32).to_be_bytes().to_vec();
    v.extend_from_slice(ctype);
    v.extend_from_slice(payload);
    v.extend_from_slice(&crc32(&[ctype, payload]).to_be_bytes());
    v
}

fn png_with_chunk(ctype: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut ihdr = Vec::new();
    ihdr.extend_from_slice(&1u32.to_be_bytes());
    ihdr.extend_from_slice(&1u32.to_be_bytes());
    ihdr.extend_from_slice(&[8, 2, 0, 0, 0]);
    let mut v = b"\x89PNG\r\n\x1a\n".to_vec();
    v.extend(png_chunk(b"IHDR", &ihdr));
    v.extend(png_chunk(ctype, payload));
    v.extend(png_chunk(b"IDAT", &zlib_store(b"\x00\x00\x00")));
    v.extend(png_chunk(b"IEND", b""));
    v
}

fn text(key: &str, value: &str) -> Vec<u8> {
    let mut v = key.as_bytes().to_vec();
    v.push(0);
    v.extend_from_slice(value.as_bytes());
    v
}

fn png_text(key: &str, value: &str) -> Vec<u8> {
    png_with_chunk(b"tEXt", &text(key, value))
}

fn jpeg_1x1() -> Vec<u8> {
    read_data("jpeg_1x1.jpg")
}

fn jseg(marker: u8, payload: &[u8]) -> Vec<u8> {
    let mut v = vec![0xFF, marker];
    v.extend_from_slice(&((payload.len() + 2) as u16).to_be_bytes());
    v.extend_from_slice(payload);
    v
}

fn jpeg_with_comment(comment: &[u8]) -> Vec<u8> {
    let base = jpeg_1x1();
    let mut v = base[..2].to_vec();
    v.extend(jseg(0xFE, comment));
    v.extend_from_slice(&base[2..]);
    v
}

fn jpeg_comments(data: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut pos = 2;
    while pos + 4 <= data.len() {
        assert_eq!(data[pos], 0xFF);
        let marker = data[pos + 1];
        pos += 2;
        if marker == 0xD9 || marker == 0xDA {
            break;
        }
        let len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        if marker == 0xFE {
            out.push(data[pos + 2..pos + len].to_vec());
        }
        pos += len;
    }
    out
}

fn minimal_jpeg_with_app11() -> Vec<u8> {
    let mut v = b"\xff\xd8".to_vec();
    v.extend(jseg(0xE0, b"JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"));
    v.extend(jseg(0xEB, b"JUMBc2pa-manifest-fake"));
    v.extend(jseg(0xDA, b"\x03\x01\x00\x02\x11\x03\x11\x00\x3f\x00"));
    v.extend_from_slice(b"\x00\x00\xff\xd9");
    v
}

fn webp_chunk(fourcc: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut v = fourcc.to_vec();
    v.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    v.extend_from_slice(payload);
    if payload.len() & 1 == 1 {
        v.push(0);
    }
    v
}

fn minimal_webp(chunks: &[(&[u8], &[u8])]) -> Vec<u8> {
    let mut body = b"WEBP".to_vec();
    for (f, p) in chunks {
        body.extend(webp_chunk(f, p));
    }
    let mut v = b"RIFF".to_vec();
    v.extend_from_slice(&(body.len() as u32).to_le_bytes());
    v.extend(body);
    v
}

fn bx(fourcc: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut v = ((payload.len() + 8) as u32).to_be_bytes().to_vec();
    v.extend_from_slice(fourcc);
    v.extend_from_slice(payload);
    v
}

fn full_box(fourcc: &[u8], version: u32, flags: u32, payload: &[u8]) -> Vec<u8> {
    let mut p = ((version << 24) | (flags & 0xFFFFFF)).to_be_bytes().to_vec();
    p.extend_from_slice(payload);
    bx(fourcc, &p)
}

fn hdlr() -> Vec<u8> {
    let mut p = b"\x00\x00\x00\x00pict".to_vec();
    p.extend_from_slice(&[0u8; 12]);
    p.extend_from_slice(b"PictureHandler\x00");
    full_box(b"hdlr", 0, 0, &p)
}

fn minimal_avif_with_c2pa_and_xmp() -> Vec<u8> {
    let ftyp = bx(b"ftyp", b"avif\x00\x00\x00\x00avifmif1");
    let jumb_sub = bx(b"jumb", b"c2pa.manifest.store.v1");
    let mut xmp = XMP_UUID.to_vec();
    xmp.extend_from_slice(b"<?xpacket begin='' id='W5M0MpCehiHzreSzNTczkc9d'?><x:xmpmeta xmlns:x='adobe:ns:meta/'><rdf:RDF xmlns:rdf='http://www.w3.org/1999/02/22-rdf-syntax-ns#'><rdf:Description rdf:about='' xmlns:ai='http://ns.adobe.com/ai/'><ai:GeneratedBy>Midjourney</ai:GeneratedBy></rdf:Description></rdf:RDF></x:xmpmeta>");
    let xmp_sub = bx(b"uuid", &xmp);
    let mut meta_payload = hdlr();
    meta_payload.extend(jumb_sub);
    meta_payload.extend(xmp_sub);
    let meta = full_box(b"meta", 0, 0, &meta_payload);
    let top_jumb = bx(b"jumb", b"c2pa.claim.v1 contentcredentials");
    let mdat = bx(b"mdat", b"\x00\x01\x02\x03\x04\x05image_pixel_data");
    [ftyp, meta, top_jumb, mdat].concat()
}

fn minimal_heic_with_xmp() -> Vec<u8> {
    let ftyp = bx(b"ftyp", b"heic\x00\x00\x00\x00mif1heic");
    let mut xmp = XMP_UUID.to_vec();
    xmp.extend_from_slice(b"<x:xmpmeta xmlns:x='adobe:ns:meta/'><rdf:RDF><rdf:Description digitalSourceType='trainedAlgorithmicMedia'/></rdf:RDF></x:xmpmeta>");
    let xmp_uuid = bx(b"uuid", &xmp);
    let meta = full_box(b"meta", 0, 0, &hdlr());
    let mdat = bx(b"mdat", b"\xaa\xbb\xcc\xddhevc_stream");
    [ftyp, meta, xmp_uuid, mdat].concat()
}

fn minimal_bmp(trailing: &[u8]) -> Vec<u8> {
    let pixel = [0u8, 0, 0xff, 0xff];
    let mut dib = Vec::new();
    for v in [40u32, 1, 1] {
        dib.extend_from_slice(&v.to_le_bytes());
    }
    dib.extend_from_slice(&1u16.to_le_bytes());
    dib.extend_from_slice(&32u16.to_le_bytes());
    for v in [0u32, pixel.len() as u32, 0, 0, 0, 0] {
        dib.extend_from_slice(&v.to_le_bytes());
    }
    let data_offset = 14 + dib.len() as u32;
    let mut v = b"BM".to_vec();
    v.extend_from_slice(&(data_offset + pixel.len() as u32).to_le_bytes());
    v.extend_from_slice(&[0, 0, 0, 0]);
    v.extend_from_slice(&data_offset.to_le_bytes());
    v.extend(dib);
    v.extend_from_slice(&pixel);
    v.extend_from_slice(trailing);
    v
}

fn gif_extension(label: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![0x21, label];
    for chunk in payload.chunks(255) {
        out.push(chunk.len() as u8);
        out.extend_from_slice(chunk);
    }
    out.push(0);
    out
}

fn gif_image() -> Vec<u8> {
    let mut v = vec![0x2c];
    for x in [0u16, 0, 1, 1] {
        v.extend_from_slice(&x.to_le_bytes());
    }
    v.extend_from_slice(&[0x00, 0x02, 2, 0x02, 0x44, 0x00]);
    v
}

fn minimal_gif(exts: &[(u8, &[u8])], image: Option<Vec<u8>>) -> Vec<u8> {
    let mut v = b"GIF89a".to_vec();
    for x in [1u16, 1] {
        v.extend_from_slice(&x.to_le_bytes());
    }
    v.extend_from_slice(&[0, 0, 0]);
    for (l, p) in exts {
        v.extend(gif_extension(*l, p));
    }
    v.extend(image.unwrap_or_else(gif_image));
    v.push(0x3b);
    v
}

fn gif_xmp() -> Vec<u8> {
    let mut v = b"XMP DataXMP".to_vec();
    v.extend_from_slice(b"<x:xmpmeta><rdf:RDF><rdf:Description digitalSourceType=\"trainedAlgorithmicMedia\"/></rdf:RDF></x:xmpmeta>");
    v
}

/// Port of `_minimal_tiff`: `(data, strip_off, strip_data)`.
fn minimal_tiff(big_endian: bool, big: bool, with_meta: bool) -> (Vec<u8>, usize, Vec<u8>) {
    let le = !big_endian;
    let off_len = if big { 8 } else { 4 };
    let count_len = if big { 8 } else { 2 };
    let entry_size = if big { 20 } else { 12 };
    let header_size = if big { 16 } else { 8 };
    let u16b = |v: u16| if le { v.to_le_bytes().to_vec() } else { v.to_be_bytes().to_vec() };
    let u32b = |v: u32| if le { v.to_le_bytes().to_vec() } else { v.to_be_bytes().to_vec() };
    let u64b = |v: u64| if le { v.to_le_bytes().to_vec() } else { v.to_be_bytes().to_vec() };
    let offb = |v: usize| if big { u64b(v as u64) } else { u32b(v as u32) };
    let countb = |v: usize| if big { u64b(v as u64) } else { u16b(v as u16) };
    let xmp = b"<x:xmpmeta xmlns:x=\"adobe:ns:meta/\"><rdf:RDF><rdf:Description digitalSourceType=\"trainedAlgorithmicMedia\"/></rdf:RDF></x:xmpmeta>".to_vec();
    let make = b"Acme Corp\x00".to_vec();
    let dt = b"2024:01:01 10:00:00\x00".to_vec();
    let maker = b"AIGC maker\x00".to_vec();
    let strip_data = vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11];

    let short_val = |v: u16| {
        let mut b = u16b(v);
        b.resize(off_len, 0);
        b
    };
    let long_val = |v: usize| offb(v);

    // (tag, type, count, value)
    let mut ifd0: Vec<(u16, u16, usize, Vec<u8>)> = vec![
        (256, 4, 1, long_val(1)),
        (257, 4, 1, long_val(1)),
        (258, 3, 1, short_val(8)),
        (259, 3, 1, short_val(1)),
        (262, 3, 1, short_val(2)),
        (273, 4, 1, vec![0; off_len]),
        (278, 4, 1, long_val(1)),
        (279, 4, 1, long_val(strip_data.len())),
    ];
    if with_meta {
        ifd0.push((271, 2, make.len(), vec![0; off_len]));
        ifd0.push((700, 2, xmp.len(), vec![0; off_len]));
        ifd0.push((34665, 4, 1, vec![0; off_len]));
    }
    let count = ifd0.len();
    let ifd0_off = header_size;
    let ifd0_end = ifd0_off + count_len + count * entry_size + off_len;
    let mut cursor = ifd0_end;

    let exif_count = if with_meta { 3 } else { 0 };
    let exif_off = if with_meta { cursor } else { 0 };
    let (mut exp_off, mut dt_off, mut mn_off) = (0, 0, 0);
    let exp_payload: Vec<u8> = [u32b(1), u32b(100)].concat();
    if with_meta {
        cursor += count_len + exif_count * entry_size + off_len;
        exp_off = cursor;
        cursor += exp_payload.len();
        dt_off = cursor;
        cursor += dt.len();
        mn_off = cursor;
        cursor += maker.len();
    }
    let strip_off = cursor;
    cursor += strip_data.len();
    let make_off = cursor;
    cursor += make.len();
    let xmp_off = cursor;

    let entry = |tag: u16, ftype: u16, fcount: usize, value: Vec<u8>| -> Vec<u8> {
        [u16b(tag), u16b(ftype), offb(fcount), value].concat()
    };
    let mut ifd0_bytes = countb(count);
    for (tag, ftype, fcount, v) in &ifd0 {
        let e = match tag {
            273 => entry(*tag, 4, 1, long_val(strip_off)),
            271 => entry(*tag, 2, make.len(), long_val(make_off)),
            700 => entry(*tag, 2, xmp.len(), long_val(xmp_off)),
            34665 => entry(*tag, 4, 1, long_val(exif_off)),
            _ => entry(*tag, *ftype, *fcount, v.clone()),
        };
        ifd0_bytes.extend(e);
    }
    ifd0_bytes.extend(offb(0));

    let (exif_bytes, tail): (Vec<u8>, Vec<u8>) = if with_meta {
        let mut e = countb(exif_count);
        e.extend(entry(33434, 5, 1, long_val(exp_off)));
        e.extend(entry(36867, 2, dt.len(), long_val(dt_off)));
        e.extend(entry(37500, 2, maker.len(), long_val(mn_off)));
        e.extend(offb(0));
        (e, [exp_payload, dt, maker, strip_data.clone(), make, xmp].concat())
    } else {
        (Vec::new(), [strip_data.clone(), make, xmp].concat())
    };

    let magic: &[u8] = if le { b"II" } else { b"MM" };
    let header: Vec<u8> = if big {
        [magic.to_vec(), u16b(43), u16b(8), u16b(0), u64b(ifd0_off as u64)].concat()
    } else {
        [magic.to_vec(), u16b(42), u32b(ifd0_off as u32)].concat()
    };
    (
        [header, ifd0_bytes, exif_bytes, tail].concat(),
        strip_off,
        strip_data,
    )
}

// ---------------------------------------------------------------------------
// test_clean_image.py
// ---------------------------------------------------------------------------

fn minimal_png_with_text() -> Vec<u8> {
    png_text("Comment", "c2pa test contentcredentials")
}

#[test]
fn strip_png_removes_text_c2pa() {
    let data = minimal_png_with_text();
    let (cleaned, actions) = strip_png(&data, true).unwrap();
    assert!(contains_any(&cleaned, &[b"c2pa"]).is_empty());
    assert!(has(&actions, "drop"));
    assert!(cleaned.starts_with(b"\x89PNG"));
    assert!(cleaned.windows(4).any(|w| w == b"IEND"));
    assert!(!cleaned.windows(4).any(|w| w == b"tEXt"));
}

#[test]
fn strip_jpeg_removes_app11() {
    let data = minimal_jpeg_with_app11();
    let (cleaned, actions) = strip_jpeg(&data, true).unwrap();
    assert!(!cleaned.windows(18).any(|w| w == b"c2pa-manifest-fake"));
    assert!(actions.iter().any(|a| a.contains("APP11") || a.contains("drop")));
    assert!(cleaned.starts_with(b"\xff\xd8"));
}

#[test]
fn keep_mode_preserves_benign_jpeg_comments() {
    let comments: [&[u8]; 5] = [
        b"Family vacation, Shanghai, 2026-08-21",
        b"Generated by ImageMagick 7.1",
        b"Claude Monet retrospective",
        b"JUMBO family photo",
        b"Jumble sale poster",
    ];
    for comment in comments {
        let src = jpeg_with_comment(comment);
        assert!(!inspect_image(&src).has_ai_metadata, "{:?}", String::from_utf8_lossy(comment));
        let r = clean_image(&src, &ImageCleanOptions { strip_all_metadata: false }).unwrap();
        assert_eq!(jpeg_comments(&r.cleaned), vec![comment.to_vec()]);
        assert!(!inspect_image(&r.cleaned).has_ai_metadata);
    }
}

#[test]
fn keep_mode_drops_ai_and_c2pa_jpeg_comments() {
    let comments: [(&[u8], bool); 2] = [
        (b"Generated by AI with OpenAI", false),
        (b"contentcredentials c2pa manifest note", true),
    ];
    for (comment, has_c2pa) in comments {
        let src = jpeg_with_comment(comment);
        let before = inspect_image(&src);
        assert!(before.has_ai_metadata);
        assert_eq!(before.has_c2pa, has_c2pa);
        let r = clean_image(&src, &ImageCleanOptions { strip_all_metadata: false }).unwrap();
        assert!(jpeg_comments(&r.cleaned).is_empty());
        assert!(!inspect_image(&r.cleaned).has_ai_metadata);
    }
}

#[test]
fn clean_image_roundtrip_png() {
    let r = clean_image(&minimal_png_with_text(), &ImageCleanOptions::default()).unwrap();
    assert!(r.report.bytes_out > 0);
    assert_eq!(r.report.format, "png");
    assert!(r.report.changed);
    assert!(!r.report.still_has_c2pa);
}

#[test]
fn webp_c2pa_and_xmp_are_detected_and_removed() {
    let mut vp8x = vec![0x04];
    vp8x.extend_from_slice(&[0; 9]);
    let data = minimal_webp(&[
        (b"VP8X", &vp8x),
        (b"VP8 ", b"image-data"),
        (b"XMP ", b"generator=OpenAI"),
        (b"C2PA", b"jumb c2pa manifest"),
    ]);
    assert_eq!(detect_format(&data), "webp");
    let (c2pa, ai, findings) = inspect_webp(&data);
    assert!(c2pa && ai);
    assert!(findings.iter().any(|f| f == "WebP C2PA chunk"));

    let (cleaned, actions) = strip_webp(&data, true).unwrap();
    assert!(has(&actions, "C2PA"));
    assert!(has(&actions, "XMP"));
    assert_eq!(u32::from_le_bytes(cleaned[4..8].try_into().unwrap()) as usize, cleaned.len() - 8);
    assert_eq!(cleaned[20] & 0x04, 0);
    let after = inspect_webp(&cleaned);
    assert_eq!((after.0, after.1), (false, false));

    let r = clean_image(&data, &ImageCleanOptions::default()).unwrap();
    assert_eq!(r.report.format, "webp");
    assert!(!r.report.still_has_c2pa);
    assert!(!r.report.still_has_ai_metadata);
}

#[test]
fn webp_image_payload_text_is_not_a_metadata_false_positive() {
    let data = minimal_webp(&[(b"VP8 ", b"ordinary pixels mentioning c2pa")]);
    let (c2pa, ai, findings) = inspect_webp(&data);
    assert!(!c2pa && !ai);
    assert!(findings.is_empty());
}

#[test]
fn truncated_webp_is_reported_and_not_rewritten() {
    let data = b"RIFF\x10\x00\x00\x00WEBPC2PA\x10\x00\x00\x00short";
    let (c2pa, ai, findings) = inspect_webp(data);
    assert!(!c2pa && !ai);
    assert!(has(&findings, "truncated"));
    let err = strip_webp(data, true).unwrap_err();
    assert!(err.0.contains("malformed WebP"));
}

#[test]
fn webp_size_mismatch_is_not_rewritten() {
    let data = minimal_webp(&[(b"VP8 ", b"image-data")]);
    let mut malformed = data.clone();
    malformed[4..8].copy_from_slice(&(data.len() as u32).to_le_bytes());
    assert!(has(&inspect_webp(&malformed).2, "size mismatch"));
    let err = strip_webp(&malformed, true).unwrap_err();
    assert!(err.0.contains("size mismatch"));
}

// ---------------------------------------------------------------------------
// test_avif_heic.py
// ---------------------------------------------------------------------------

#[test]
fn detect_format_avif_and_heic() {
    assert_eq!(detect_format(&minimal_avif_with_c2pa_and_xmp()), "avif");
    assert_eq!(detect_format(&minimal_heic_with_xmp()), "heic");
    let avis = [bx(b"ftyp", b"avis\x00\x00\x00\x00avis"), b"data".to_vec()].concat();
    assert_eq!(detect_format(&avis), "avif");
    let mif1 = [bx(b"ftyp", b"mif1\x00\x00\x00\x00mif1heic"), b"data".to_vec()].concat();
    assert_eq!(detect_format(&mif1), "heic");
}

#[test]
fn inspect_isobmff_detects_c2pa_and_xmp() {
    let (c2pa, ai, findings) = inspect_isobmff(&minimal_avif_with_c2pa_and_xmp(), "avif");
    assert!(c2pa && ai);
    assert!(findings.iter().any(|f| f.contains("C2PA") || f.to_lowercase().contains("jumb")));
    assert!(findings.iter().any(|f| f.to_lowercase().contains("uuid") || f.contains("XMP")));
}

#[test]
fn inspect_isobmff_heic_ai_metadata() {
    let (_c2pa, ai, findings) = inspect_isobmff(&minimal_heic_with_xmp(), "heic");
    assert!(ai);
    assert!(findings.iter().any(|f| f.contains("trainedAlgorithmicMedia") || f.contains("XMP")));
}

#[test]
fn strip_isobmff_removes_c2pa_and_xmp() {
    let (cleaned, actions) = strip_isobmff(&minimal_avif_with_c2pa_and_xmp(), "avif", true).unwrap();
    assert!(actions.iter().any(|a| a.to_lowercase().contains("jumb")));
    assert!(actions.iter().any(|a| a.to_lowercase().contains("xmp") || a.to_lowercase().contains("uuid")));
    let (c2pa, ai, _f) = inspect_isobmff(&cleaned, "avif");
    assert!(!c2pa && !ai);
    assert_eq!(detect_format(&cleaned), "avif");
    assert!(cleaned.windows(4).any(|w| w == b"mdat"));
    assert!(!cleaned.to_ascii_lowercase().windows(4).any(|w| w == b"jumb"));
}

#[test]
fn clean_image_avif_roundtrip() {
    let r = clean_image(&minimal_avif_with_c2pa_and_xmp(), &ImageCleanOptions::default()).unwrap();
    assert_eq!(r.report.format, "avif");
    assert!(!r.report.still_has_c2pa && !r.report.still_has_ai_metadata);
    assert!(r.report.actions.iter().any(|a| a.to_lowercase().contains("jumb")));
    let rep = inspect_image(&r.cleaned);
    assert_eq!(rep.format, "avif");
    assert!(!rep.has_c2pa && !rep.has_ai_metadata);
}

#[test]
fn clean_image_heic_roundtrip() {
    let r = clean_image(&minimal_heic_with_xmp(), &ImageCleanOptions::default()).unwrap();
    assert_eq!(r.report.format, "heic");
    assert!(!r.report.still_has_ai_metadata);
    assert!(r.report.actions.iter().any(|a| a.to_lowercase().contains("uuid") || a.to_lowercase().contains("xmp")));
}

// ---------------------------------------------------------------------------
// test_isobmff_truncated_bytescan.py
// ---------------------------------------------------------------------------

fn avif_bytescan(marker: &[u8], first_box_overruns: bool) -> Vec<u8> {
    let ftyp = [&b"\x00\x00\x00\x14ftypavif"[..], &[0u8; 4]].concat();
    let body = [marker, &[0u8; 16]].concat();
    if first_box_overruns {
        let size = (ftyp.len() + body.len() + 64) as u32;
        let head = [&size.to_be_bytes()[..], b"ftypavif", &[0u8; 8]].concat();
        [head, body].concat()
    } else {
        [(ftyp.len() as u32).to_be_bytes().to_vec(), b"ftypavif".to_vec(), vec![0u8; 8], body].concat()
    }
}

#[test]
fn truncated_avif_still_bytescans_for_c2pa() {
    let data = avif_bytescan(b"c2pa contentcredentials", true);
    let (c2pa, _, findings) = inspect_isobmff(&data, "avif");
    assert!(c2pa, "{findings:?}");
    assert!(has(&findings, "byte-scan C2PA markers"));
    assert!(has(&findings, "no ISOBMFF boxes found"));
}

#[test]
fn intact_avif_box_parse_path_unchanged() {
    let data = avif_bytescan(b"c2pa contentcredentials", false);
    let (c2pa, _, findings) = inspect_isobmff(&data, "avif");
    assert!(c2pa);
    assert!(findings.iter().any(|f| f.contains("top-level box") && f.to_lowercase().contains("c2pa")));
    assert!(!has(&findings, "no ISOBMFF boxes found"));
}

#[test]
fn truncated_markerless_avif_reports_parse_failure() {
    let data = avif_bytescan(b"nothing interesting", true);
    let (c2pa, _, findings) = inspect_isobmff(&data, "avif");
    assert!(!c2pa);
    assert_eq!(findings, vec!["not a valid AVIF (no ISOBMFF boxes found)".to_string()]);
}

// ---------------------------------------------------------------------------
// test_image_formats_bmp_gif_tiff.py
// ---------------------------------------------------------------------------

#[test]
fn detect_format_bmp_gif_tiff() {
    assert_eq!(detect_format(&minimal_bmp(b"")), "bmp");
    assert_eq!(detect_format(&minimal_gif(&[], None)), "gif");
    for (be, big) in [(false, false), (true, false), (false, true), (true, true)] {
        assert_eq!(detect_format(&minimal_tiff(be, big, true).0), "tiff");
    }
    assert_eq!(detect_format(b"GIF87a rest"), "gif");
}

#[test]
fn bmp_clean_has_no_flags() {
    let data = minimal_bmp(b"");
    let (c2pa, ai, findings) = inspect_bmp(&data);
    assert!(!c2pa && !ai);
    assert!(findings.iter().any(|f| f.to_lowercase().contains("no metadata")));
    let (cleaned, actions) = strip_bmp(&data, true).unwrap();
    assert_eq!(cleaned, data);
    assert!(has(&actions, "no BMP trailing"));
}

#[test]
fn bmp_trailing_metadata_detected_and_stripped() {
    let xmp = b"<x:xmpmeta><rdf:Description digitalSourceType=\"trainedAlgorithmicMedia\"/></x:xmpmeta>";
    let data = minimal_bmp(xmp);
    let (_c, ai, findings) = inspect_bmp(&data);
    assert!(ai);
    assert!(findings.iter().any(|f| f.to_lowercase().contains("trailing")));
    let (cleaned, actions) = strip_bmp(&data, true).unwrap();
    assert!(has(&actions, "drop"));
    assert_eq!(cleaned, minimal_bmp(b""));
    assert_eq!(u32::from_le_bytes(cleaned[2..6].try_into().unwrap()) as usize, cleaned.len());
}

#[test]
fn bmp_keep_non_ai_metadata() {
    let data = minimal_bmp(b"trailing bytes without markers");
    let (kept, actions) = strip_bmp(&data, false).unwrap();
    assert_eq!(kept, data);
    assert!(actions.iter().any(|a| a.to_lowercase().contains("keep")));
}

#[test]
fn bmp_roundtrip() {
    let r = clean_image(&minimal_bmp(b"<x:xmpmeta>OpenAI</x:xmpmeta>"), &ImageCleanOptions::default()).unwrap();
    assert_eq!(r.report.format, "bmp");
    assert!(!r.report.still_has_ai_metadata);
    assert_eq!(r.cleaned, minimal_bmp(b""));
}

#[test]
fn gif_inspect_detects_comment_and_xmp() {
    let data = minimal_gif(&[(0xFE, b"made with c2pa tools"), (0xFF, &gif_xmp())], None);
    let (c2pa, ai, findings) = inspect_gif(&data);
    assert!(ai && c2pa);
    assert!(findings.iter().any(|f| f.to_lowercase().contains("comment")));
    assert!(findings.iter().any(|f| f.to_lowercase().contains("xmp")));
}

#[test]
fn gif_strip_removes_metadata_keeps_pixels_and_loop() {
    let image = gif_image();
    let mut loop_ext = b"NETSCAPE2.0".to_vec();
    loop_ext.extend_from_slice(&0u16.to_le_bytes());
    let data = minimal_gif(
        &[
            (0xFE, b"made with c2pa tools"),
            (0xFF, &gif_xmp()),
            (0xFF, &loop_ext),
            (0xF9, b"\x00\x00\x00\x00"),
        ],
        Some(image.clone()),
    );
    let (cleaned, actions) = strip_gif(&data, true).unwrap();
    assert!(has(&actions, "drop GIF comment"));
    assert!(has(&actions, "drop GIF XMP application"));
    let find = |h: &[u8], n: &[u8]| h.windows(n.len()).any(|w| w == n);
    assert!(!find(&cleaned, b"c2pa tools"));
    assert!(!find(&cleaned, b"XMP DataXMP"));
    assert!(find(&cleaned, &loop_ext));
    assert!(find(&cleaned, b"\x21\xf9\x04"));
    assert!(find(&cleaned, &image));
    let (c2pa, ai, _) = inspect_gif(&cleaned);
    assert!(!c2pa && !ai);
}

#[test]
fn gif_keep_non_ai_metadata() {
    let plain = minimal_gif(&[(0xFE, b"just a comment")], None);
    let (_s, actions) = strip_gif(&plain, true).unwrap();
    assert!(has(&actions, "drop GIF comment"));
    let (kept, actions2) = strip_gif(&plain, false).unwrap();
    assert!(kept.windows(14).any(|w| w == b"just a comment"));
    assert!(!has(&actions2, "drop GIF"));
}

#[test]
fn gif_global_color_table_preserved() {
    let mut data = b"GIF89a".to_vec();
    for x in [2u16, 2] {
        data.extend_from_slice(&x.to_le_bytes());
    }
    data.extend_from_slice(&[0x91, 0, 0]);
    let ncolors = 1usize << ((0x91 & 7) + 1);
    let gct: Vec<u8> = (0..3 * ncolors).map(|i| i as u8).collect();
    data.extend_from_slice(&gct);
    data.extend(gif_extension(0xFE, b"hello"));
    let mut img = vec![0x2c];
    for x in [0u16, 0, 2, 2] {
        img.extend_from_slice(&x.to_le_bytes());
    }
    img.extend_from_slice(&[0x00, 0x02, 2, 0x02, 0x44, 0x00]);
    data.extend_from_slice(&img);
    data.push(0x3b);
    let (cleaned, actions) = strip_gif(&data, true).unwrap();
    assert!(has(&actions, "drop GIF comment"));
    let find = |n: &[u8]| cleaned.windows(n.len()).any(|w| w == n);
    assert!(find(&gct));
    assert!(find(&img));
    assert!(!find(b"hello"));
    assert_eq!(detect_format(&cleaned), "gif");
}

#[test]
fn gif_roundtrip() {
    let data = minimal_gif(&[(0xFE, b"made with c2pa tools"), (0xFF, &gif_xmp())], None);
    let r = clean_image(&data, &ImageCleanOptions::default()).unwrap();
    assert_eq!(r.report.format, "gif");
    assert!(!r.report.still_has_c2pa && !r.report.still_has_ai_metadata);
    let rep = inspect_image(&r.cleaned);
    assert_eq!(rep.format, "gif");
    assert!(!rep.has_ai_metadata);
}

fn find(h: &[u8], n: &[u8]) -> bool {
    h.windows(n.len()).any(|w| w == n)
}

#[test]
fn tiff_inspect_detects_metadata() {
    let (data, _o, _s) = minimal_tiff(false, false, true);
    let (_c, ai, findings) = inspect_tiff(&data);
    assert!(ai);
    for needle in ["XMP", "ExifIFD", "MakerNote", "trainedAlgorithmicMedia"] {
        assert!(has(&findings, needle), "missing {needle}: {findings:?}");
    }
}

#[test]
fn tiff_strip_removes_metadata_preserves_strip() {
    let (data, strip_off, strip_data) = minimal_tiff(false, false, true);
    let (cleaned, actions) = strip_tiff(&data, true).unwrap();
    assert!(has(&actions, "drop TIFF tag 700"));
    assert!(has(&actions, "drop TIFF tag 34665"));
    assert!(has(&actions, "drop TIFF tag 271"));
    for n in [&b"Acme Corp"[..], b"trainedAlgorithmicMedia", b"AIGC", b"2024:01:01"] {
        assert!(!find(&cleaned, n));
    }
    assert_eq!(&cleaned[strip_off..strip_off + strip_data.len()], &strip_data[..]);
    assert_eq!(detect_format(&cleaned), "tiff");
    let (c2pa, ai, _) = inspect_tiff(&cleaned);
    assert!(!c2pa && !ai);
}

#[test]
fn tiff_bigtiff_strip() {
    for (be, big) in [(false, true), (true, true)] {
        let (data, strip_off, strip_data) = minimal_tiff(be, big, true);
        let (cleaned, actions) = strip_tiff(&data, true).unwrap();
        assert!(has(&actions, "drop TIFF tag 700"));
        assert!(!find(&cleaned, b"Acme Corp"));
        assert!(!find(&cleaned, b"trainedAlgorithmicMedia"));
        assert_eq!(&cleaned[strip_off..strip_off + strip_data.len()], &strip_data[..]);
        assert_eq!(detect_format(&cleaned), "tiff");
        let (c2pa, ai, _) = inspect_tiff(&cleaned);
        assert!(!c2pa && !ai);
    }
}

#[test]
fn tiff_clean_roundtrip_byte_identical() {
    let (data, _o, _s) = minimal_tiff(false, false, false);
    let (cleaned, actions) = strip_tiff(&data, true).unwrap();
    assert_eq!(cleaned, data);
    assert!(has(&actions, "no TIFF metadata tags removed"));
}

#[test]
fn tiff_keep_non_ai_metadata() {
    let (data, _o, _s) = minimal_tiff(false, false, true);
    let (cleaned, actions) = strip_tiff(&data, false).unwrap();
    assert!(has(&actions, "drop TIFF tag 700"));
    assert!(has(&actions, "drop TIFF tag 34665"));
    assert!(!has(&actions, "drop TIFF tag 271"));
    assert!(find(&cleaned, b"Acme Corp"));
    assert!(!find(&cleaned, b"AIGC"));
}

#[test]
fn tiff_roundtrip() {
    let (data, _o, _s) = minimal_tiff(false, false, true);
    let r = clean_image(&data, &ImageCleanOptions::default()).unwrap();
    assert_eq!(r.report.format, "tiff");
    assert!(!r.report.still_has_c2pa && !r.report.still_has_ai_metadata);
    let rep = inspect_image(&r.cleaned);
    assert_eq!(rep.format, "tiff");
    assert!(!rep.has_ai_metadata);
}

// ---------------------------------------------------------------------------
// test_ai_generator_hints.py
// ---------------------------------------------------------------------------

const ISSUE_PRODUCTS: [&str; 9] = [
    "ChatGPT", "DALL-E", "Midjourney", "Stable Diffusion", "Gemini", "Imagen", "Adobe Firefly",
    "Grok", "Sora",
];

#[test]
fn software_tag_naming_generator_flags_ai() {
    for product in ISSUE_PRODUCTS {
        let (c2pa, ai, findings) = inspect_png(&png_text("Software", product));
        assert!(!c2pa);
        assert!(ai, "{product}");
        assert!(findings.iter().any(|f| f.contains("AI generator") && f.contains(product)));
    }
}

#[test]
fn every_generator_product_hint_matches_in_software_tag() {
    for p in AI_GENERATOR_PRODUCTS {
        let product = String::from_utf8(p.to_vec()).unwrap();
        let (_c, ai, findings) = inspect_png(&png_text("Software", &product));
        assert!(ai, "{product}");
        assert!(has(&findings, "AI generator"));
    }
}

#[test]
fn creator_and_parameters_keys_are_scoped() {
    assert!(inspect_png(&png_text("Creator", "DALL-E 3")).1);
    assert!(inspect_png(&png_text("parameters", "Steps: 20, Sampler: DPM++ 2M, Model: SDXL base 1.0")).1);
    assert!(!inspect_png(&png_text("parameters", "Steps: 20, Sampler: DPM++ 2M, Model: sd_xl_base_1.0")).1);
}

#[test]
fn vendor_name_still_flags_via_flat_hints() {
    let (_c, ai, findings) = inspect_png(&png_text("Software", "OpenAI"));
    assert!(ai);
    assert!(has(&findings, "OpenAI"));
}

#[test]
fn generator_word_in_comment_does_not_false_positive() {
    let data = png_text("Comment", "Hiking near the Gemini constellation with my dog Sora");
    let (_c, ai, findings) = inspect_png(&data);
    assert!(!ai);
    assert!(findings.is_empty());
}

#[test]
fn generated_by_comment_still_flags_via_flat_hints() {
    assert!(inspect_png(&png_text("Comment", "Generated by AI")).1);
}

#[test]
fn lowercase_key_and_value_match() {
    let (_c, ai, findings) = inspect_png(&png_text("software", "chatgpt"));
    assert!(ai);
    assert!(has(&findings, "AI generator"));
}

#[test]
fn ztext_compressed_software_matches() {
    let mut payload = b"Software\x00\x00".to_vec();
    payload.extend(zlib_store(b"ChatGPT"));
    let (_c, ai, findings) = inspect_png(&png_with_chunk(b"zTXt", &payload));
    assert!(ai);
    assert!(has(&findings, "AI generator"));
}

#[test]
fn itext_software_matches() {
    let (_c, ai, findings) =
        inspect_png(&png_with_chunk(b"iTXt", b"Software\x00\x00\x00\x00\x00ChatGPT"));
    assert!(ai);
    assert!(has(&findings, "AI generator"));
}

#[test]
fn compressed_text_flat_hint_matches_and_is_dropped() {
    let mut z = b"Comment\x00\x00".to_vec();
    z.extend(zlib_store(b"Generated by AI"));
    let mut i = b"Comment\x00\x01\x00\x00\x00".to_vec();
    i.extend(zlib_store(b"Generated by AI"));
    for (ctype, payload) in [(&b"zTXt"[..], z), (&b"iTXt"[..], i)] {
        let data = png_with_chunk(ctype, &payload);
        let (_c, ai, findings) = inspect_png(&data);
        assert!(ai);
        assert!(has(&findings, "Generated by"));
        let (cleaned, actions) = strip_png(&data, false).unwrap();
        assert!(!find(&cleaned, ctype));
        assert!(has(&actions, "drop"));
    }
}

#[test]
fn strip_keep_mode_drops_generator_tagged_chunk() {
    let (cleaned, actions) = strip_png(&png_text("Software", "ChatGPT"), false).unwrap();
    assert!(!find(&cleaned, b"ChatGPT"));
    assert!(has(&actions, "drop"));
}

#[test]
fn strip_keep_mode_keeps_benign_text_chunk() {
    let data = png_text("Comment", "Hiking near the Gemini constellation");
    let (cleaned, actions) = strip_png(&data, false).unwrap();
    assert!(find(&cleaned, b"Gemini"));
    assert!(!has(&actions, "drop"));
}

#[test]
fn inspect_image_end_to_end() {
    let report = inspect_image(&png_text("Software", "ChatGPT"));
    assert!(report.has_ai_metadata);
    assert!(has(&report.findings, "AI generator"));
}

// ---------------------------------------------------------------------------
// extras: zlib bomb refusal and report serialization
// ---------------------------------------------------------------------------

#[test]
fn ztxt_bomb_is_refused_not_inflated() {
    let bomb = read_data("png_ztxt_bomb.png");
    let r = inspect_png(&bomb);
    assert!(has(&r.2, "not fully inspected (decompressed text exceeds cap)"));
    let (cleaned, actions) = strip_png(&bomb, false).unwrap();
    assert!(has(&actions, "decompressed text exceeds cap"));
    assert!(!find(&cleaned, b"zTXt"));
}

#[test]
fn reports_serialize_with_python_field_names() {
    let rep = inspect_image(&png_text("Software", "ChatGPT"));
    let v = serde_json::to_value(&rep).unwrap();
    for k in ["format", "has_c2pa", "has_ai_metadata", "findings", "findings_confidence", "notes"] {
        assert!(v.get(k).is_some(), "{k}");
    }
    let r = clean_image(&png_text("Software", "ChatGPT"), &ImageCleanOptions::default()).unwrap();
    let v = serde_json::to_value(&r.report).unwrap();
    for k in [
        "format", "actions", "bytes_in", "bytes_out", "changed", "still_has_c2pa",
        "still_has_ai_metadata", "post_findings",
    ] {
        assert!(v.get(k).is_some(), "{k}");
    }
    assert_eq!(clean_image(b"hello", &ImageCleanOptions::default()).unwrap_err().0, "unsupported format: unknown");
}
