//! Ports of the ffmpeg-free cases in tests/test_av_meta.py (test_clean_audio.py
//! and test_clean_video.py only cover ffmpeg purification plans and have no
//! counterpart here), plus truncated-prefix / mutation no-panic sweeps.

mod common;

use common::*;
use wm_av::*;
use wm_image::isobmff::{contains_c2pa_prov_box, C2PA_BMFF_UUID, XMP_UUID};

fn bx(fourcc: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut v = ((payload.len() + 8) as u32).to_be_bytes().to_vec();
    v.extend_from_slice(fourcc);
    v.extend_from_slice(payload);
    v
}
fn xbx(fourcc: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut v = 1u32.to_be_bytes().to_vec();
    v.extend_from_slice(fourcc);
    v.extend_from_slice(&((payload.len() + 16) as u64).to_be_bytes());
    v.extend_from_slice(payload);
    v
}
fn cat(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}
fn mp4(boxes: &[&[u8]]) -> Vec<u8> {
    let ftyp = bx(b"ftyp", &cat(&[b"isom", &[0; 4], b"isomiso2mp41"]));
    cat(&[&ftyp, &boxes.concat()])
}
fn mdat() -> Vec<u8> {
    bx(b"mdat", &[0; 16])
}
fn moov_udta(p: &[u8]) -> Vec<u8> {
    bx(b"moov", &cat(&[&bx(b"mvhd", &[0; 20]), &bx(b"udta", p)]))
}
fn mp4_xmp(t: &[u8]) -> Vec<u8> {
    mp4(&[&bx(b"uuid", &cat(&[&XMP_UUID, t])), &mdat()])
}
fn mp4_udta_tag(t: &[u8]) -> Vec<u8> {
    let p = cat(&[b"\xa9too", &((t.len() + 4) as u32).to_be_bytes(), &[0; 4], t]);
    mp4(&[&moov_udta(&p), &mdat()])
}
fn mp4_c2pa(purpose: &[u8], data: &[u8]) -> Vec<u8> {
    mp4(&[&bx(b"uuid", &cat(&[&C2PA_BMFF_UUID, purpose, b"\0", data])), &mdat()])
}
fn riff(cid: &[u8], p: &[u8]) -> Vec<u8> {
    let mut v = cid.to_vec();
    v.extend_from_slice(&(p.len() as u32).to_le_bytes());
    v.extend_from_slice(p);
    if p.len() & 1 == 1 {
        v.push(0);
    }
    v
}
fn wav(chunks: &[&[u8]]) -> Vec<u8> {
    let body = cat(&[b"WAVE", &chunks.concat()]);
    cat(&[b"RIFF", &(body.len() as u32).to_le_bytes(), &body])
}
fn fmt_chunk() -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&1u16.to_le_bytes());
    p.extend_from_slice(&1u16.to_le_bytes());
    p.extend_from_slice(&44100u32.to_le_bytes());
    p.extend_from_slice(&88200u32.to_le_bytes());
    p.extend_from_slice(&2u16.to_le_bytes());
    p.extend_from_slice(&16u16.to_le_bytes());
    riff(b"fmt ", &p)
}
fn data_chunk(n: usize) -> Vec<u8> {
    riff(b"data", &vec![1u8; n])
}
fn list_info(t: &[u8]) -> Vec<u8> {
    let mut txt = t.to_vec();
    if t.len().is_multiple_of(2) {
        txt.push(0);
    }
    riff(b"LIST", &cat(&[b"INFO", &riff(b"ISFT", &txt)]))
}
fn ssz(n: usize) -> [u8; 4] {
    [((n >> 21) & 0x7F) as u8, ((n >> 14) & 0x7F) as u8, ((n >> 7) & 0x7F) as u8, (n & 0x7F) as u8]
}
fn frame(id: &[u8], p: &[u8], major: u8, flags: [u8; 2]) -> Vec<u8> {
    let size = if major == 4 { ssz(p.len()) } else { (p.len() as u32).to_be_bytes() };
    cat(&[id, &size, &flags, p])
}
fn f3(id: &[u8], p: &[u8]) -> Vec<u8> {
    frame(id, p, 3, [0, 0])
}
fn f4(id: &[u8], p: &[u8]) -> Vec<u8> {
    frame(id, p, 4, [0, 0])
}
const AUDIO4: [u8; 16] = [0xFF, 0xFB, 0x90, 0x00, 0xFF, 0xFB, 0x90, 0x00, 0xFF, 0xFB, 0x90, 0x00, 0xFF, 0xFB, 0x90, 0x00];
fn mp3(frames: &[&[u8]], major: u8) -> Vec<u8> {
    let body = frames.concat();
    cat(&[b"ID3", &[major, 0, 0], &ssz(body.len()), &body, &AUDIO4])
}
fn flac(frames: &[&[u8]], major: u8, ext: &[u8], footer: bool) -> Vec<u8> {
    let body = cat(&[ext, &frames.concat()]);
    let flags = (if ext.is_empty() { 0 } else { 0x40 }) | (if footer { 0x10 } else { 0 });
    let size = ssz(body.len());
    let id3_footer = if footer { cat(&[b"3DI", &[major, 0, flags], &size]) } else { vec![] };
    let id3 = if body.is_empty() {
        vec![]
    } else {
        cat(&[b"ID3", &[major, 0, flags], &size, &body, &id3_footer])
    };
    cat(&[&id3, b"fLaC", b"\x80\x00\x00\x22", &[0; 34]])
}
fn flac0() -> Vec<u8> {
    flac(&[], 3, b"", false)
}
fn geob() -> Vec<u8> {
    b"\x00application/c2pa\x00manifest.c2pa\x00Content Credentials\x00jumbf-data".to_vec()
}
fn idx(h: &[u8], n: &[u8]) -> usize {
    h.windows(n.len()).position(|w| w == n).unwrap()
}
fn has(h: &[u8], n: &[u8]) -> bool {
    h.windows(n.len()).any(|w| w == n)
}
fn clean(d: &[u8], all: bool) -> AvCleanResult {
    clean_av(d, &AvCleanOptions { strip_all_metadata: all }).unwrap()
}
fn acts_have(r: &AvCleanResult, s: &str) -> bool {
    r.report.actions.iter().any(|a| a.contains(s))
}

// ---- detect ----
#[test]
fn detect_formats() {
    assert_eq!(detect_av_format(&mp4(&[])), "mp4");
    assert_eq!(detect_av_format(&wav(&[&fmt_chunk()])), "wav");
    assert_eq!(detect_av_format(&mp3(&[&f3(b"TIT2", b"\x00Song")], 3)), "mp3");
    assert_eq!(detect_av_format(&AUDIO4), "mp3");
    assert_eq!(detect_av_format(&flac0()), "flac");
    assert_eq!(detect_av_format(&flac(&[&f3(b"TIT2", b"\x00My Track")], 3, b"", false)), "flac");
    assert_eq!(detect_av_format(b"not a known av container"), "unknown");
    assert_eq!(detect_av_format(b""), "unknown");
}

#[test]
fn av_exts_constant() {
    assert_eq!(AV_EXTS.len(), 7);
    assert!(AV_EXTS.contains(&".flac") && AV_EXTS.contains(&".m4v"));
}

#[test]
fn unsupported_format_errors() {
    let e = clean_av(b"hello", &AvCleanOptions::default()).unwrap_err();
    assert_eq!(e.0, "unsupported audio/video format for cleaning: unknown");
    let r = inspect_av(b"hello");
    assert_eq!(r.format, "unknown");
    assert_eq!(r.findings, vec!["unsupported format (MP4/MOV/M4A/WAV/MP3/FLAC)"]);
    assert_eq!(r.notes.len(), 1);
}

// ---- FLAC ----
#[test]
fn flac_c2pa_geob_detected() {
    let d = flac(&[&f3(b"GEOB", &geob())], 3, b"", false);
    let r = inspect_av(&d);
    assert_eq!(r.format, "flac");
    assert!(r.has_c2pa && r.has_ai_metadata);
    assert!(r.findings.iter().any(|f| f.contains("GEOB")));
    assert_eq!(r.findings_confidence, vec!["confirmed"]);
}

#[test]
fn flac_keep_mode_drops_geob_keeps_title() {
    let d = flac(&[&f3(b"TIT2", b"\x00My Track"), &f3(b"GEOB", &geob())], 3, b"", false);
    let r = clean(&d, false);
    assert_eq!(r.report.format, "flac");
    assert!(!r.report.still_has_c2pa);
    assert!(has(&r.cleaned, b"My Track") && !has(&r.cleaned, b"application/c2pa"));
    assert!(r.cleaned.ends_with(&flac0()));
    assert!(acts_have(&r, "GEOB"));
}

#[test]
fn flac_keep_mode_drops_empty_id3_tag() {
    let r = clean(&flac(&[&f3(b"GEOB", &geob())], 3, b"", false), false);
    assert_eq!(r.cleaned, flac0());
}

#[test]
fn flac_keep_mode_preserves_retained_frame_bytes() {
    let title = frame(b"TIT2", b"\x00My Track", 4, [0x20, 0]);
    let d = flac(&[&title, &f4(b"GEOB", &geob())], 4, b"", false);
    assert!(has(&clean(&d, false).cleaned, &title));
}

#[test]
fn flac_c2pa_geob_after_extended_header() {
    let v23 = cat(&[&10u32.to_be_bytes(), b"\x80\x00", &0u32.to_be_bytes(), &[0; 4]]);
    let v24 = cat(&[&ssz(6), b"\x01\x00"]);
    for (major, ext) in [(3u8, v23), (4u8, v24)] {
        let title = frame(b"TIT2", b"\x00My Track", major, [0, 0]);
        let g = frame(b"GEOB", &geob(), major, [0, 0]);
        let d = flac(&[&title, &g], major, &ext, false);
        assert!(inspect_av(&d).has_c2pa);
        let c = clean(&d, false).cleaned;
        assert!(!has(&c, b"application/c2pa") && has(&c, &title));
        assert!(c.ends_with(&flac0()));
        assert_eq!(c[5] & 0x40, 0);
    }
}

#[test]
fn flac_c2pa_geob_before_footer() {
    let title = f4(b"TIT2", b"\x00My Track");
    let d = flac(&[&title, &f4(b"GEOB", &geob())], 4, b"", true);
    let r = inspect_av(&d);
    assert_eq!(r.format, "flac");
    assert!(r.has_c2pa);
    let c = clean(&d, false).cleaned;
    assert_eq!(detect_av_format(&c), "flac");
    assert!(has(&c, &title) && !has(&c, b"application/c2pa") && !has(&c, b"3DI"));
    assert_eq!(c[5] & 0x10, 0);
    assert!(c.ends_with(&flac0()));
}

#[test]
fn flac_ignores_non_geob_ai_text() {
    let d = flac(&[&f3(b"COMM", b"\x00Generated by AI")], 3, b"", false);
    let r = inspect_av(&d);
    assert!(!r.has_c2pa && !r.has_ai_metadata);
    assert_eq!(clean(&d, false).cleaned, d);
}

#[test]
fn flac_ignores_truncated_c2pa_geob() {
    let d = flac(&[&f3(b"GEOB", b"\x00application/c2pa\x00")], 3, b"", false);
    let r = inspect_av(&d);
    assert!(!r.has_c2pa && !r.has_ai_metadata);
    assert_eq!(clean(&d, false).cleaned, d);
}

#[test]
fn flac_keep_mode_preserves_malformed_tags() {
    let g = f3(b"GEOB", &geob());
    let trunc = cat(&[b"TIT2", &20u32.to_be_bytes(), b"\0\0partial"]);
    let d = flac(&[&g, &trunc], 3, b"", false);
    assert_eq!(clean(&d, false).cleaned, d);
    let d = flac(&[&g, b"TIT2bad"], 3, b"", false);
    assert_eq!(clean(&d, false).cleaned, d);
}

#[test]
fn flac_keep_mode_accepts_zero_padding() {
    let d = flac(&[&f3(b"GEOB", &geob()), &[0; 7]], 3, b"", false);
    assert_eq!(clean(&d, false).cleaned, flac0());
}

#[test]
fn flac_strip_all_drops_whole_tag() {
    let d = flac(&[&f3(b"TIT2", b"\x00My Track")], 3, b"", false);
    let r = clean(&d, true);
    assert_eq!(r.cleaned, flac0());
    assert!(r.report.actions[0].starts_with("drop FLAC ID3v2.3 tag"));
}

// ---- MP4 ----
#[test]
fn mp4_xmp_detected_and_stripped() {
    let d = mp4_xmp(b"Generated by AI toolchain");
    let r = inspect_av(&d);
    assert_eq!(r.format, "mp4");
    assert!(r.has_ai_metadata && r.findings.iter().any(|f| f.to_lowercase().contains("uuid")));
    let c = clean(&d, true);
    assert!(!c.report.still_has_ai_metadata);
    assert!(!has(&c.cleaned, b"Generated by AI"));
    assert!(acts_have(&c, "uuid"));
    assert_eq!(idx(&c.cleaned, b"mdat"), idx(&d, b"mdat"));
}

#[test]
fn mp4_extended_xmp_preserves_mdat_offset() {
    let x = xbx(b"uuid", &cat(&[&XMP_UUID, b"Generated by AI"]));
    let d = mp4(&[&x, &mdat()]);
    let c = clean(&d, true).cleaned;
    assert_eq!(idx(&c, b"mdat"), idx(&d, b"mdat"));
    assert_eq!(&c[28..36], b"\x00\x00\x00\x01free");
    assert!(!has(&c, b"Generated by AI"));
}

#[test]
fn mp4_udta_generator_tag() {
    let r = inspect_av(&mp4_udta_tag(b"ElevenLabs AI Voice Generator"));
    assert!(!r.has_ai_metadata);
    let d = mp4_udta_tag(b"Generated by AI");
    let r = inspect_av(&d);
    assert!(r.has_ai_metadata && r.findings.iter().any(|f| f.contains("udta")));
    let c = clean(&d, true);
    assert!(!has(&c.cleaned, b"Generated by AI") && !c.report.still_has_ai_metadata);
    assert_eq!(idx(&c.cleaned, b"mdat"), idx(&d, b"mdat"));
}

#[test]
fn mp4_udta_default_and_keep_mode() {
    let d = mp4_udta_tag(b"Adobe Premiere Pro 2026");
    let c = clean(&d, true);
    assert!(!has(&c.cleaned, b"Adobe Premiere Pro 2026") && acts_have(&c, "udta"));
    let k = clean(&d, false);
    assert!(has(&k.cleaned, b"Adobe Premiere Pro 2026") && !acts_have(&k, "udta"));
}

#[test]
fn mp4_truncated_tail_survives_udta_stripping() {
    let moov = moov_udta(b"    toolGenerated by OpenAI Sora");
    let md = bx(b"mdat", &vec![0u8; 4096]);
    let whole = mp4(&[&moov, &md]);
    let mdat_start = idx(&whole, &md[..8]);
    let d = &whole[..whole.len() - 1024];
    let r = clean(d, true);
    assert_eq!(r.cleaned.len(), d.len());
    assert_eq!(&r.cleaned[mdat_start..], &d[mdat_start..]);
    assert!(!has(&r.cleaned, b"Generated by OpenAI Sora"));
    assert!(r.report.still_has_ai_metadata);
    assert!(r.report.post_findings.iter().any(|f| f.contains("not fully inspected")));
}

#[test]
fn mp4_truncated_metadata_box_inconclusive() {
    let moov = moov_udta(&cat(&[b"    toolGenerated by OpenAI Sora", &[0; 32]]));
    let full = mp4(&[&moov]);
    let d = &full[..full.len() - 16];
    let r = clean(d, true);
    assert_eq!(r.cleaned, d);
    assert!(r.report.still_has_ai_metadata);
    assert!(r.report.post_findings.iter().any(|f| f.contains("not fully inspected")));
}

#[test]
fn mp4_clean_file_is_idempotent() {
    let r = clean(&mp4(&[]), true);
    assert!(!r.report.still_has_ai_metadata && !r.report.still_has_c2pa && !r.report.changed);
    assert_eq!(r.report.actions, vec!["no MP4 metadata boxes removed (already clean or none matched)"]);
}

#[test]
fn mp4_c2pa_manifest_detected_and_stripped() {
    let data = cat(&[b"c2pa", &[0; 8], b"jumb", &[0; 4]]);
    let d = mp4_c2pa(b"manifest", &data);
    let r = inspect_av(&d);
    assert!(r.has_c2pa && r.has_ai_metadata);
    assert!(r.findings.iter().any(|f| f.contains("content-provenance")));
    let c = clean(&d, true);
    assert!(!c.report.still_has_c2pa && !has(&c.cleaned, &C2PA_BMFF_UUID));
    assert!(acts_have(&c, "content-provenance"));
    assert_eq!(idx(&c.cleaned, b"mdat"), idx(&d, b"mdat"));
    assert!(has(&c.cleaned, b"free"));
}

#[test]
fn mp4_c2pa_manifest_stripped_in_keep_mode_by_user_type() {
    let bin: Vec<u8> = (1u8..64).collect();
    let d = mp4_c2pa(b"manifest", &bin);
    assert!(inspect_av(&d).has_c2pa);
    let c = clean(&d, false);
    assert!(!c.report.still_has_c2pa && !has(&c.cleaned, &C2PA_BMFF_UUID));
    assert!(acts_have(&c, "content-provenance"));
}

#[test]
fn mp4_c2pa_update_and_merkle() {
    let b: Vec<u8> = (1u8..32).collect();
    let d = mp4(&[&mdat(), &bx(b"uuid", &cat(&[&C2PA_BMFF_UUID, b"update\0", &b]))]);
    assert!(inspect_av(&d).has_c2pa);
    let c = clean(&d, false);
    assert!(!c.report.still_has_c2pa && !has(&c.cleaned, &C2PA_BMFF_UUID));
    let m: Vec<u8> = (1u8..128).collect();
    let r = inspect_av(&mp4_c2pa(b"merkle", &m));
    assert!(r.has_c2pa && r.findings.iter().any(|f| f.contains("content-provenance")));
}

#[test]
fn mp4_c2pa_bytes_at_invalid_offset_not_manifest() {
    let bad = bx(b"uuid", &cat(&[b"\x00", &C2PA_BMFF_UUID, b"not-a-manifest"]));
    let d = mp4(&[&bad, &mdat()]);
    assert!(!inspect_av(&d).has_c2pa);
    let c = clean(&d, false);
    assert!(has(&c.cleaned, &C2PA_BMFF_UUID) && !acts_have(&c, "content-provenance"));
}

#[test]
fn mp4_mdat_marker_bytes_do_not_create_c2pa_finding() {
    let mut media = vec![0u8; 256];
    media[32..36].copy_from_slice(b"jumb");
    media[64..68].copy_from_slice(b"uuid");
    media[68..84].copy_from_slice(&C2PA_BMFF_UUID);
    media[128..132].copy_from_slice(b"JUMB");
    let d = mp4(&[&bx(b"free", &[0; 16]), &bx(b"mdat", &media), &moov_udta(b"Lavf/Remotion")]);
    let r = inspect_av(&d);
    assert!(!r.has_c2pa && !r.findings.iter().any(|f| f.contains("byte-scan C2PA markers")));
    let c = clean(&d, false);
    assert_eq!(c.cleaned, d);
    assert!(!c.report.still_has_c2pa);
}

#[test]
fn mp4_c2pa_uuid_at_offset_4() {
    let d = mp4(&[&bx(b"uuid", &cat(&[&[0; 4], &C2PA_BMFF_UUID, b"manifest\0data"])), &mdat()]);
    assert!(inspect_av(&d).has_c2pa);
    assert!(!clean(&d, false).report.still_has_c2pa);
}

#[test]
fn c2pa_prov_box_scan_requires_uuid_fourcc() {
    assert!(contains_c2pa_prov_box(&cat(&[&[0; 8], b"uuid", &C2PA_BMFF_UUID, b"rest"])));
    assert!(!contains_c2pa_prov_box(&cat(&[&[0; 10], &C2PA_BMFF_UUID, &[0; 10]])));
}

#[test]
fn mp4_without_boxes_is_a_value_error() {
    let mut d = b"\x00\x00\x00\x02ftypisom".to_vec();
    d.extend_from_slice(&[0; 4]);
    let e = clean_av(&d, &AvCleanOptions::default()).unwrap_err();
    assert_eq!(e.0, "not a valid MP4 (no ISOBMFF boxes)");
}

// ---- WAV ----
#[test]
fn wav_list_info_detected_and_stripped() {
    let d = wav(&[&fmt_chunk(), &list_info(b"Generated by AI"), &data_chunk(8)]);
    let r = inspect_av(&d);
    assert_eq!(r.format, "wav");
    assert!(r.has_ai_metadata && r.findings.iter().any(|f| f.contains("LIST INFO")));
    let c = clean(&d, true);
    assert!(!has(&c.cleaned, b"Generated by AI") && !c.report.still_has_ai_metadata);
}

#[test]
fn wav_c2pa_chunk_detected_and_stripped() {
    let (f, dc) = (fmt_chunk(), data_chunk(8));
    let d = wav(&[&f, &riff(b"C2PA", b"C2PA manifest store"), &dc]);
    let r = inspect_av(&d);
    assert!(r.has_c2pa && r.findings.iter().any(|f| f.contains("C2PA")));
    let c = clean(&d, false);
    assert_eq!(c.report.actions, vec!["drop WAV C2PA chunk"]);
    assert_eq!(c.cleaned, wav(&[&f, &dc]));
    assert!(!c.report.still_has_c2pa);
}

#[test]
fn wav_audio_untouched_and_riff_size_fixed() {
    let audio: Vec<u8> = (0..1024).map(|i| (i % 256) as u8).collect();
    let d = wav(&[&fmt_chunk(), &list_info(b"Generated by AI"), &riff(b"data", &audio)]);
    let c = clean(&d, true).cleaned;
    assert!(has(&c, &audio));
    assert_eq!(u32::from_le_bytes(c[4..8].try_into().unwrap()) as usize, c.len() - 8);
}

#[test]
fn wav_clean_noop_and_keep_mode() {
    let d = wav(&[&fmt_chunk(), &riff(b"data", &[1, 2, 3, 4, 1, 2, 3, 4])]);
    let r = clean(&d, true);
    assert!(r.report.actions[0].contains("no WAV metadata chunks removed"));
    assert_eq!(r.cleaned, d);
    let d = wav(&[&fmt_chunk(), &list_info(b"Adobe Audition"), &data_chunk(8)]);
    assert!(has(&clean(&d, false).cleaned, b"Adobe Audition"));
}

#[test]
fn wav_id3_chunk() {
    let tag = cat(&[b"ID3", &[3, 0, 0], &ssz(f3(b"TSSE", b"\x00Generated by AI").len()), &f3(b"TSSE", b"\x00Generated by AI")]);
    let d = wav(&[&fmt_chunk(), &riff(b"id3 ", &tag), &data_chunk(8)]);
    let r = inspect_av(&d);
    assert!(r.has_ai_metadata && r.findings[0].starts_with("WAV id3 chunk / ID3v2 frame TSSE"));
    let c = clean(&d, false);
    assert!(acts_have(&c, "drop WAV id3 chunk") && !has(&c.cleaned, b"Generated by AI"));
}

// ---- MP3 ----
#[test]
fn mp3_id3v23_ai_hint_detected() {
    let d = mp3(&[&f3(b"TIT2", b"\x00My Track"), &f3(b"TSSE", b"\x00Generated by AI")], 3);
    let r = inspect_av(&d);
    assert_eq!(r.format, "mp3");
    assert!(r.has_ai_metadata && r.findings.iter().any(|f| f.contains("TSSE")));
}

#[test]
fn mp3_strip_all_drops_whole_tag() {
    let d = mp3(&[&f3(b"TIT2", b"\x00My Track"), &f3(b"TSSE", b"\x00Generated by AI")], 3);
    let c = clean(&d, true);
    assert!(!has(&c.cleaned, b"My Track") && !has(&c.cleaned, b"Generated by AI"));
    assert!(!c.report.still_has_ai_metadata && c.cleaned.ends_with(&AUDIO4));
}

#[test]
fn mp3_keep_mode_drops_only_flagged_frame() {
    let d = mp3(&[&f3(b"TIT2", b"\x00My Track"), &f3(b"TSSE", b"\x00Generated by AI")], 3);
    let c = clean(&d, false);
    assert!(has(&c.cleaned, b"My Track") && !has(&c.cleaned, b"Generated by AI"));
    assert!(acts_have(&c, "TSSE"));
}

#[test]
fn mp3_id3v24_syncsafe_round_trip() {
    let d = mp3(&[&f4(b"TIT2", b"\x00My Track"), &f4(b"TSSE", b"\x00Generated by AI")], 4);
    assert!(inspect_av(&d).has_ai_metadata);
    let c = clean(&d, false);
    assert!(has(&c.cleaned, b"My Track") && !has(&c.cleaned, b"Generated by AI"));
    assert!(!inspect_av(&c.cleaned).has_ai_metadata && !c.report.still_has_ai_metadata);
}

#[test]
fn mp3_no_id3_noop() {
    let d = AUDIO4.repeat(5);
    let c = clean(&d, true);
    assert_eq!(c.cleaned, d);
    assert!(!c.report.still_has_ai_metadata);
}

#[test]
fn mp3_id3v22_whole_tag() {
    let body = b"TT2\x00\x00\x10\x00Generated by AI";
    let d = cat(&[b"ID3", &[2, 0, 0], &ssz(body.len()), body, &AUDIO4]);
    assert!(inspect_av(&d).has_ai_metadata);
    let c = clean(&d, false);
    assert!(!has(&c.cleaned, b"Generated by AI") && acts_have(&c, "ID3v2.2"));
}

#[test]
fn mp3_truncated_tag_finds_audio_frame() {
    let d = cat(&[b"ID3\x03\x00\x00", &ssz(900), &[1, 2, 3], &AUDIO4]);
    let r = inspect_av(&d);
    assert!(r.findings[0].starts_with("truncated ID3v2.3 tag detected"));
    let c = clean(&d, true);
    assert_eq!(c.cleaned, AUDIO4);
    assert!(c.report.actions[0].contains("found audio frame at offset 13"));
}

#[test]
fn json_shape() {
    let v = serde_json::to_value(inspect_av(&mp4_xmp(b"x"))).unwrap();
    for k in ["format", "has_c2pa", "has_ai_metadata", "findings", "findings_confidence", "notes"] {
        assert!(v.get(k).is_some(), "{k}");
    }
    assert!(v.get("path").is_none());
}

// ---- no-panic sweeps ----
fn corpus() -> Vec<Vec<u8>> {
    let mut v: Vec<Vec<u8>> = std::fs::read_dir(data_dir())
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().is_some_and(|x| x == "bin"))
        .map(|e| std::fs::read(e.path()).unwrap())
        .collect();
    v.push(mp4_udta_tag(b"Generated by AI"));
    v.push(mp4_c2pa(b"manifest", b"c2pa"));
    v.push(wav(&[&fmt_chunk(), &list_info(b"Claude"), &riff(b"C2PA", b"x"), &data_chunk(7)]));
    v.push(mp3(&[&f4(b"TSSE", b"\x00Claude")], 4));
    v.push(flac(&[&f4(b"GEOB", &geob())], 4, b"", true));
    v
}

fn exercise(d: &[u8]) {
    let _ = detect_av_format(d);
    let _ = inspect_av(d);
    for all in [true, false] {
        let o = AvCleanOptions { strip_all_metadata: all };
        let _ = clean_av(d, &o);
        let _ = strip_id3v2(d, all);
        let _ = strip_wav(d, all);
        let _ = strip_flac(d, all);
        let _ = strip_mp4(d, all);
        let _ = strip_moov_udta(d, all);
    }
    let _ = inspect_id3v2(d);
    let _ = inspect_wav(d);
    let _ = inspect_flac(d);
    let _ = inspect_mp4(d);
    let _ = parse_id3v2_frames(d);
}

#[test]
fn truncated_prefixes_never_panic() {
    let c = corpus();
    assert!(c.len() > 150);
    for d in &c {
        for n in 0..=d.len() {
            exercise(&d[..n]);
        }
    }
}

#[test]
fn mutated_inputs_never_panic() {
    let mut s: u64 = 0x1234_5678_9abc_def0;
    let mut next = move || {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        s
    };
    for d in corpus() {
        if d.is_empty() {
            continue;
        }
        for _ in 0..12 {
            let mut m = d.clone();
            for _ in 0..3 {
                let at = (next() as usize) % m.len().min(64);
                m[at] = [0x00, 0xFF, 0x7F, 0x80, next() as u8][(next() % 5) as usize];
            }
            exercise(&m);
        }
    }
}
