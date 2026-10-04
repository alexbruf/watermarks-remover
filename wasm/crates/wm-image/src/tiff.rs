//! TIFF (classic and BigTIFF): IFD walker, inspect and in-place strip.
//!
//! Offsets and counts are handled as `u128` where Python's unbounded integers
//! could otherwise overflow (a BigTIFF entry count is a u64, and
//! `count * entry_size` or `value_offset + byte_size` can exceed 64 bits).

use crate::common::*;
use std::collections::{BTreeMap, BTreeSet};

pub const MAX_TIFF_IFDS: usize = 4096;

fn type_size(ftype: u16) -> u128 {
    match ftype {
        1 | 2 | 6 | 7 => 1,
        3 | 8 => 2,
        4 | 9 | 11 => 4,
        5 | 10 | 12 => 8,
        _ => 1,
    }
}

/// Provenance / descriptive metadata tags stripped when cleaning TIFF.
pub fn tiff_meta_tag_name(tag: u16) -> Option<&'static str> {
    Some(match tag {
        269 => "DocumentName",
        270 => "ImageDescription",
        271 => "Make",
        272 => "Model",
        305 => "Software",
        306 => "DateTime",
        315 => "Artist",
        316 => "HostComputer",
        33432 => "Copyright",
        40091 => "XPTitle",
        40092 => "XPComment",
        40093 => "XPAuthor",
        40094 => "XPKeywords",
        40095 => "XPSubject",
        700 => "XMP",
        33723 => "IPTC/NAA",
        34377 => "Photoshop",
        34665 => "ExifIFD",
        34853 => "GPSInfo",
        37500 => "MakerNote",
        _ => return None,
    })
}

/// Structural tags that must survive even when their payload looks marker-ish.
fn is_keep_tag(tag: u16) -> bool {
    matches!(
        tag,
        254 | 255 | 256 | 257 | 258 | 259 | 262 | 263 | 264 | 265 | 266 | 273 | 274 | 277 | 278
            | 279 | 282 | 283 | 284 | 285 | 286 | 287 | 288 | 289 | 290 | 291 | 292 | 293 | 294
            | 295 | 296 | 297 | 301 | 302 | 304 | 320..=347 | 512..=521 | 529..=533 | 33421
            | 33422 | 33423 | 34675 | 34676 | 50706..=50741
    )
}

fn is_sub_ifd_tag3(tag: u16) -> bool {
    matches!(tag, 34665 | 34853 | 40965)
}

fn is_sub_ifd_tag2(tag: u16) -> bool {
    matches!(tag, 34665 | 34853)
}

#[derive(Debug, Clone)]
pub struct TiffEntry {
    pub tag: u16,
    pub ftype: u16,
    pub count: u64,
    /// Inline value field bytes (4 for classic, 8 for BigTIFF).
    pub value: Vec<u8>,
    pub byte_size: u128,
    pub value_offset: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct TiffIfd {
    pub count: u64,
    pub entries: Vec<TiffEntry>,
    pub next: u64,
    pub block_len: usize,
}

#[derive(Debug, Clone)]
pub struct TiffLayout {
    pub little: bool,
    pub bigtiff: bool,
}

pub fn tiff_layout(data: &[u8]) -> Option<TiffLayout> {
    let head = data.get(..4)?;
    match head {
        b"II*\x00" => Some(TiffLayout { little: true, bigtiff: false }),
        b"MM\x00*" => Some(TiffLayout { little: false, bigtiff: false }),
        b"II+\x00" => Some(TiffLayout { little: true, bigtiff: true }),
        b"MM\x00+" => Some(TiffLayout { little: false, bigtiff: true }),
        _ => None,
    }
}

fn read_uint(bytes: &[u8], little: bool) -> u64 {
    let mut v: u64 = 0;
    if little {
        for &b in bytes.iter().take(8).rev() {
            v = (v << 8) | b as u64;
        }
    } else {
        for &b in bytes.iter().take(8) {
            v = (v << 8) | b as u64;
        }
    }
    v
}

/// Port of `_parse_tiff_ifds`: `(layout, {offset: ifd})`.
pub fn parse_tiff_ifds(data: &[u8]) -> Result<(TiffLayout, BTreeMap<u64, TiffIfd>), ImageError> {
    let layout = tiff_layout(data).ok_or_else(|| ImageError::new("not a TIFF"))?;
    let (bo_little, bigtiff) = (layout.little, layout.bigtiff);
    let n = data.len() as u128;
    let count_len: usize = if bigtiff { 8 } else { 2 };
    let off_len: usize = if bigtiff { 8 } else { 4 };
    let entry_size: usize = if bigtiff { 20 } else { 12 };
    let header_size: usize = if bigtiff { 16 } else { 8 };
    let mut ifds: BTreeMap<u64, TiffIfd> = BTreeMap::new();
    if data.len() < header_size {
        return Ok((layout, ifds));
    }
    let first = read_uint(&data[header_size - off_len..header_size], bo_little);
    if first == 0 || first as u128 + count_len as u128 > n {
        return Ok((layout, ifds));
    }
    let mut seen: BTreeSet<u64> = BTreeSet::new();
    let mut todo: Vec<u64> = vec![first];
    while let Some(off) = todo.pop() {
        if ifds.len() >= MAX_TIFF_IFDS {
            break;
        }
        if seen.contains(&off) || off as u128 + count_len as u128 > n {
            continue;
        }
        seen.insert(off);
        let offu = off as usize; // off < n <= usize::MAX
        let count = read_uint(&data[offu..offu + count_len], bo_little);
        let mut block_len: u128 = count_len as u128 + count as u128 * entry_size as u128;
        let next_ptr: u64;
        if offu as u128 + block_len + off_len as u128 <= n {
            let at = offu + block_len as usize;
            next_ptr = read_uint(&data[at..at + off_len], bo_little);
        } else {
            block_len = n.saturating_sub(offu as u128 + off_len as u128);
            next_ptr = 0;
        }
        let mut entries: Vec<TiffEntry> = Vec::new();
        let mut i: u128 = 0;
        while i < count as u128 {
            let e = offu as u128 + count_len as u128 + i * entry_size as u128;
            if e + entry_size as u128 > n {
                break;
            }
            let e = e as usize;
            let tag = rd_u16(data, e, bo_little).unwrap_or(0);
            let ftype = rd_u16(data, e + 2, bo_little).unwrap_or(0);
            let fcount = read_uint(&data[e + 4..e + 4 + off_len], bo_little);
            let value = data[e + 4 + off_len..e + entry_size].to_vec();
            let byte_size = fcount as u128 * type_size(ftype);
            let value_offset = if byte_size > value.len() as u128 {
                Some(read_uint(&value[..off_len], bo_little))
            } else {
                None
            };
            entries.push(TiffEntry { tag, ftype, count: fcount, value, byte_size, value_offset });
            i += 1;
        }
        let sub_ptrs: Vec<u64> = entries
            .iter()
            .filter(|e| is_sub_ifd_tag3(e.tag))
            .map(|e| read_uint(&e.value[..off_len], bo_little))
            .collect();
        ifds.insert(off, TiffIfd { count, entries, next: next_ptr, block_len: block_len as usize });
        if next_ptr != 0 {
            todo.push(next_ptr);
        }
        for ptr in sub_ptrs {
            if ptr != 0 {
                todo.push(ptr);
            }
        }
    }
    Ok((layout, ifds))
}

/// Python `_tiff_entry_payload(...) or b""`.
pub fn tiff_entry_payload<'a>(data: &'a [u8], ent: &'a TiffEntry) -> &'a [u8] {
    match ent.value_offset {
        None => {
            if ent.byte_size <= ent.value.len() as u128 {
                &ent.value[..ent.byte_size as usize]
            } else {
                &[]
            }
        }
        Some(vo) => {
            let start = (vo as u128).min(data.len() as u128) as usize;
            let end = (vo as u128 + ent.byte_size).min(data.len() as u128) as usize;
            if start >= end {
                &[]
            } else {
                &data[start..end]
            }
        }
    }
}

pub fn inspect_tiff(data: &[u8]) -> Inspection {
    let mut findings: Vec<String> = Vec::new();
    let mut has_c2pa = false;
    let mut has_ai = false;
    let Ok((_layout, ifds)) = parse_tiff_ifds(data) else {
        return (false, false, vec!["not a valid TIFF".to_string()]);
    };
    if ifds.is_empty() {
        return (false, false, vec!["TIFF with no image file directories".to_string()]);
    }
    for ifd in ifds.values() {
        for ent in &ifd.entries {
            let tag = ent.tag;
            let payload = tiff_entry_payload(data, ent);
            let hits = contains_ai_or_c2pa(payload);
            if !hits.is_empty() {
                if any_lower_in(&hits, &["c2pa", "contentcredentials", "jumb", "contentauth"]) {
                    has_c2pa = true;
                }
                has_ai = true;
                findings.push(format!("TIFF tag {tag}: {}", join_first(&hits, 6)));
            }
            if let Some(name) = tiff_meta_tag_name(tag) {
                let label = if is_sub_ifd_tag3(tag) { "sub-IFD" } else { "tag" };
                findings.push(format!("TIFF {label} {tag} ({name}) present"));
            }
        }
    }
    let whole = contains_any(data, &C2PA_MARKERS);
    if !whole.is_empty() && !has_c2pa {
        has_c2pa = true;
        findings.push(format!("byte-scan C2PA markers: {}", join_first(&whole, 6)));
    }
    if findings.is_empty() {
        findings.push("no TIFF metadata tags found".to_string());
    }
    (has_c2pa, has_ai || has_c2pa, findings)
}

type Range = (u128, u128);

#[allow(clippy::too_many_arguments)]
fn collect_sub_ifd_drops(
    little: bool,
    off_len: usize,
    ifds: &BTreeMap<u64, TiffIfd>,
    data_len: u128,
    ptr: u64,
    drop_ranges: &mut Vec<Range>,
    drop_ifd_ranges: &mut Vec<Range>,
    seen: &mut BTreeSet<u64>,
) {
    let Some(sub) = ifds.get(&ptr) else { return };
    if seen.contains(&ptr) {
        return;
    }
    seen.insert(ptr);
    drop_ifd_ranges
        .push((ptr as u128, (ptr as u128 + sub.block_len as u128 + off_len as u128).min(data_len)));
    for ent in &sub.entries {
        if is_sub_ifd_tag2(ent.tag) {
            let p2 = read_uint(&ent.value[..off_len], little);
            if p2 != 0 {
                collect_sub_ifd_drops(little, off_len, ifds, data_len, p2, drop_ranges, drop_ifd_ranges, seen);
            }
        } else if let Some(vo) = ent.value_offset {
            let (vo, vs) = (vo as u128, ent.byte_size);
            if vo + vs <= data_len {
                drop_ranges.push((vo, vo + vs));
            }
        }
    }
}

fn covered(ranges: &[Range], start: u128, end: u128) -> bool {
    ranges.iter().any(|&(s, e)| s <= start && end <= e)
}

pub fn strip_tiff(data: &[u8], strip_all_metadata: bool) -> Stripped {
    let (layout, ifds) = parse_tiff_ifds(data)?;
    if ifds.is_empty() {
        return Err(ImageError::new("not a valid TIFF (no image file directories)"));
    }
    let (little, bigtiff) = (layout.little, layout.bigtiff);
    let n = data.len();
    let n128 = n as u128;
    let off_len: usize = if bigtiff { 8 } else { 4 };
    let mut actions: Vec<String> = Vec::new();
    let mut kept: BTreeMap<u64, Vec<TiffEntry>> = BTreeMap::new();
    let mut drop_ranges: Vec<Range> = Vec::new();
    let mut drop_ifd_ranges: Vec<Range> = Vec::new();

    for (&off, ifd) in &ifds {
        let mut keep_here: Vec<TiffEntry> = Vec::new();
        for ent in &ifd.entries {
            let tag = ent.tag;
            let payload = tiff_entry_payload(data, ent);
            let mut marker_hit = has_ai_or_c2pa(payload);
            if is_sub_ifd_tag2(tag) {
                let ptr = read_uint(&ent.value[..off_len], little);
                if let Some(sub) = ifds.get(&ptr) {
                    let end = (ptr as u128 + sub.block_len as u128 + off_len as u128).min(n128) as usize;
                    let sub_blob = slice_clamped(data, ptr as usize, end);
                    marker_hit = marker_hit || has_ai_or_c2pa(sub_blob);
                    for sent in &sub.entries {
                        if has_ai_or_c2pa(tiff_entry_payload(data, sent)) {
                            marker_hit = true;
                            break;
                        }
                    }
                }
            }
            let mut drop = false;
            if tiff_meta_tag_name(tag).is_some() {
                drop = strip_all_metadata || marker_hit;
            } else if marker_hit && !is_keep_tag(tag) {
                drop = true;
            }
            if !drop {
                keep_here.push(ent.clone());
                continue;
            }
            match tiff_meta_tag_name(tag) {
                Some(name) => actions.push(format!("drop TIFF tag {tag} ({name})")),
                None => actions.push(format!("drop TIFF tag {tag} (AI markers)")),
            }
            if is_sub_ifd_tag2(tag) {
                let ptr = read_uint(&ent.value[..off_len], little);
                collect_sub_ifd_drops(
                    little,
                    off_len,
                    &ifds,
                    n128,
                    ptr,
                    &mut drop_ranges,
                    &mut drop_ifd_ranges,
                    &mut BTreeSet::new(),
                );
            } else if let Some(vo) = ent.value_offset {
                if vo as u128 + ent.byte_size <= n128 {
                    drop_ranges.push((vo as u128, vo as u128 + ent.byte_size));
                }
            }
        }
        kept.insert(off, keep_here);
    }

    // Ranges still referenced from the root through kept entries must never be
    // zeroed. An orphaned sub-IFD (its pointer dropped) contributes nothing.
    let mut reachable: BTreeSet<u64> = BTreeSet::new();
    let root = if bigtiff {
        read_uint(&data[16 - off_len..16], little)
    } else {
        read_uint(&data[8 - off_len..8], little)
    };
    let mut stack: Vec<u64> = vec![root];
    while let Some(off) = stack.pop() {
        if reachable.contains(&off) || !ifds.contains_key(&off) {
            continue;
        }
        reachable.insert(off);
        if let Some(ents) = kept.get(&off) {
            for ent in ents {
                if is_sub_ifd_tag3(ent.tag) {
                    stack.push(read_uint(&ent.value[..off_len], little));
                }
            }
        }
        let next = ifds[&off].next;
        if next != 0 {
            stack.push(next);
        }
    }

    let mut referenced: Vec<Range> = Vec::new();
    for off in &reachable {
        if let Some(ents) = kept.get(off) {
            for ent in ents {
                if let Some(vo) = ent.value_offset {
                    if vo as u128 + ent.byte_size <= n128 {
                        referenced.push((vo as u128, vo as u128 + ent.byte_size));
                    }
                }
                if is_sub_ifd_tag3(ent.tag) {
                    let ptr = read_uint(&ent.value[..off_len], little);
                    if let Some(sub) = ifds.get(&ptr) {
                        referenced.push((
                            ptr as u128,
                            (ptr as u128 + sub.block_len as u128 + off_len as u128).min(n128),
                        ));
                    }
                }
            }
        }
    }

    let mut zero: Vec<Range> = Vec::new();
    for &(s, e) in &drop_ranges {
        if !covered(&referenced, s, e) {
            zero.push((s, e));
        }
    }
    for &(s, e) in &drop_ifd_ranges {
        if !covered(&referenced, s, e) {
            zero.push((s, e));
        }
    }

    // Patch IFD entry regions in place, then zero dropped payloads.
    let mut out = data.to_vec();
    for (&off, ifd) in &ifds {
        let entries = kept.get(&off).map(Vec::as_slice).unwrap_or(&[]);
        let mut block: Vec<u8> = Vec::new();
        if bigtiff {
            let c = entries.len() as u64;
            block.extend_from_slice(&if little { c.to_le_bytes() } else { c.to_be_bytes() });
        } else {
            let c = entries.len() as u16;
            block.extend_from_slice(&if little { c.to_le_bytes() } else { c.to_be_bytes() });
        }
        for ent in entries {
            block.extend_from_slice(&if little { ent.tag.to_le_bytes() } else { ent.tag.to_be_bytes() });
            block.extend_from_slice(&if little { ent.ftype.to_le_bytes() } else { ent.ftype.to_be_bytes() });
            push_off(&mut block, ent.count, bigtiff, little);
            block.extend_from_slice(&ent.value);
        }
        push_off(&mut block, ifd.next, bigtiff, little);
        let region_len = ifd.block_len + off_len;
        let offu = off as usize;
        if offu as u128 + region_len as u128 <= n128 {
            block.truncate(region_len);
            block.resize(region_len, 0);
            out[offu..offu + region_len].copy_from_slice(&block);
        }
    }
    for &(s, e) in &zero {
        for b in &mut out[s as usize..e as usize] {
            *b = 0;
        }
    }

    if actions.is_empty() {
        actions.push("no TIFF metadata tags removed (already clean or none matched)".to_string());
    }
    Ok((out, actions))
}

/// `struct.pack(off_fmt, v)`: u64 for BigTIFF, u32 for classic.
fn push_off(block: &mut Vec<u8>, v: u64, bigtiff: bool, little: bool) {
    if bigtiff {
        block.extend_from_slice(&if little { v.to_le_bytes() } else { v.to_be_bytes() });
    } else {
        let v = v as u32;
        block.extend_from_slice(&if little { v.to_le_bytes() } else { v.to_be_bytes() });
    }
}
