//! Minimal zip reader/writer over `&[u8]` (stored + deflate via `miniz_oxide`),
//! written to reproduce the behaviour of Python's `zipfile` that the container
//! code depends on: which archives are rejected, which member reads fail (and
//! with which exception class), the decompressed-size budget, and the member
//! order. No filesystem, clock or threads.
//!
//! Differences from CPython: bzip2 / LZMA members (readable by Python when the
//! optional modules are present) report `NotImplementedError`; written archives
//! use a fixed 1980-01-01 timestamp and drop `extra` fields.

use crate::pyutil::{crc32, decode_cp437, py_str_repr};
use miniz_oxide::deflate::compress_to_vec;
use miniz_oxide::inflate::{decompress_to_vec_with_limit, TINFLStatus};

/// `container_meta.MAX_ZIP_DECOMPRESSED_BYTES`.
pub const MAX_ZIP_DECOMPRESSED_BYTES: u64 = 128 * 1024 * 1024;

const SIG_EOCD: &[u8] = b"PK\x05\x06";
const SIG_EOCD64: &[u8] = b"PK\x06\x06";
const SIG_EOCD64_LOC: &[u8] = b"PK\x06\x07";
const SIG_CEN: &[u8] = b"PK\x01\x02";
const SIG_LOC: &[u8] = b"PK\x03\x04";

/// A zip parse/read failure, tagged with the Python exception class name that
/// `zipfile` would have raised (`BadZipFile`, `NotImplementedError`,
/// `RuntimeError`, `EOFError`, `error` for `zlib.error`, ...).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZipError {
    pub class: &'static str,
    pub message: String,
}

impl ZipError {
    fn new(class: &'static str, message: impl Into<String>) -> Self {
        ZipError { class, message: message.into() }
    }
    fn bad(message: impl Into<String>) -> Self {
        Self::new("BadZipFile", message)
    }
}

/// Either an ordinary zip failure or `ZipBudgetExceeded` (which Python keeps
/// out of its `_ZIP_PARSE_ERRORS` handling so it propagates).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ZipFail {
    Parse(ZipError),
    Budget(String),
}

impl From<ZipError> for ZipFail {
    fn from(e: ZipError) -> Self {
        ZipFail::Parse(e)
    }
}

pub fn budget_message() -> String {
    format!(
        "zip decompressed size exceeds cap ({MAX_ZIP_DECOMPRESSED_BYTES} bytes); refusing to process"
    )
}

#[derive(Debug, Clone)]
pub struct ZipEntry {
    /// `ZipInfo.filename` (cut at the first NUL).
    pub name: String,
    orig_name: String,
    pub flag_bits: u16,
    pub method: u16,
    pub crc: u32,
    pub compress_size: u64,
    pub file_size: u64,
    header_offset: i128,
    end_offset: Option<i128>,
    pub external_attr: u32,
    pub comment: Vec<u8>,
}

#[derive(Debug)]
pub struct ZipArchive<'a> {
    data: &'a [u8],
    pub entries: Vec<ZipEntry>,
}

struct EndRec {
    size_cd: i128,
    offset_cd: i128,
    location: i128,
}

fn le16(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}
fn le32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}
fn le64(b: &[u8], at: usize) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[at..at + 8]);
    u64::from_le_bytes(a)
}

fn rfind(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if hay.len() < needle.len() {
        return None;
    }
    (0..=hay.len() - needle.len()).rev().find(|&i| &hay[i..i + needle.len()] == needle)
}

fn end_rec64(data: &[u8], location: usize, mut rec: EndRec) -> Result<EndRec, ZipError> {
    let off = location as i128 - 20;
    if off < 0 {
        return Ok(rec);
    }
    let off = off as usize;
    let loc = &data[off..off + 20];
    if &loc[..4] != SIG_EOCD64_LOC {
        return Ok(rec);
    }
    let diskno = le32(loc, 4);
    let reloff = le64(loc, 8);
    let disks = le32(loc, 16);
    if diskno != 0 || disks > 1 {
        return Err(ZipError::bad("zipfiles that span multiple disks are not supported"));
    }
    let offset = off as i128 - 56;
    if reloff as i128 > offset {
        return Err(ZipError::bad("Corrupt zip64 end of central directory locator"));
    }
    let reloff = reloff as usize;
    let mut extrasz = offset - reloff as i128;
    let offset = offset as usize;
    let mut rec64 = data.get(reloff..reloff + 56).unwrap_or(&[]);
    if !rec64.starts_with(SIG_EOCD64) && reloff != offset {
        extrasz = 0;
        rec64 = data.get(offset..offset + 56).unwrap_or(&[]);
    }
    if rec64.len() != 56 || !rec64.starts_with(SIG_EOCD64) {
        return Err(ZipError::bad("Zip64 end of central directory record not found"));
    }
    let sz = le64(rec64, 4) as i128;
    let dirsize = le64(rec64, 40) as i128;
    let diroffset = le64(rec64, 48) as i128;
    if diroffset + dirsize != reloff as i128 || sz + 12 != 56 + extrasz {
        return Err(ZipError::bad("Corrupt zip64 end of central directory record"));
    }
    rec.size_cd = dirsize;
    rec.offset_cd = diroffset;
    rec.location = offset as i128 - extrasz;
    Ok(rec)
}

fn end_rec(data: &[u8]) -> Result<Option<EndRec>, ZipError> {
    let filesize = data.len();
    let mk = |at: usize| -> EndRec {
        EndRec {
            size_cd: le32(data, at + 12) as i128,
            offset_cd: le32(data, at + 16) as i128,
            location: at as i128,
        }
    };
    if filesize >= 22 {
        let tail = &data[filesize - 22..];
        if &tail[..4] == SIG_EOCD && tail[20] == 0 && tail[21] == 0 {
            return end_rec64(data, filesize - 22, mk(filesize - 22)).map(Some);
        }
    }
    let max_comment_start = filesize.saturating_sub((1 << 16) + 22);
    let tail = &data[max_comment_start..];
    if let Some(start) = rfind(tail, SIG_EOCD) {
        if tail.len() - start < 22 {
            return Ok(None);
        }
        let at = max_comment_start + start;
        return end_rec64(data, at, mk(at)).map(Some);
    }
    Ok(None)
}

fn decode_extra(
    extra: &[u8],
    file_size: &mut u64,
    compress_size: &mut u64,
    header_offset: &mut u64,
) -> Result<(), ZipError> {
    let mut ex = extra;
    while ex.len() >= 4 {
        let tp = le16(ex, 0);
        let ln = le16(ex, 2) as usize;
        if ln + 4 > ex.len() {
            return Err(ZipError::bad(format!("Corrupt extra field {tp:04x} (size={ln})")));
        }
        if tp == 0x0001 {
            let mut d = &ex[4..ln + 4];
            let mut take = |field: &str| -> Result<u64, ZipError> {
                if d.len() < 8 {
                    return Err(ZipError::bad(format!("Corrupt zip64 extra field. {field} not found.")));
                }
                let v = le64(d, 0);
                d = &d[8..];
                Ok(v)
            };
            if *file_size == 0xFFFF_FFFF {
                *file_size = take("File size")?;
            }
            if *compress_size == 0xFFFF_FFFF {
                *compress_size = take("Compress size")?;
            }
            if *header_offset == 0xFFFF_FFFF {
                *header_offset = take("Header offset")?;
            }
        }
        ex = &ex[ln + 4..];
    }
    Ok(())
}

impl<'a> ZipArchive<'a> {
    /// `zipfile.ZipFile(io.BytesIO(data))`.
    pub fn open(data: &'a [u8]) -> Result<ZipArchive<'a>, ZipError> {
        let rec = end_rec(data)?.ok_or_else(|| ZipError::bad("File is not a zip file"))?;
        let concat = rec.location - rec.size_cd - rec.offset_cd;
        let start_dir = rec.offset_cd + concat;
        if start_dir < 0 {
            return Err(ZipError::bad("Bad offset for central directory"));
        }
        let size_cd = rec.size_cd;
        let cd: &[u8] = {
            let s = (start_dir as u128).min(data.len() as u128) as usize;
            let e = (start_dir as u128 + size_cd.max(0) as u128).min(data.len() as u128) as usize;
            &data[s..e]
        };
        let mut pos = 0usize;
        let mut total: i128 = 0;
        let mut entries: Vec<ZipEntry> = Vec::new();
        while total < size_cd {
            if cd.len() < pos + 46 {
                return Err(ZipError::bad("Truncated central directory"));
            }
            let c = &cd[pos..pos + 46];
            pos += 46;
            if &c[..4] != SIG_CEN {
                return Err(ZipError::bad("Bad magic number for central directory"));
            }
            let extract_version = c[6];
            let flags = le16(c, 8);
            let method = le16(c, 10);
            let crc = le32(c, 16);
            let mut compress_size = le32(c, 20) as u64;
            let mut file_size = le32(c, 24) as u64;
            let fnlen = le16(c, 28) as usize;
            let exlen = le16(c, 30) as usize;
            let cmlen = le16(c, 32) as usize;
            let external_attr = le32(c, 38);
            let mut header_offset = le32(c, 42) as u64;

            let take = |pos: &mut usize, n: usize| -> &[u8] {
                let e = (*pos + n).min(cd.len());
                let s = (*pos).min(e);
                *pos = e;
                &cd[s..e]
            };
            let raw_name = take(&mut pos, fnlen);
            let orig_name = if flags & 0x800 != 0 {
                match std::str::from_utf8(raw_name) {
                    Ok(s) => s.to_string(),
                    Err(e) => {
                        return Err(ZipError::new(
                            "UnicodeDecodeError",
                            format!("'utf-8' codec can't decode bytes: {e}"),
                        ))
                    }
                }
            } else {
                decode_cp437(raw_name)
            };
            let extra = take(&mut pos, exlen);
            let comment = take(&mut pos, cmlen).to_vec();
            if extract_version > 63 {
                return Err(ZipError::new(
                    "NotImplementedError",
                    format!("zip file version {:.1}", extract_version as f64 / 10.0),
                ));
            }
            decode_extra(extra, &mut file_size, &mut compress_size, &mut header_offset)?;
            let name = match orig_name.find('\0') {
                Some(i) => orig_name[..i].to_string(),
                None => orig_name.clone(),
            };
            entries.push(ZipEntry {
                name,
                orig_name,
                flag_bits: flags,
                method,
                crc,
                compress_size,
                file_size,
                header_offset: header_offset as i128 + concat,
                end_offset: None,
                external_attr,
                comment,
            });
            total += 46 + fnlen as i128 + exlen as i128 + cmlen as i128;
        }
        let mut order: Vec<usize> = (0..entries.len()).collect();
        order.sort_by(|&a, &b| entries[b].header_offset.cmp(&entries[a].header_offset));
        let mut end_offset = start_dir;
        for i in order {
            entries[i].end_offset = Some(end_offset);
            end_offset = entries[i].header_offset;
        }
        Ok(ZipArchive { data, entries })
    }

    /// `zf.namelist()`.
    pub fn names(&self) -> Vec<&str> {
        self.entries.iter().map(|e| e.name.as_str()).collect()
    }

    /// `zf.getinfo(name)`: the *last* entry carrying that name.
    pub fn find(&self, name: &str) -> Option<usize> {
        self.entries.iter().rposition(|e| e.name == name)
    }

    /// `_check_zip_budget(info, budget)`.
    pub fn check_budget(&self, idx: usize) -> Result<(), ZipFail> {
        if self.entries[idx].file_size > MAX_ZIP_DECOMPRESSED_BYTES {
            return Err(ZipFail::Budget(budget_message()));
        }
        Ok(())
    }

    /// `_read_zip_member(zf, info, budget)`: read one member, charging the
    /// bytes actually produced to `budget`.
    pub fn read(&self, idx: usize, budget: &mut u64) -> Result<Vec<u8>, ZipFail> {
        self.check_budget(idx)?;
        let e = &self.entries[idx];
        let data = self.data;
        let off = e.header_offset;
        if off < 0 || off as u128 > data.len() as u128 {
            return Err(ZipError::bad("Truncated file header").into());
        }
        let off = off as usize;
        let hdr = data.get(off..off + 30).ok_or_else(|| ZipError::bad("Truncated file header"))?;
        if &hdr[..4] != SIG_LOC {
            return Err(ZipError::bad("Bad magic number for file header").into());
        }
        let local_flags = le16(hdr, 6);
        let fnlen = le16(hdr, 26) as usize;
        let exlen = le16(hdr, 28) as usize;
        let name_end = (off + 30 + fnlen).min(data.len());
        let fname = &data[(off + 30).min(name_end)..name_end];
        let data_start = (name_end + exlen).min(data.len()).max(name_end);

        if e.flag_bits & 0x20 != 0 {
            return Err(ZipError::new("NotImplementedError", "compressed patched data (flag bit 5)").into());
        }
        if e.flag_bits & 0x40 != 0 {
            return Err(ZipError::new("NotImplementedError", "strong encryption (flag bit 6)").into());
        }
        let fname_str = if local_flags & 0x800 != 0 {
            match std::str::from_utf8(fname) {
                Ok(s) => s.to_string(),
                Err(err) => {
                    return Err(ZipError::new(
                        "UnicodeDecodeError",
                        format!("'utf-8' codec can't decode bytes: {err}"),
                    )
                    .into())
                }
            }
        } else {
            decode_cp437(fname)
        };
        if fname_str != e.orig_name {
            return Err(ZipError::bad(format!(
                "File name in directory {} and header {} differ.",
                py_str_repr(&e.orig_name),
                crate::pyutil::py_str_repr(&String::from_utf8_lossy(fname))
            ))
            .into());
        }
        if let Some(end) = e.end_offset {
            if data_start as i128 + e.compress_size as i128 > end {
                return Err(ZipError::bad(format!(
                    "Overlapped entries: {} (possible zip bomb)",
                    py_str_repr(&e.orig_name)
                ))
                .into());
            }
        }
        if e.flag_bits & 1 != 0 {
            return Err(ZipError::new(
                "RuntimeError",
                format!("File {} is encrypted, password required for extraction", py_str_repr(&e.name)),
            )
            .into());
        }
        if e.method != 0 && e.method != 8 {
            return Err(ZipError::new(
                "NotImplementedError",
                format!("compression type {}", e.method),
            )
            .into());
        }

        let csize = e.compress_size.min(usize::MAX as u64) as usize;
        let avail_end = data_start.saturating_add(csize).min(data.len());
        let avail = &data[data_start..avail_end];
        let truncated_file = avail.len() < csize;
        let remaining = MAX_ZIP_DECOMPRESSED_BYTES.saturating_sub(*budget);
        let cap = e.file_size.min(remaining + 1);

        let out: Vec<u8> = if e.method == 0 {
            let want = e.file_size.min(csize as u64) as usize;
            if avail.len() < want {
                return Err(ZipError::new("EOFError", "").into());
            }
            avail[..want].to_vec()
        } else if e.file_size == 0 {
            Vec::new()
        } else {
            match decompress_to_vec_with_limit(avail, cap as usize) {
                Ok(v) => v,
                Err(err) => match err.status {
                    TINFLStatus::HasMoreOutput => {
                        let mut v = err.output;
                        v.truncate(cap as usize);
                        v
                    }
                    TINFLStatus::NeedsMoreInput | TINFLStatus::FailedCannotMakeProgress => {
                        if truncated_file {
                            return Err(ZipError::new("EOFError", "").into());
                        }
                        err.output
                    }
                    _ => {
                        if (err.output.len() as u64) >= e.file_size.min(cap) {
                            let mut v = err.output;
                            v.truncate(cap as usize);
                            v
                        } else {
                            return Err(ZipError::new(
                                "error",
                                "Error -3 while decompressing data: invalid stored block lengths",
                            )
                            .into());
                        }
                    }
                },
            }
        };

        if (out.len() as u64) > remaining {
            *budget = budget.saturating_add(out.len() as u64);
            return Err(ZipFail::Budget(budget_message()));
        }
        *budget += out.len() as u64;
        if crc32(&out) != e.crc {
            return Err(ZipError::bad(format!("Bad CRC-32 for file {}", py_str_repr(&e.name))).into());
        }
        Ok(out)
    }
}

/// One member to write.
#[derive(Debug, Clone)]
pub struct OutEntry {
    pub name: String,
    /// 0 = stored, anything else = deflate.
    pub method: u16,
    pub external_attr: u32,
    pub comment: Vec<u8>,
    pub data: Vec<u8>,
}

impl OutEntry {
    /// An entry that keeps the source member's compression method, attributes
    /// and comment (as `ZipFile.writestr(zinfo, data)` does).
    pub fn from_source(src: &ZipEntry, data: Vec<u8>) -> OutEntry {
        OutEntry {
            name: src.name.clone(),
            method: if src.method == 0 { 0 } else { 8 },
            external_attr: if src.external_attr == 0 { 0o600 << 16 } else { src.external_attr },
            comment: src.comment.clone(),
            data,
        }
    }
}

const DOS_DATE_1980_01_01: u16 = 33;

/// Serialise a zip with a fixed 1980-01-01 00:00:00 timestamp.
pub fn write_zip(entries: &[OutEntry]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    struct Rec {
        flags: u16,
        method: u16,
        crc: u32,
        csize: u32,
        fsize: u32,
        name: Vec<u8>,
        comment: Vec<u8>,
        ext_attr: u32,
        offset: u64,
    }
    let mut recs: Vec<Rec> = Vec::with_capacity(entries.len());
    for e in entries {
        let name_bytes = e.name.as_bytes().to_vec();
        let flags: u16 = if e.name.is_ascii() { 0 } else { 0x800 };
        let method: u16 = if e.method == 0 { 0 } else { 8 };
        let payload = if method == 0 { e.data.clone() } else { compress_to_vec(&e.data, 6) };
        let offset = out.len() as u64;
        out.extend_from_slice(SIG_LOC);
        out.extend_from_slice(&20u16.to_le_bytes());
        out.extend_from_slice(&flags.to_le_bytes());
        out.extend_from_slice(&method.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&DOS_DATE_1980_01_01.to_le_bytes());
        let crc = crc32(&e.data);
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        out.extend_from_slice(&(e.data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&name_bytes);
        out.extend_from_slice(&payload);
        recs.push(Rec {
            flags,
            method,
            crc,
            csize: payload.len() as u32,
            fsize: e.data.len() as u32,
            name: name_bytes,
            comment: e.comment.clone(),
            ext_attr: e.external_attr,
            offset,
        });
    }
    let cd_start = out.len() as u64;
    for r in &recs {
        out.extend_from_slice(SIG_CEN);
        out.push(20);
        out.push(3);
        out.push(20);
        out.push(0);
        out.extend_from_slice(&r.flags.to_le_bytes());
        out.extend_from_slice(&r.method.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&DOS_DATE_1980_01_01.to_le_bytes());
        out.extend_from_slice(&r.crc.to_le_bytes());
        out.extend_from_slice(&r.csize.to_le_bytes());
        out.extend_from_slice(&r.fsize.to_le_bytes());
        out.extend_from_slice(&(r.name.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&(r.comment.len().min(0xFFFF) as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&r.ext_attr.to_le_bytes());
        out.extend_from_slice(&(r.offset as u32).to_le_bytes());
        out.extend_from_slice(&r.name);
        out.extend_from_slice(&r.comment[..r.comment.len().min(0xFFFF)]);
    }
    let cd_size = out.len() as u64 - cd_start;
    let n = recs.len() as u64;
    let need64 = n >= 0xFFFF || cd_start > 0xFFFF_FFFE || cd_size > 0xFFFF_FFFE;
    if need64 {
        let rec64_off = out.len() as u64;
        out.extend_from_slice(SIG_EOCD64);
        out.extend_from_slice(&44u64.to_le_bytes());
        out.extend_from_slice(&45u16.to_le_bytes());
        out.extend_from_slice(&45u16.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&n.to_le_bytes());
        out.extend_from_slice(&n.to_le_bytes());
        out.extend_from_slice(&cd_size.to_le_bytes());
        out.extend_from_slice(&cd_start.to_le_bytes());
        out.extend_from_slice(SIG_EOCD64_LOC);
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&rec64_off.to_le_bytes());
        out.extend_from_slice(&1u32.to_le_bytes());
    }
    out.extend_from_slice(SIG_EOCD);
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    let n16 = n.min(0xFFFF) as u16;
    out.extend_from_slice(&n16.to_le_bytes());
    out.extend_from_slice(&n16.to_le_bytes());
    out.extend_from_slice(&(cd_size.min(0xFFFF_FFFF) as u32).to_le_bytes());
    out.extend_from_slice(&(cd_start.min(0xFFFF_FFFF) as u32).to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}
