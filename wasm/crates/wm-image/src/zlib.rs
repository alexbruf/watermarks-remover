//! Minimal zlib inflater with a hard output budget.
//!
//! Mirrors the behaviour of CPython's
//! `zlib.decompressobj().decompress(data, max_length=limit)` as used by
//! `_zlib_decompress_bounded`:
//!
//! * a truncated stream is not an error: whatever was fully decoded is returned;
//! * a corrupt stream (bad header, bad Huffman data, bad checksum) is an error;
//! * output that reaches the limit before the stream ends is a budget error.

/// PNG text is metadata, not a document (1 MiB decompressed cap).
pub const MAX_PNG_TEXT_DECOMPRESSED_BYTES: usize = 1 << 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InflateError {
    /// `zlib.error` in Python: the stream is corrupt.
    Corrupt,
    /// `PngTextBudgetExceeded` in Python: output reached the cap.
    BudgetExceeded,
}

enum Stop {
    Truncated,
    Corrupt,
    Budget,
}

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
    buf: u64,
    cnt: u32,
}

impl<'a> Reader<'a> {
    fn bits(&mut self, n: u32) -> Result<u32, Stop> {
        while self.cnt < n {
            let b = *self.data.get(self.pos).ok_or(Stop::Truncated)?;
            self.pos += 1;
            self.buf |= (b as u64) << self.cnt;
            self.cnt += 8;
        }
        let v = (self.buf & ((1u64 << n) - 1)) as u32;
        self.buf >>= n;
        self.cnt -= n;
        Ok(v)
    }

    fn align(&mut self) {
        self.buf = 0;
        self.cnt = 0;
    }
}

struct Huff {
    count: [u16; 16],
    symbol: Vec<u16>,
    max_len: usize,
}

#[derive(PartialEq, Eq, Clone, Copy)]
enum Kind {
    Codes,
    Other,
}

impl Huff {
    /// zlib's `inflate_table` acceptance rules: over-subscribed sets are
    /// errors; incomplete sets are errors unless they hold a single length-1
    /// code (and never for the code-length code); an all-zero set is allowed.
    fn build(lengths: &[u8], kind: Kind) -> Result<Huff, Stop> {
        let mut count = [0u16; 16];
        for &l in lengths {
            count[l as usize] += 1;
        }
        let mut max_len = 0;
        for len in (1..16).rev() {
            if count[len] != 0 {
                max_len = len;
                break;
            }
        }
        let mut left: i32 = 1;
        for &c in &count[1..16] {
            left <<= 1;
            left -= c as i32;
            if left < 0 {
                return Err(Stop::Corrupt);
            }
        }
        if max_len != 0 && left > 0 && (kind == Kind::Codes || max_len != 1) {
            return Err(Stop::Corrupt);
        }
        let mut offs = [0u16; 16];
        for len in 1..15 {
            offs[len + 1] = offs[len] + count[len];
        }
        let mut symbol = vec![0u16; lengths.len()];
        for (sym, &l) in lengths.iter().enumerate() {
            if l != 0 {
                symbol[offs[l as usize] as usize] = sym as u16;
                offs[l as usize] += 1;
            }
        }
        Ok(Huff { count, symbol, max_len })
    }

    fn decode(&self, r: &mut Reader) -> Result<u16, Stop> {
        if self.max_len == 0 {
            r.bits(1)?;
            return Err(Stop::Corrupt);
        }
        let mut code: i32 = 0;
        let mut first: i32 = 0;
        let mut index: i32 = 0;
        for len in 1..=self.max_len {
            code |= r.bits(1)? as i32;
            let count = self.count[len] as i32;
            if code - count < first {
                return self
                    .symbol
                    .get((index + (code - first)) as usize)
                    .copied()
                    .ok_or(Stop::Corrupt);
            }
            index += count;
            first += count;
            first <<= 1;
            code <<= 1;
        }
        Err(Stop::Corrupt)
    }
}

const LBASE: [u16; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
    163, 195, 227, 258,
];
const LEXT: [u8; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];
const DBASE: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
];
const DEXT: [u8; 30] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13,
];
const CLORDER: [usize; 19] = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];

fn adler32(data: &[u8]) -> u32 {
    let (mut a, mut b) = (1u32, 0u32);
    for chunk in data.chunks(5552) {
        for &x in chunk {
            a += x as u32;
            b += a;
        }
        a %= 65521;
        b %= 65521;
    }
    (b << 16) | a
}

fn emit(out: &mut Vec<u8>, limit: usize, byte: u8) -> Result<(), Stop> {
    if out.len() >= limit {
        return Err(Stop::Budget);
    }
    out.push(byte);
    Ok(())
}

fn codes(
    r: &mut Reader,
    out: &mut Vec<u8>,
    limit: usize,
    lit: &Huff,
    dist: &Huff,
) -> Result<(), Stop> {
    loop {
        let sym = lit.decode(r)? as usize;
        if sym < 256 {
            emit(out, limit, sym as u8)?;
        } else if sym == 256 {
            return Ok(());
        } else {
            let s = sym - 257;
            if s >= 29 {
                return Err(Stop::Corrupt);
            }
            let len = LBASE[s] as usize + r.bits(LEXT[s] as u32)? as usize;
            let ds = dist.decode(r)? as usize;
            if ds >= 30 {
                return Err(Stop::Corrupt);
            }
            let d = DBASE[ds] as usize + r.bits(DEXT[ds] as u32)? as usize;
            if out.len() >= limit {
                return Err(Stop::Budget);
            }
            if d > out.len() {
                return Err(Stop::Corrupt);
            }
            for _ in 0..len {
                let b = out[out.len() - d];
                emit(out, limit, b)?;
            }
        }
    }
}

fn fixed_tables() -> Result<(Huff, Huff), Stop> {
    let mut l = [0u8; 288];
    for (i, v) in l.iter_mut().enumerate() {
        *v = match i {
            0..=143 => 8,
            144..=255 => 9,
            256..=279 => 7,
            _ => 8,
        };
    }
    let lit = Huff::build(&l, Kind::Other)?;
    let dist = Huff::build(&[5u8; 32], Kind::Other)?;
    Ok((lit, dist))
}

fn dynamic_tables(r: &mut Reader) -> Result<(Huff, Huff), Stop> {
    let nlen = r.bits(5)? as usize + 257;
    let ndist = r.bits(5)? as usize + 1;
    let ncode = r.bits(4)? as usize + 4;
    if nlen > 286 || ndist > 30 {
        return Err(Stop::Corrupt);
    }
    let mut cl = [0u8; 19];
    for &o in CLORDER.iter().take(ncode) {
        cl[o] = r.bits(3)? as u8;
    }
    let clh = Huff::build(&cl, Kind::Codes)?;
    let mut lens = vec![0u8; nlen + ndist];
    let mut have = 0usize;
    while have < nlen + ndist {
        let sym = if clh.max_len == 0 {
            // zlib's degenerate all-invalid table decodes as length 0, 1 bit.
            r.bits(1)?;
            0
        } else {
            clh.decode(r)?
        };
        if sym < 16 {
            lens[have] = sym as u8;
            have += 1;
        } else {
            let (prev, repeat) = match sym {
                16 => {
                    let extra = r.bits(2)? as usize;
                    if have == 0 {
                        return Err(Stop::Corrupt);
                    }
                    (lens[have - 1], 3 + extra)
                }
                17 => (0, 3 + r.bits(3)? as usize),
                _ => (0, 11 + r.bits(7)? as usize),
            };
            if have + repeat > nlen + ndist {
                return Err(Stop::Corrupt);
            }
            for _ in 0..repeat {
                lens[have] = prev;
                have += 1;
            }
        }
    }
    if lens[256] == 0 {
        return Err(Stop::Corrupt);
    }
    let lit = Huff::build(&lens[..nlen], Kind::Other)?;
    let dist = Huff::build(&lens[nlen..], Kind::Other)?;
    Ok((lit, dist))
}

fn inflate(data: &[u8], limit: usize, out: &mut Vec<u8>) -> Result<bool, Stop> {
    // zlib header (2 bytes). Fewer than 2 bytes is simply "need more input".
    if data.len() < 2 {
        return Err(Stop::Truncated);
    }
    let (cmf, flg) = (data[0] as u32, data[1] as u32);
    if ((cmf << 8) + flg) % 31 != 0 || (cmf & 15) != 8 || (cmf >> 4) + 8 > 15 {
        return Err(Stop::Corrupt);
    }
    let mut r = Reader { data, pos: 2, buf: 0, cnt: 0 };
    if flg & 0x20 != 0 {
        // preset dictionary: zlib reports "need dict" once the id is read.
        return Err(if data.len() >= 6 { Stop::Corrupt } else { Stop::Truncated });
    }
    loop {
        let last = r.bits(1)?;
        let btype = r.bits(2)?;
        match btype {
            0 => {
                r.align();
                let len = r.bits(16)? as usize;
                let nlen = r.bits(16)? as usize;
                if len != (!nlen & 0xffff) {
                    return Err(Stop::Corrupt);
                }
                for _ in 0..len {
                    if out.len() >= limit {
                        return Err(Stop::Budget);
                    }
                    let b = *r.data.get(r.pos).ok_or(Stop::Truncated)?;
                    r.pos += 1;
                    out.push(b);
                }
            }
            1 => {
                let (lit, dist) = fixed_tables()?;
                codes(&mut r, out, limit, &lit, &dist)?;
            }
            2 => {
                let (lit, dist) = dynamic_tables(&mut r)?;
                codes(&mut r, out, limit, &lit, &dist)?;
            }
            _ => return Err(Stop::Corrupt),
        }
        if last == 1 {
            break;
        }
    }
    r.align();
    let tail = r.data.get(r.pos..r.pos + 4).ok_or(Stop::Truncated)?;
    let want = u32::from_be_bytes([tail[0], tail[1], tail[2], tail[3]]);
    if want != adler32(out) {
        return Err(Stop::Corrupt);
    }
    Ok(true)
}

/// Inflate zlib data, refusing output that reaches `limit` bytes before the
/// stream ends.
pub fn zlib_decompress_bounded_with_limit(
    data: &[u8],
    limit: usize,
) -> Result<Vec<u8>, InflateError> {
    let mut out = Vec::new();
    match inflate(data, limit, &mut out) {
        Ok(_) => Ok(out),
        Err(Stop::Corrupt) => Err(InflateError::Corrupt),
        Err(Stop::Budget) => Err(InflateError::BudgetExceeded),
        Err(Stop::Truncated) => {
            if out.len() >= limit {
                Err(InflateError::BudgetExceeded)
            } else {
                Ok(out)
            }
        }
    }
}

/// `_zlib_decompress_bounded`: 1 MiB cap.
pub fn zlib_decompress_bounded(data: &[u8]) -> Result<Vec<u8>, InflateError> {
    zlib_decompress_bounded_with_limit(data, MAX_PNG_TEXT_DECOMPRESSED_BYTES)
}
