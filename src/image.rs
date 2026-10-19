//! MCUboot image format, mirroring scripts/imgtool/image.py.

use anyhow::{bail, ensure, Context, Result};
use sha2::Digest;
use std::collections::BTreeMap;
use std::fmt;

use crate::keys::{aes_ctr, EncKey, Key};

pub const IMAGE_MAGIC: u32 = 0x96f3_b83d;
pub const IMAGE_HEADER_SIZE: usize = 32;
const TLV_INFO_MAGIC: u16 = 0x6907;
const TLV_PROT_INFO_MAGIC: u16 = 0x6908;
const DEFAULT_MAX_ALIGN: usize = 8;
const MAGIC_SIZE: usize = 16;

const F_ENCRYPTED_AES128: u32 = 0x04;
const F_ENCRYPTED_AES256: u32 = 0x08;
const F_NON_BOOTABLE: u32 = 0x10;
const F_RAM_LOAD: u32 = 0x20;
const F_ROM_FIXED: u32 = 0x100;

pub mod tlv {
    pub const KEYHASH: u8 = 0x01;
    pub const PUBKEY: u8 = 0x02;
    pub const SHA256: u8 = 0x10;
    pub const SHA384: u8 = 0x11;
    pub const SHA512: u8 = 0x12;
    pub const ECDSASIG: u8 = 0x22;
    pub const ED25519: u8 = 0x24;
    pub const SIG_PURE: u8 = 0x25;
    pub const ENCEC256: u8 = 0x32;
    pub const ENCX25519: u8 = 0x33;
    pub const ENCX25519_SHA512: u8 = 0x34;
    pub const SEC_CNT: u8 = 0x50;
}

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Sha {
    S256,
    S384,
    S512,
}

impl Sha {
    fn tlv(self) -> u8 {
        match self {
            Sha::S256 => tlv::SHA256,
            Sha::S384 => tlv::SHA384,
            Sha::S512 => tlv::SHA512,
        }
    }

    fn from_tlv(t: u8) -> Option<Sha> {
        [Sha::S256, Sha::S384, Sha::S512].into_iter().find(|s| s.tlv() == t)
    }

    pub fn digest(self, data: &[u8]) -> Vec<u8> {
        match self {
            Sha::S256 => sha2::Sha256::digest(data).to_vec(),
            Sha::S384 => sha2::Sha384::digest(data).to_vec(),
            Sha::S512 => sha2::Sha512::digest(data).to_vec(),
        }
    }
}

/// key_and_user_sha_to_alg_and_tlv(): `user` None means "auto".
fn select_sha(key: Option<&Key>, user: Option<Sha>, pure: bool) -> Result<Sha> {
    let Some(key) = key else { return Ok(user.unwrap_or(Sha::S256)) };
    let allowed = key.allowed_sha(pure);
    match user {
        _ if allowed.is_empty() => bail!("Could not find allowed hash algorithms for {} key", key.shortname()),
        None => Ok(allowed[0]),
        _ if pure => Ok(allowed[0]),
        Some(s) if allowed.contains(&s) => Ok(s),
        Some(s) => bail!("Key {} can not be used with --sha {s:?}; allowed sha are one of {allowed:?}", key.shortname()),
    }
}

#[derive(Clone, Copy, Default, Debug, PartialEq)]
pub struct Version {
    pub major: u8,
    pub minor: u8,
    pub revision: u16,
    pub build: u32,
}

impl std::str::FromStr for Version {
    type Err = anyhow::Error;

    /// maj.min.rev+build with later parts optional, no leading zeros (version.py).
    fn from_str(s: &str) -> Result<Version> {
        let bad = || anyhow::anyhow!("Invalid version number, should be maj.min.rev+build with later parts optional");
        let num = |p: &str| -> Result<u64> {
            ensure!(!p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) && (p == "0" || !p.starts_with('0')), bad());
            p.parse().map_err(|_| bad())
        };
        let (main, build) = match s.split_once('+') {
            Some((m, b)) => (m, Some(b)),
            None => (s, None),
        };
        let parts: Vec<&str> = main.split('.').collect();
        // build is only valid after a full maj.min.rev
        ensure!(parts.len() <= 3 && (build.is_none() || parts.len() == 3), bad());
        let p = |i: usize| parts.get(i).map_or(Ok(0), |v| num(v));
        Ok(Version {
            major: p(0)?.try_into().map_err(|_| bad())?,
            minor: p(1)?.try_into().map_err(|_| bad())?,
            revision: p(2)?.try_into().map_err(|_| bad())?,
            build: build.map_or(Ok(0), num)?.try_into().map_err(|_| bad())?,
        })
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}.{}.{}+{}", self.major, self.minor, self.revision, self.build)
    }
}

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Endian {
    Little,
    Big,
}

impl Endian {
    fn u16(self, v: u16) -> [u8; 2] {
        if self == Endian::Big { v.to_be_bytes() } else { v.to_le_bytes() }
    }
    fn u32(self, v: u32) -> [u8; 4] {
        if self == Endian::Big { v.to_be_bytes() } else { v.to_le_bytes() }
    }
}

struct Tlv {
    endian: Endian,
    magic: u16,
    buf: Vec<u8>,
}

impl Tlv {
    fn new(endian: Endian, magic: u16) -> Tlv {
        Tlv { endian, magic, buf: Vec::new() }
    }

    fn add(&mut self, kind: u8, payload: &[u8]) {
        self.buf.extend([kind, 0]);
        self.buf.extend(self.endian.u16(payload.len() as u16));
        self.buf.extend(payload);
    }

    fn get(&self) -> Vec<u8> {
        if self.buf.is_empty() {
            return Vec::new();
        }
        let mut out = self.endian.u16(self.magic).to_vec();
        out.extend(self.endian.u16((4 + self.buf.len()) as u16));
        out.extend(&self.buf);
        out
    }
}

/// Everything `imgtool sign` needs except the key and the input bytes.
#[derive(Clone, Debug)]
pub struct Opts {
    pub version: Version,
    pub header_size: usize,
    pub pad_header: bool,
    pub pad: bool,
    pub confirm: bool,
    pub test: bool,
    pub align: usize,
    pub max_align: usize,
    pub slot_size: usize,
    pub max_sectors: usize,
    pub overwrite_only: bool,
    pub endian: Endian,
    pub load_addr: u32,
    pub rom_fixed: u32,
    pub erased_val: u8,
    pub security_counter: Option<u32>,
    pub non_bootable: bool,
    pub public_key_full: bool,
    pub sha: Option<Sha>,
    pub pure: bool,
    pub aes256: bool,
    pub clear: bool,
    pub hmac_sha: Sha,
    pub save_enctlv: bool,
    /// Some(ENC TLV value length) when encrypting; sizes the trailer key slots.
    pub enc_tlv_len: Option<usize>,
}

impl Opts {
    fn boot_magic(&self) -> Vec<u8> {
        if self.max_align == DEFAULT_MAX_ALIGN {
            return vec![0x77, 0xc2, 0x95, 0xf3, 0x60, 0xd2, 0xef, 0x7f, 0x35, 0x52, 0x50, 0x0f, 0x2c, 0xb6, 0x79, 0x80];
        }
        let mut m = self.endian.u16(self.max_align as u16).to_vec();
        m.extend([0x2d, 0xe1, 0x5d, 0x29, 0x41, 0x0b, 0x8d, 0x77, 0x67, 0x9c, 0x11, 0x0f, 0x1f, 0x8a]);
        m
    }

    fn magic_align_size(&self) -> usize {
        MAGIC_SIZE.next_multiple_of(self.max_align)
    }

    pub fn trailer_size(&self) -> Result<usize> {
        if self.overwrite_only {
            return Ok(self.max_align * 2 + self.magic_align_size());
        }
        ensure!([1, 2, 4, 8, 16, 32].contains(&self.align), "Invalid alignment: {}", self.align);
        let mut t = self.max_sectors * 3 * self.align + self.max_align * 4 + self.magic_align_size();
        if let Some(len) = self.enc_tlv_len {
            // two key slots; image.py sizes plain slots for 16 bytes even with AES-256
            let slot = if self.save_enctlv { len } else { 16 };
            t += slot.next_multiple_of(self.max_align) * 2;
        }
        Ok(t)
    }

    /// Offset of image_ok from the end of the slot.
    fn image_ok_from_end(&self) -> usize {
        self.magic_align_size() + self.max_align
    }

    /// The image_ok flag to write, if any (confirm sets it, test leaves it erased).
    fn image_ok_flag(&self) -> Option<Vec<u8>> {
        if !(self.test || self.confirm) || self.overwrite_only {
            return None;
        }
        let mut flag = vec![self.erased_val; self.max_align];
        if self.confirm {
            flag[0] = 0x01;
        }
        Some(flag)
    }
}

/// Image.load() + Image.create(): returns header + body + protected TLVs + TLVs.
pub fn create(input: &[u8], o: &Opts, key: Option<&Key>, enc: Option<&EncKey>) -> Result<Vec<u8>> {
    if let Some(k) = key {
        ensure!(k.is_private(), "Cannot sign with a public-only PEM; signing requires the private key.");
    }
    if let (Some(Key::P256(_)), Some(EncKey::X25519(_))) = (key, enc) {
        bail!("Signing and encryption must use the same type of key");
    }
    if let Some(e) = enc {
        e.check_hmac(o.hmac_sha)?;
    }
    ensure!(!(o.pure && o.sha.is_some()), "Pure signatures, currently, enforces preferred hash algorithm, and forbids sha selection by user.");
    ensure!(o.header_size >= IMAGE_HEADER_SIZE, "Minimum value for -H/--header-size is {IMAGE_HEADER_SIZE}");
    ensure!(o.load_addr == 0 || o.rom_fixed == 0, "Can not set rom_fixed and load_addr at the same time");

    let mut payload = Vec::with_capacity(input.len() + o.header_size + 1024);
    if o.pad_header {
        payload.resize(o.header_size, o.erased_val);
    }
    payload.extend_from_slice(input);
    ensure!(payload.len() >= o.header_size, "Input is smaller than the header size");
    ensure!(
        o.pad_header || payload[..o.header_size].iter().all(|&b| b == 0),
        "Header padding was not requested and image does not start with zeros"
    );

    if enc.is_some() {
        // AES-CTR works on whole blocks
        payload.resize(payload.len().next_multiple_of(16), 0);
    }

    let sha = select_sha(key, o.sha, o.pure)?;
    let e = o.endian;

    let mut prot = Tlv::new(e, TLV_PROT_INFO_MAGIC);
    if let Some(cnt) = o.security_counter {
        prot.add(tlv::SEC_CNT, &e.u32(cnt));
    }
    let prot = prot.get();

    let mut flags = 0;
    if o.load_addr != 0 {
        flags |= F_RAM_LOAD;
    }
    if o.rom_fixed != 0 {
        flags |= F_ROM_FIXED;
    }
    if o.non_bootable {
        flags |= F_NON_BOOTABLE;
    }
    if enc.is_some() {
        flags |= if o.aes256 { F_ENCRYPTED_AES256 } else { F_ENCRYPTED_AES128 };
    }
    let img_size = u32::try_from(payload.len() - o.header_size).context("image too large")?;
    let v = o.version;
    let mut hdr = Vec::with_capacity(IMAGE_HEADER_SIZE);
    hdr.extend(e.u32(IMAGE_MAGIC));
    hdr.extend(e.u32(if o.rom_fixed != 0 { o.rom_fixed } else { o.load_addr }));
    hdr.extend(e.u16(o.header_size as u16));
    hdr.extend(e.u16(prot.len() as u16));
    hdr.extend(e.u32(img_size));
    hdr.extend(e.u32(flags));
    hdr.extend([v.major, v.minor]);
    hdr.extend(e.u16(v.revision));
    hdr.extend(e.u32(v.build));
    hdr.extend([0; 4]);
    payload[..IMAGE_HEADER_SIZE].copy_from_slice(&hdr);

    // Protected TLVs are part of the hashed / signed region.
    let body_end = payload.len();
    payload.extend(&prot);

    let mut tlvs = Tlv::new(e, TLV_INFO_MAGIC);
    let digest = sha.digest(&payload);
    tlvs.add(sha.tlv(), &digest);
    if o.pure {
        tlvs.add(tlv::SIG_PURE, &[1]);
    }
    if let Some(k) = key {
        let pubder = k.public_der();
        if o.public_key_full {
            tlvs.add(tlv::PUBKEY, &pubder);
        } else {
            tlvs.add(tlv::KEYHASH, &sha.digest(&pubder));
        }
        tlvs.add(k.sig_tlv(), &k.sign(&payload, &digest, o.pure)?);
    }

    // Hash and signature cover the plaintext; only the body is encrypted.
    payload.truncate(body_end);
    if let Some(e) = enc {
        let mut plainkey = vec![0; if o.aes256 { 32 } else { 16 }];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut plainkey);
        let (kind, enctlv) = e.wrap(&plainkey, o.hmac_sha)?;
        tlvs.add(kind, &enctlv);
        if !o.clear {
            aes_ctr(&plainkey, &mut payload[o.header_size..]);
        }
    }
    payload.extend(&prot);
    payload.extend(tlvs.get());

    if o.slot_size > 0 {
        let tsize = o.trailer_size()?;
        ensure!(
            payload.len() + tsize <= o.slot_size,
            "Image size (0x{:x}) + trailer (0x{tsize:x}) exceeds requested size 0x{:x}",
            payload.len(),
            o.slot_size
        );
    }
    Ok(payload)
}

/// Image.pad_to(): fill to slot_size with erased_val and write the trailer.
pub fn pad_to_slot(payload: &mut Vec<u8>, o: &Opts) -> Result<()> {
    ensure!(payload.len() + o.trailer_size()? <= o.slot_size, "image does not fit in slot");
    payload.resize(o.slot_size, o.erased_val);
    let magic = o.boot_magic();
    let end = payload.len();
    payload[end - magic.len()..].copy_from_slice(&magic);
    if let Some(flag) = o.image_ok_flag() {
        // image.py only sets the first byte here; the rest is already erased
        payload[end - o.image_ok_from_end()] = flag[0];
    }
    Ok(())
}

/// Sparse trailer writes for hex output (Image.save() with .hex + --pad).
pub fn trailer_records(o: &Opts, base: u32) -> Result<Vec<(u32, Vec<u8>)>> {
    let slot_end = base as usize + o.slot_size;
    let tsize = o.trailer_size()?;
    let trailer_addr = slot_end - tsize;
    let mut out = Vec::new();
    if let Some(flag) = o.image_ok_flag() {
        out.push(((trailer_addr + tsize - o.image_ok_from_end()) as u32, flag));
    }
    let magic = o.boot_magic();
    out.push(((slot_end - magic.len()) as u32, magic));
    Ok(out)
}

#[derive(Debug)]
pub enum VerifyError {
    InvalidMagic,
    InvalidTlvInfoMagic,
    InvalidHash,
    InvalidSignature,
    KeyMismatch,
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(match self {
            VerifyError::InvalidMagic => "Invalid image magic; is this an MCUboot image?",
            VerifyError::InvalidTlvInfoMagic => "Invalid TLV info magic; is this an MCUboot image?",
            VerifyError::InvalidHash => "Image has an invalid hash",
            VerifyError::InvalidSignature => "No signature found for the given key",
            VerifyError::KeyMismatch => "Key type does not match TLV record",
        })
    }
}

pub struct Verified {
    pub version: Version,
    pub digest: Option<Vec<u8>>,
    pub signature: Option<Vec<u8>>,
}

/// Image.verify(). Little-endian images only, like image.py.
pub fn verify(b: &[u8], key: Option<&Key>) -> Result<Verified, VerifyError> {
    use VerifyError::*;
    let u16_at = |o: usize| b.get(o..o + 2).map(|s| u16::from_le_bytes([s[0], s[1]]));
    let u32_at = |o: usize| b.get(o..o + 4).map(|s| u32::from_le_bytes(s.try_into().unwrap()));

    if u32_at(0) != Some(IMAGE_MAGIC) || b.len() < IMAGE_HEADER_SIZE {
        return Err(InvalidMagic);
    }
    let version = Version {
        major: b[20],
        minor: b[21],
        revision: u16_at(22).unwrap(),
        build: u32_at(24).unwrap(),
    };
    let mut tlv_off = u16_at(8).unwrap() as usize + u32_at(12).unwrap() as usize;
    let mut magic = u16_at(tlv_off).ok_or(InvalidTlvInfoMagic)?;
    let mut tlv_tot = u16_at(tlv_off + 2).ok_or(InvalidTlvInfoMagic)? as usize;
    if magic == TLV_PROT_INFO_MAGIC {
        tlv_off += tlv_tot;
        magic = u16_at(tlv_off).ok_or(InvalidTlvInfoMagic)?;
        tlv_tot = u16_at(tlv_off + 2).ok_or(InvalidTlvInfoMagic)? as usize;
    }
    if magic != TLV_INFO_MAGIC {
        return Err(InvalidTlvInfoMagic);
    }

    let hash_region = &b[..tlv_off];
    let tlv_end = (tlv_off + tlv_tot).min(b.len());
    let mut entries = Vec::new();
    let mut off = tlv_off + 4;
    while off + 4 <= tlv_end {
        let len = u16_at(off + 2).unwrap() as usize;
        let val = b.get(off + 4..off + 4 + len).ok_or(InvalidTlvInfoMagic)?;
        entries.push((b[off], val));
        off += 4 + len;
    }
    let pure = entries.iter().any(|&(t, _)| t == tlv::SIG_PURE);

    let mut digest: Option<Vec<u8>> = None;
    for (t, val) in entries {
        if let Some(sha) = Sha::from_tlv(t) {
            if key.is_some_and(|k| select_sha(Some(k), Some(sha), false).is_err()) {
                return Err(KeyMismatch);
            }
            let d = sha.digest(hash_region);
            if d != val {
                return Err(InvalidHash);
            }
            if key.is_none() {
                return Ok(Verified { version, digest: Some(d), signature: None });
            }
            digest = Some(d);
        } else if let Some(k) = key.filter(|k| k.sig_tlv() == t) {
            // pure: the signature covers the whole hash region, not the digest
            if pure && t != tlv::ED25519 {
                continue;
            }
            if k.verify(val, hash_region, digest.as_deref().unwrap_or_default(), pure) {
                return Ok(if pure {
                    Verified { version, digest: None, signature: Some(val.to_vec()) }
                } else {
                    Verified { version, digest, signature: None }
                });
            }
        }
    }
    Err(InvalidSignature)
}

/// Intel HEX → (bytes from min to max address, gaps filled with 0xff, min address).
pub fn hex_to_bin(text: &str) -> Result<(Vec<u8>, u32)> {
    let mut mem = BTreeMap::new();
    let mut upper = 0u32;
    for (n, line) in text.lines().map(str::trim).enumerate().filter(|(_, l)| !l.is_empty()) {
        let bad = || anyhow::anyhow!("invalid hex record on line {}", n + 1);
        let hex = line.strip_prefix(':').ok_or_else(bad)?;
        ensure!(hex.len() % 2 == 0 && hex.len() >= 10, bad());
        let rec = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
            .collect::<Result<Vec<u8>, _>>()
            .map_err(|_| bad())?;
        ensure!(rec.len() == rec[0] as usize + 5, bad());
        ensure!(rec.iter().fold(0u8, |a, &x| a.wrapping_add(x)) == 0, "checksum error on line {}", n + 1);
        let addr = u16::from_be_bytes([rec[1], rec[2]]) as u32;
        let data = &rec[4..rec.len() - 1];
        match rec[3] {
            0 => {
                for (i, &d) in data.iter().enumerate() {
                    mem.insert(upper + addr + i as u32, d);
                }
            }
            1 => break,
            2 => upper = (u16::from_be_bytes([data[0], data[1]]) as u32) << 4,
            4 => upper = (u16::from_be_bytes([data[0], data[1]]) as u32) << 16,
            3 | 5 => {} // start address: irrelevant for the image
            t => bail!("unknown hex record type {t} on line {}", n + 1),
        }
    }
    let (Some((&min, _)), Some((&max, _))) = (mem.first_key_value(), mem.last_key_value()) else {
        bail!("hex file contains no data");
    };
    let mut out = vec![0xff; (max - min + 1) as usize];
    for (a, d) in mem {
        out[(a - min) as usize] = d;
    }
    Ok((out, min))
}

/// Intel HEX writer laid out like python-intelhex's tofile(): 16-byte records,
/// split at gaps and 64K boundaries, type-04 records only when data is above 64K.
pub fn bin_to_hex(segments: &[(u32, Vec<u8>)]) -> String {
    let mut mem = BTreeMap::new();
    for (base, data) in segments {
        for (i, &d) in data.iter().enumerate() {
            mem.insert(base + i as u32, d);
        }
    }
    let mem: Vec<(u32, u8)> = mem.into_iter().collect();
    let need_ela = mem.last().is_some_and(|&(a, _)| a > 0xffff);
    let mut out = String::new();
    let mut rec = |kind: u8, addr: u16, data: &[u8]| {
        let mut r = vec![data.len() as u8];
        r.extend(addr.to_be_bytes());
        r.push(kind);
        r.extend(data);
        r.push(r.iter().fold(0u8, |a, &x| a.wrapping_sub(x)));
        out.push(':');
        out.extend(r.iter().map(|b| format!("{b:02X}")));
        out.push('\n');
    };
    let mut high = None;
    let mut i = 0;
    while i < mem.len() {
        let start = mem[i].0;
        if need_ela && high != Some(start >> 16) {
            high = Some(start >> 16);
            rec(4, 0, &((start >> 16) as u16).to_be_bytes());
        }
        let mut j = i;
        while j < mem.len() && j - i < 16 && mem[j].0 == start + (j - i) as u32 && mem[j].0 >> 16 == start >> 16 {
            j += 1;
        }
        let data: Vec<u8> = mem[i..j].iter().map(|&(_, d)| d).collect();
        rec(0, start as u16, &data);
        i = j;
    }
    rec(1, 0, &[]);
    out
}
