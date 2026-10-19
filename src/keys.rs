//! Key loading / signing, mirroring scripts/imgtool/keys/*.py.

use anyhow::{bail, ensure, Context, Result};
use ed25519_dalek::{Signer, Verifier};
use p256::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey, LineEnding};
use rand_core::OsRng;

use crate::image::{tlv, Sha};

/// Public key the AES image key is wrapped for (ECIES, image.py ecies_hkdf()).
pub enum EncKey {
    P256(p256::PublicKey),
    X25519(x25519_dalek::PublicKey),
}

// No pkcs8 support in x25519-dalek; X25519 SPKI / PKCS#8 DER have fixed prefixes.
const X25519_SPKI_PREFIX: &[u8] = &[0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00];
const X25519_PKCS8_PREFIX: &[u8] = &[0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20];

impl EncKey {
    /// Accepts the public key or the keypair, like imgtool's load_key().
    pub fn load(path: &str) -> Result<EncKey> {
        let pem = std::fs::read_to_string(path).with_context(|| format!("cannot read key {path}"))?;
        if let Ok(k) = p256::PublicKey::from_public_key_pem(&pem) {
            return Ok(EncKey::P256(k));
        }
        if let Ok(k) = p256::SecretKey::from_pkcs8_pem(&pem).or_else(|_| p256::SecretKey::from_sec1_pem(&pem)) {
            return Ok(EncKey::P256(k.public_key()));
        }
        if let Ok((_, der)) = p256::pkcs8::der::pem::decode_vec(pem.as_bytes()) {
            let raw = |prefix: &[u8]| -> Option<[u8; 32]> { der.strip_prefix(prefix)?.try_into().ok() };
            if let Some(b) = raw(X25519_SPKI_PREFIX) {
                return Ok(EncKey::X25519(b.into()));
            }
            if let Some(b) = raw(X25519_PKCS8_PREFIX) {
                return Ok(EncKey::X25519((&x25519_dalek::StaticSecret::from(b)).into()));
            }
        }
        bail!("{path}: unsupported encryption key (supported: ECDSA P-256, X25519 PEM)")
    }

    pub fn check_hmac(&self, hmac: Sha) -> Result<()> {
        ensure!(hmac == Sha::S256 || matches!(self, EncKey::X25519(_)), "Currently only ECIES-X25519 supports HMAC-SHA512");
        Ok(())
    }

    /// Length of the ENC TLV value: ephemeral pubkey + mac + wrapped key.
    pub fn tlv_len(&self, keylen: usize, hmac: Sha) -> usize {
        let pubk = if matches!(self, EncKey::P256(_)) { 65 } else { 32 };
        pubk + hmac.digest(&[]).len() + keylen
    }

    /// ECIES: ECDH with an ephemeral key, HKDF("MCUBoot_ECIES_v1"), AES-CTR wrap, HMAC.
    /// Returns (TLV type, ephemeral pubkey || mac || wrapped key).
    pub fn wrap(&self, plainkey: &[u8], hmac: Sha) -> Result<(u8, Vec<u8>)> {
        self.check_hmac(hmac)?;
        let (shared, mut out, kind) = match self {
            EncKey::P256(pk) => {
                let e = p256::ecdh::EphemeralSecret::random(&mut OsRng);
                let pubk = p256::EncodedPoint::from(e.public_key()).as_bytes().to_vec();
                (e.diffie_hellman(pk).raw_secret_bytes().to_vec(), pubk, tlv::ENCEC256)
            }
            EncKey::X25519(pk) => {
                let e = x25519_dalek::EphemeralSecret::random_from_rng(OsRng);
                let pubk = x25519_dalek::PublicKey::from(&e).as_bytes().to_vec();
                let kind = if hmac == Sha::S512 { tlv::ENCX25519_SHA512 } else { tlv::ENCX25519 };
                (e.diffie_hellman(pk).as_bytes().to_vec(), pubk, kind)
            }
        };
        let n = plainkey.len();
        let mut derived = vec![0; n + hmac.digest(&[]).len()];
        match hmac {
            Sha::S512 => hkdf::Hkdf::<sha2::Sha512>::new(None, &shared).expand(b"MCUBoot_ECIES_v1", &mut derived),
            _ => hkdf::Hkdf::<sha2::Sha256>::new(None, &shared).expand(b"MCUBoot_ECIES_v1", &mut derived),
        }
        .map_err(|_| anyhow::anyhow!("HKDF output too long"))?;
        let mut cipherkey = plainkey.to_vec();
        aes_ctr(&derived[..n], &mut cipherkey);
        out.extend(hmac_mac(hmac, &derived[n..], &cipherkey));
        out.extend(cipherkey);
        Ok((kind, out))
    }
}

fn hmac_mac(sha: Sha, key: &[u8], data: &[u8]) -> Vec<u8> {
    use hmac::Mac;
    match sha {
        Sha::S512 => hmac::Hmac::<sha2::Sha512>::new_from_slice(key).unwrap().chain_update(data).finalize().into_bytes().to_vec(),
        _ => hmac::Hmac::<sha2::Sha256>::new_from_slice(key).unwrap().chain_update(data).finalize().into_bytes().to_vec(),
    }
}

/// AES-CTR with an all-zero nonce, as MCUboot uses for both key wrap and image body.
pub fn aes_ctr(key: &[u8], data: &mut [u8]) {
    use ctr::cipher::{KeyIvInit, StreamCipher};
    let iv = [0u8; 16];
    match key.len() {
        16 => ctr::Ctr128BE::<aes::Aes128>::new(key.into(), &iv.into()).apply_keystream(data),
        32 => ctr::Ctr128BE::<aes::Aes256>::new(key.into(), &iv.into()).apply_keystream(data),
        n => unreachable!("AES key length {n}"),
    }
}

#[allow(clippy::large_enum_variant)] // one key per run, boxing buys nothing
pub enum Key {
    Ed25519(ed25519_dalek::SigningKey),
    Ed25519Pub(ed25519_dalek::VerifyingKey),
    P256(p256::ecdsa::SigningKey),
    P256Pub(p256::ecdsa::VerifyingKey),
}

impl Key {
    // ponytail: unencrypted PEM only; password-protected keys (keygen -p) come later.
    pub fn load(path: &str) -> Result<Key> {
        let pem = std::fs::read_to_string(path).with_context(|| format!("cannot read key {path}"))?;
        if let Ok(k) = ed25519_dalek::SigningKey::from_pkcs8_pem(&pem) {
            return Ok(Key::Ed25519(k));
        }
        if let Ok(k) = p256::SecretKey::from_pkcs8_pem(&pem).or_else(|_| p256::SecretKey::from_sec1_pem(&pem)) {
            return Ok(Key::P256(k.into()));
        }
        if let Ok(k) = ed25519_dalek::VerifyingKey::from_public_key_pem(&pem) {
            return Ok(Key::Ed25519Pub(k));
        }
        if let Ok(k) = p256::PublicKey::from_public_key_pem(&pem) {
            return Ok(Key::P256Pub(k.into()));
        }
        bail!("{path}: unsupported key (supported: Ed25519, ECDSA P-256 PEM)")
    }

    pub fn generate(kind: &str, path: &str) -> Result<()> {
        let pem = match kind {
            // PKCS#8 v1 (no embedded public key): OpenSSL 3.0 rejects dalek's default v2 output
            "ed25519" => ed25519_dalek::pkcs8::KeypairBytes {
                secret_key: ed25519_dalek::SigningKey::generate(&mut OsRng).to_bytes(),
                public_key: None,
            }
            .to_pkcs8_pem(LineEnding::LF)?,
            "ecdsa-p256" => p256::SecretKey::random(&mut OsRng).to_pkcs8_pem(LineEnding::LF)?,
            _ => bail!("unsupported key type {kind}"),
        };
        std::fs::write(path, pem.as_bytes()).with_context(|| format!("cannot write {path}"))
    }

    pub fn is_private(&self) -> bool {
        matches!(self, Key::Ed25519(_) | Key::P256(_))
    }

    /// SubjectPublicKeyInfo DER, which is what MCUboot embeds / hashes.
    pub fn public_der(&self) -> Vec<u8> {
        match self {
            Key::Ed25519(k) => k.verifying_key().to_public_key_der(),
            Key::Ed25519Pub(k) => k.to_public_key_der(),
            Key::P256(k) => k.verifying_key().to_public_key_der(),
            Key::P256Pub(k) => k.to_public_key_der(),
        }
        .expect("SPKI encoding of a valid key cannot fail")
        .into_vec()
    }

    pub fn public_pem(&self) -> String {
        match self {
            Key::Ed25519(k) => k.verifying_key().to_public_key_pem(LineEnding::LF),
            Key::Ed25519Pub(k) => k.to_public_key_pem(LineEnding::LF),
            Key::P256(k) => k.verifying_key().to_public_key_pem(LineEnding::LF),
            Key::P256Pub(k) => k.to_public_key_pem(LineEnding::LF),
        }
        .expect("SPKI encoding of a valid key cannot fail")
    }

    pub fn shortname(&self) -> &'static str {
        match self {
            Key::Ed25519(_) | Key::Ed25519Pub(_) => "ed25519",
            Key::P256(_) | Key::P256Pub(_) => "ecdsa",
        }
    }

    pub fn sig_tlv(&self) -> u8 {
        match self {
            Key::Ed25519(_) | Key::Ed25519Pub(_) => tlv::ED25519,
            Key::P256(_) | Key::P256Pub(_) => tlv::ECDSASIG,
        }
    }

    /// ALLOWED_KEY_SHA / ALLOWED_PURE_KEY_SHA from image.py; first entry is the default.
    pub fn allowed_sha(&self, pure: bool) -> &'static [Sha] {
        match (self, pure) {
            (Key::Ed25519(_), true) => &[Sha::S512],
            (_, true) => &[],
            (Key::Ed25519(_) | Key::Ed25519Pub(_) | Key::P256Pub(_), false) => &[Sha::S256, Sha::S512],
            (Key::P256(_), false) => &[Sha::S256],
        }
    }

    /// Ed25519 signs the digest (or the whole payload when pure); ECDSA signs the payload.
    pub fn sign(&self, payload: &[u8], digest: &[u8], pure: bool) -> Result<Vec<u8>> {
        Ok(match self {
            Key::Ed25519(k) => k.sign(if pure { payload } else { digest }).to_bytes().to_vec(),
            Key::P256(k) => {
                let sig: p256::ecdsa::Signature = k.sign(payload);
                sig.to_der().as_bytes().to_vec()
            }
            _ => bail!("Cannot sign with a public-only PEM; signing requires the private key."),
        })
    }

    pub fn verify(&self, sig: &[u8], payload: &[u8], digest: &[u8], pure: bool) -> bool {
        let ed = |vk: &ed25519_dalek::VerifyingKey| {
            ed25519_dalek::Signature::from_slice(sig)
                .is_ok_and(|s| vk.verify(if pure { payload } else { digest }, &s).is_ok())
        };
        let ec = |vk: &p256::ecdsa::VerifyingKey| {
            // strip the optional --pad-sig zero padding, as image.py does
            let len = sig.get(1).map_or(0, |&l| l as usize + 2).min(sig.len());
            p256::ecdsa::Signature::from_der(&sig[..len]).is_ok_and(|s| vk.verify(payload, &s).is_ok())
        };
        match self {
            Key::Ed25519(k) => ed(&k.verifying_key()),
            Key::Ed25519Pub(k) => ed(k),
            Key::P256(k) => ec(k.verifying_key()),
            Key::P256Pub(k) => ec(k),
        }
    }
}
