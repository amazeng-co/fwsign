//! Key loading / signing, mirroring scripts/imgtool/keys/*.py.

use anyhow::{bail, Context, Result};
use ed25519_dalek::{Signer, Verifier};
use p256::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey, LineEnding};
use rand_core::OsRng;

use crate::image::{tlv, Sha};

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
