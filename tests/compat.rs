//! Differential test against the reference Python imgtool.
//! IMGTOOL_PY=/path/to/mcuboot/scripts/imgtool.py cargo test

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const RS: &str = env!("CARGO_BIN_EXE_fwsign");

fn py() -> Option<PathBuf> {
    std::env::var_os("IMGTOOL_PY").map(PathBuf::from)
}

fn run(rust: bool, args: &[&str]) -> Output {
    let mut c = if rust {
        Command::new(RS)
    } else {
        let mut c = Command::new("python3");
        c.arg(py().unwrap());
        c
    };
    c.args(args).output().unwrap()
}

fn ok(rust: bool, args: &[&str]) -> Output {
    let out = run(rust, args);
    assert!(
        out.status.success(),
        "{} {args:?} failed:\n{}{}",
        if rust { "rust" } else { "python" },
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    out
}

fn tmp(name: &str) -> String {
    let d = Path::new(env!("CARGO_TARGET_TMPDIR")).join("compat");
    std::fs::create_dir_all(&d).unwrap();
    d.join(name).to_str().unwrap().to_owned()
}

/// Deterministic pseudo-firmware; odd length and >64K so hex output crosses a segment.
fn firmware(len: usize) -> Vec<u8> {
    let mut x: u32 = 0x1234_5678;
    (0..len)
        .map(|_| {
            x = x.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            (x >> 16) as u8
        })
        .collect()
}

/// Signs with both tools and asserts byte-identical output.
fn same_output(name: &str, infile: &str, ext: &str, args: &[&str]) {
    let (r, p) = (
        tmp(&format!("{name}.rs.{ext}")),
        tmp(&format!("{name}.py.{ext}")),
    );
    for (rust, out) in [(true, &r), (false, &p)] {
        let mut a = vec!["sign"];
        a.extend(args);
        a.extend([infile, out.as_str()]);
        ok(rust, &a);
    }
    assert!(
        std::fs::read(&r).unwrap() == std::fs::read(&p).unwrap(),
        "{name}: output differs ({r} vs {p})"
    );
}

#[test]
fn matches_python_imgtool() {
    if py().is_none() {
        eprintln!("IMGTOOL_PY not set, skipping differential test");
        return;
    }
    let bin = tmp("fw.bin");
    std::fs::write(&bin, firmware(70_001)).unwrap();
    let ed = tmp("ed25519.pem");
    let ec = tmp("p256.pem");
    ok(false, &["keygen", "-t", "ed25519", "-k", &ed]);
    ok(false, &["keygen", "-t", "ecdsa-p256", "-k", &ec]);

    // raw hex input written by python-intelhex, above 64K, for hex→hex runs
    let hex_in = tmp("fw.hex");
    let script = format!(
        "from intelhex import IntelHex; ih = IntelHex(); ih.frombytes(open({bin:?}, 'rb').read(), offset=0x08020000); ih.tofile({hex_in:?}, 'hex')"
    );
    assert!(Command::new("python3")
        .args(["-c", &script])
        .status()
        .unwrap()
        .success());

    let common = ["-H", "0x200", "--pad-header", "-S", "0x40000"];
    let cases: &[(&str, &[&str])] = &[
        ("plain", &["-v", "1.2.3+4"]),
        (
            "confirm",
            &[
                "-v",
                "1.2.3+4",
                "--align",
                "4",
                "--pad",
                "--confirm",
                "-s",
                "auto",
            ],
        ),
        ("test", &["-v", "1.0", "--test", "-s", "0x42", "-M", "64"]),
        (
            "ow",
            &[
                "-v",
                "3",
                "--overwrite-only",
                "--pad",
                "-R",
                "0",
                "--align",
                "16",
                "--max-align",
                "16",
                "-L",
                "0x20000000",
            ],
        ),
        (
            "rom",
            &[
                "-v",
                "1.0.0",
                "-F",
                "0x08010000",
                "--non-bootable",
                "--public-key-format",
                "full",
            ],
        ),
        ("sha512", &["-v", "2.0", "--sha", "512"]),
        ("pure", &["-v", "2.0", "--pure"]),
        (
            "big",
            &[
                "-v",
                "1.0.0",
                "-e",
                "big",
                "-s",
                "7",
                "--pad",
                "--confirm",
                "--max-align",
                "32",
                "--align",
                "32",
            ],
        ),
    ];
    for (name, args) in cases {
        for (kname, key) in [("nokey", None), ("ed", Some(ed.as_str()))] {
            let mut a: Vec<&str> = common.to_vec();
            a.extend(*args);
            if let Some(k) = key {
                a.extend(["-k", k]);
            }
            same_output(&format!("{name}-{kname}"), &bin, "bin", &a);
            if !name.starts_with("big") {
                same_output(
                    &format!("{name}-{kname}-hexout"),
                    &bin,
                    "hex",
                    &[&a[..], &["-x", "0x10000"]].concat(),
                );
            }
        }
    }
    same_output(
        "hex2hex",
        &hex_in,
        "hex",
        &[
            "-v",
            "1.0",
            "-H",
            "0x20",
            "--pad-header",
            "-S",
            "0x40000",
            "-k",
            &ed,
            "--pad",
            "--confirm",
        ],
    );

    // ECDSA signatures are randomized in Python, so cross-verify instead of comparing bytes.
    let sec1 = py().unwrap().parent().unwrap().join("../root-ec-p256.pem");
    let sec1 = sec1.to_str().unwrap();
    for key in [ec.as_str(), sec1] {
        for (signer, verifier) in [(true, false), (false, true)] {
            let out = tmp("ec.bin");
            ok(
                signer,
                &[
                    &["sign"][..],
                    &common,
                    &["-v", "1.0", "-s", "auto", "-k", key, &bin, &out],
                ]
                .concat(),
            );
            let v = ok(verifier, &["verify", "-k", key, &out]);
            assert!(String::from_utf8_lossy(&v.stdout).contains("Image version: 1.0.0+0"));
        }
    }

    // verify output and failure modes match
    let img = tmp("verify.bin");
    ok(
        false,
        &[
            &["sign"][..],
            &common,
            &["-v", "1.2.3+4", "-k", &ed, &bin, &img],
        ]
        .concat(),
    );
    let mut tampered = std::fs::read(&img).unwrap();
    tampered[0x300] ^= 1;
    let bad = tmp("tampered.bin");
    std::fs::write(&bad, tampered).unwrap();
    for args in [
        vec!["verify", "-k", &ed, &img],
        vec!["verify", &img],
        vec!["verify", "-k", &ec, &img],
        vec!["verify", "-k", &ed, &bad],
    ] {
        let (r, p) = (run(true, &args), run(false, &args));
        assert_eq!(r.status.success(), p.status.success(), "{args:?}");
        assert_eq!(
            String::from_utf8_lossy(&r.stdout),
            String::from_utf8_lossy(&p.stdout),
            "{args:?}"
        );
    }

    // getpub, including a key generated by the Rust keygen (proves Python can read it)
    let rs_ed = tmp("rs-ed25519.pem");
    let rs_ec = tmp("rs-p256.pem");
    ok(true, &["keygen", "-t", "ed25519", "-k", &rs_ed]);
    ok(true, &["keygen", "-t", "ecdsa-p256", "-k", &rs_ec]);
    for key in [ed.as_str(), ec.as_str(), sec1, &rs_ed, &rs_ec] {
        for enc in [
            &["-e", "lang-c"][..],
            &["-e", "pem"],
            &["-e", "raw"],
            &["-e", "lang-c", "--name-suffix", "_2"],
            &[],
        ] {
            let args = [&["getpub", "-k", key][..], enc].concat();
            let (r, p) = (ok(true, &args).stdout, ok(false, &args).stdout);
            // C output starts with an "Autogenerated by <tool>" comment line naming the tool
            let body = |o: &[u8]| -> Vec<u8> {
                let s = o.split(|&b| b == b'\n');
                if o.starts_with(b"/* Autogenerated") {
                    s.skip(1).flatten().copied().collect()
                } else {
                    o.to_vec()
                }
            };
            assert_eq!(body(&r), body(&p), "{args:?}");
        }
    }
}

/// Independent ECIES decryptor (python `cryptography`, as the bootloader does it):
/// unwraps the AES key, decrypts the body and checks it against the hash TLV.
const DECRYPT_PY: &str = r#"
import sys, struct, hashlib
from cryptography.hazmat.primitives import serialization, hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import ec, x25519
img = open(sys.argv[1], 'rb').read()
priv = serialization.load_pem_private_key(open(sys.argv[2], 'rb').read(), None)
_, _, hs, ps, isz, flags = struct.unpack('<IIHHII', img[:20])
keylen = 32 if flags & 0x08 else 16
t = hs + isz + ps
_, tot = struct.unpack('<HH', img[t:t + 4])
tlvs, p = {}, t + 4
while p < t + tot:
    ty, _, ln = struct.unpack('<BBH', img[p:p + 4])
    tlvs[ty] = img[p + 4:p + 4 + ln]
    p += 4 + ln
if 0x32 in tlvs:
    v, alg = tlvs[0x32], hashes.SHA256()
    shared = priv.exchange(ec.ECDH(), ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), v[:65]))
    v = v[65:]
else:
    v, alg = (tlvs[0x33], hashes.SHA256()) if 0x33 in tlvs else (tlvs[0x34], hashes.SHA512())
    shared = priv.exchange(x25519.X25519PublicKey.from_public_bytes(v[:32]))
    v = v[32:]
d = HKDF(alg, keylen + alg.digest_size, None, b'MCUBoot_ECIES_v1').derive(shared)
mac, ck = v[:alg.digest_size], v[alg.digest_size:]
assert len(ck) == keylen, 'wrapped key length'
h = hmac.HMAC(d[keylen:], alg); h.update(ck); h.verify(mac)
key = Cipher(algorithms.AES(d[:keylen]), modes.CTR(bytes(16))).decryptor().update(ck)
body = Cipher(algorithms.AES(key), modes.CTR(bytes(16))).decryptor().update(img[hs:hs + isz])
plain = img[:hs] + body + img[hs + isz:t]
sha = hashlib.sha512 if 0x12 in tlvs else hashlib.sha256
assert sha(plain).digest() == tlvs.get(0x12, tlvs.get(0x10)), 'hash of decrypted image'
assert body != img[hs:hs + isz], 'body was not encrypted'
print('ok')
"#;

/// Zero the values of ENC* TLVs (random per run) so images can be compared.
fn mask_enc(mut img: Vec<u8>) -> Vec<u8> {
    let u16_at = |b: &[u8], o: usize| u16::from_le_bytes([b[o], b[o + 1]]) as usize;
    let isz = u32::from_le_bytes(img[12..16].try_into().unwrap()) as usize;
    let t = u16_at(&img, 8) + isz + u16_at(&img, 10);
    let end = t + u16_at(&img, t + 2);
    let mut p = t + 4;
    while p < end {
        let len = u16_at(&img, p + 2);
        if (0x30..=0x34).contains(&img[p]) {
            img[p + 4..p + 4 + len].fill(0);
        }
        p += 4 + len;
    }
    img
}

#[test]
fn encryption_matches_python() {
    let Some(py_path) = py() else {
        eprintln!("IMGTOOL_PY not set, skipping differential test");
        return;
    };
    let root = py_path.parent().unwrap().join("..");
    let k = |n: &str| root.join(n).to_str().unwrap().to_owned();
    let (x_pub, x_priv, ec_pub, ec_priv) = (
        k("enc-x25519-pub.pem"),
        k("enc-x25519-priv.pem"),
        k("enc-ec256-pub.pem"),
        k("enc-ec256-priv.pem"),
    );
    let (ed, ec) = (k("root-ed25519.pem"), k("root-ec-p256.pem"));
    let bin = tmp("enc-fw.bin");
    std::fs::write(&bin, firmware(10_001)).unwrap();

    // (name, signing key, encryption key, decryption key, extra args)
    type Case<'a> = (&'a str, Option<&'a str>, &'a str, &'a str, &'a [&'a str]);
    let cases: &[Case] = &[
        ("x25519", Some(&ed), &x_pub, &x_priv, &[]),
        (
            "x25519-aes256",
            Some(&ed),
            &x_pub,
            &x_priv,
            &["--encrypt-keylen", "256"],
        ),
        (
            "x25519-hmac512",
            Some(&ed),
            &x_pub,
            &x_priv,
            &["--hmac-sha", "512", "--encrypt-keylen", "256"],
        ),
        ("x25519-privkey", Some(&ed), &x_priv, &x_priv, &[]),
        ("x25519-nokey", None, &x_pub, &x_priv, &[]),
        ("ec256-ed", Some(&ed), &ec_pub, &ec_priv, &[]),
        (
            "ec256-ec",
            Some(&ec),
            &ec_pub,
            &ec_priv,
            &["--encrypt-keylen", "256"],
        ),
    ];
    for &(name, key, enc, priv_key, extra) in cases {
        for trailer in [
            &["--pad", "--confirm"][..],
            &["--pad", "--save-enctlv", "--align", "8"],
            &[],
        ] {
            let mut args = vec![
                "sign",
                "-H",
                "0x200",
                "--pad-header",
                "-S",
                "0x20000",
                "-v",
                "1.0",
                "-E",
                enc,
            ];
            args.extend(extra);
            args.extend(trailer);
            if let Some(k) = key {
                args.extend(["-k", k]);
            }
            // ECDSA signatures are randomized, so only Ed25519/unsigned images compare structurally
            if key != Some(ec.as_str()) {
                let (r, p) = (
                    tmp(&format!("{name}-clear.rs.bin")),
                    tmp(&format!("{name}-clear.py.bin")),
                );
                ok(true, &[&args[..], &["--clear", &bin, &r]].concat());
                ok(false, &[&args[..], &["--clear", &bin, &p]].concat());
                let (r, p) = (std::fs::read(&r).unwrap(), std::fs::read(&p).unwrap());
                assert!(
                    mask_enc(r) == mask_enc(p),
                    "{name} {trailer:?}: --clear image differs"
                );
            }
            for rust in [true, false] {
                let out = tmp(&format!("{name}-{rust}.bin"));
                ok(rust, &[&args[..], &[&bin, &out]].concat());
                let d = Command::new("python3")
                    .args(["-c", DECRYPT_PY, &out, priv_key])
                    .output()
                    .unwrap();
                assert_eq!(
                    String::from_utf8_lossy(&d.stdout).trim(),
                    "ok",
                    "{name} {trailer:?} rust={rust}: {}",
                    String::from_utf8_lossy(&d.stderr)
                );
            }
        }
    }

    // invalid combinations are rejected by both
    let out = tmp("bad.bin");
    for bad in [
        vec!["-k", &ec, "-E", &x_pub],
        vec!["-k", &ed, "-E", &ec_pub, "--hmac-sha", "512"],
    ] {
        let args = [
            &[
                "sign",
                "-H",
                "0x200",
                "--pad-header",
                "-S",
                "0x20000",
                "-v",
                "1.0",
            ][..],
            &bad,
            &[&bin, &out],
        ]
        .concat();
        assert!(
            !run(true, &args).status.success() && !run(false, &args).status.success(),
            "{bad:?}"
        );
    }
}
