//! Differential test against the reference Python imgtool.
//! IMGTOOL_PY=/path/to/mcuboot/scripts/imgtool.py cargo test

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const RS: &str = env!("CARGO_BIN_EXE_imgtool");

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
    let (r, p) = (tmp(&format!("{name}.rs.{ext}")), tmp(&format!("{name}.py.{ext}")));
    for (rust, out) in [(true, &r), (false, &p)] {
        let mut a = vec!["sign"];
        a.extend(args);
        a.extend([infile, out.as_str()]);
        ok(rust, &a);
    }
    assert!(std::fs::read(&r).unwrap() == std::fs::read(&p).unwrap(), "{name}: output differs ({r} vs {p})");
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
    assert!(Command::new("python3").args(["-c", &script]).status().unwrap().success());

    let common = ["-H", "0x200", "--pad-header", "-S", "0x40000"];
    let cases: &[(&str, &[&str])] = &[
        ("plain", &["-v", "1.2.3+4"]),
        ("confirm", &["-v", "1.2.3+4", "--align", "4", "--pad", "--confirm", "-s", "auto"]),
        ("test", &["-v", "1.0", "--test", "-s", "0x42", "-M", "64"]),
        ("ow", &["-v", "3", "--overwrite-only", "--pad", "-R", "0", "--align", "16", "--max-align", "16", "-L", "0x20000000"]),
        ("rom", &["-v", "1.0.0", "-F", "0x08010000", "--non-bootable", "--public-key-format", "full"]),
        ("sha512", &["-v", "2.0", "--sha", "512"]),
        ("pure", &["-v", "2.0", "--pure"]),
        ("big", &["-v", "1.0.0", "-e", "big", "-s", "7", "--pad", "--confirm", "--max-align", "32", "--align", "32"]),
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
                same_output(&format!("{name}-{kname}-hexout"), &bin, "hex", &[&a[..], &["-x", "0x10000"]].concat());
            }
        }
    }
    same_output("hex2hex", &hex_in, "hex", &["-v", "1.0", "-H", "0x20", "--pad-header", "-S", "0x40000", "-k", &ed, "--pad", "--confirm"]);

    // ECDSA signatures are randomized in Python, so cross-verify instead of comparing bytes.
    let sec1 = py().unwrap().parent().unwrap().join("../root-ec-p256.pem");
    let sec1 = sec1.to_str().unwrap();
    for key in [ec.as_str(), sec1] {
        for (signer, verifier) in [(true, false), (false, true)] {
            let out = tmp("ec.bin");
            ok(signer, &[&["sign"][..], &common, &["-v", "1.0", "-s", "auto", "-k", key, &bin, &out]].concat());
            let v = ok(verifier, &["verify", "-k", key, &out]);
            assert!(String::from_utf8_lossy(&v.stdout).contains("Image version: 1.0.0+0"));
        }
    }

    // verify output and failure modes match
    let img = tmp("verify.bin");
    ok(false, &[&["sign"][..], &common, &["-v", "1.2.3+4", "-k", &ed, &bin, &img]].concat());
    let mut tampered = std::fs::read(&img).unwrap();
    tampered[0x300] ^= 1;
    let bad = tmp("tampered.bin");
    std::fs::write(&bad, tampered).unwrap();
    for args in [vec!["verify", "-k", &ed, &img], vec!["verify", &img], vec!["verify", "-k", &ec, &img], vec!["verify", "-k", &ed, &bad]] {
        let (r, p) = (run(true, &args), run(false, &args));
        assert_eq!(r.status.success(), p.status.success(), "{args:?}");
        assert_eq!(String::from_utf8_lossy(&r.stdout), String::from_utf8_lossy(&p.stdout), "{args:?}");
    }

    // getpub, including a key generated by the Rust keygen (proves Python can read it)
    let rs_ed = tmp("rs-ed25519.pem");
    let rs_ec = tmp("rs-p256.pem");
    ok(true, &["keygen", "-t", "ed25519", "-k", &rs_ed]);
    ok(true, &["keygen", "-t", "ecdsa-p256", "-k", &rs_ec]);
    for key in [ed.as_str(), ec.as_str(), sec1, &rs_ed, &rs_ec] {
        for enc in [&["-e", "lang-c"][..], &["-e", "pem"], &["-e", "raw"], &["-e", "lang-c", "--name-suffix", "_2"], &[]] {
            let args = [&["getpub", "-k", key][..], enc].concat();
            assert_eq!(ok(true, &args).stdout, ok(false, &args).stdout, "{args:?}");
        }
    }
}
