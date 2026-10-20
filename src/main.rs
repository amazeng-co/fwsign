mod image;
mod keys;

use anyhow::{bail, ensure, Context, Result};
use clap::{Parser, Subcommand};
use std::io::Write;
use std::path::Path;

use image::{Endian, Opts, Sha, Version};
use keys::{EncKey, Key};

/// Sign, verify and encrypt MCUboot firmware images.
///
/// Command line compatible with MCUboot's scripts/imgtool.py.
#[derive(Parser)]
#[command(name = "fwsign")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)] // parsed once
enum Cmd {
    /// Generate pub/private keypair
    Keygen {
        #[arg(short, long)]
        key: String,
        #[arg(short = 't', long = "type", value_parser = ["ed25519", "ecdsa-p256"])]
        kind: String,
        #[arg(short, long)]
        password: bool,
    },
    /// Dump public key from keypair
    Getpub {
        #[arg(short, long)]
        key: String,
        #[arg(short, long, value_parser = ["lang-c", "lang-rust", "pem", "raw"])]
        encoding: Option<String>,
        /// Deprecated, use --encoding
        #[arg(short, long, value_parser = ["c", "rust"], conflicts_with = "encoding")]
        lang: Option<String>,
        #[arg(short, long)]
        output: Option<String>,
        #[arg(long, default_value = "")]
        name_suffix: String,
    },
    /// Check that signed image can be verified by given key
    Verify {
        #[arg(short, long)]
        key: Option<String>,
        imgfile: String,
    },
    /// Create a signed or unsigned image
    #[command(alias = "create")]
    Sign(SignArgs),
    /// Print fwsign version information
    Version,
}

#[derive(clap::Args)]
struct SignArgs {
    #[arg(short, long)]
    key: Option<String>,
    #[arg(long, default_value = "hash", value_parser = ["hash", "full"])]
    public_key_format: String,
    #[arg(long, default_value = "1", value_parser = ["1", "2", "4", "8", "16", "32"])]
    align: String,
    #[arg(long, value_parser = ["8", "16", "32"])]
    max_align: Option<String>,
    #[arg(short, long)]
    version: Version,
    #[arg(short = 's', long)]
    security_counter: Option<String>,
    #[arg(short = 'H', long, value_parser = parse_int)]
    header_size: u64,
    #[arg(long)]
    pad_header: bool,
    #[arg(short = 'S', long, value_parser = parse_int)]
    slot_size: u64,
    #[arg(long)]
    pad: bool,
    #[arg(long)]
    confirm: bool,
    #[arg(long)]
    test: bool,
    #[arg(short = 'M', long, default_value_t = 128)]
    max_sectors: usize,
    #[arg(long)]
    overwrite_only: bool,
    #[arg(short, long, default_value = "little", value_parser = ["little", "big"])]
    endian: String,
    #[arg(short = 'R', long, value_parser = ["0", "0xff"])]
    erased_val: Option<String>,
    #[arg(short = 'x', long, value_parser = parse_int)]
    hex_addr: Option<u64>,
    #[arg(short = 'L', long, value_parser = parse_int)]
    load_addr: Option<u64>,
    #[arg(short = 'F', long, value_parser = parse_int)]
    rom_fixed: Option<u64>,
    #[arg(long)]
    non_bootable: bool,
    #[arg(long, default_value = "auto", value_parser = ["auto", "256", "384", "512"])]
    sha: String,
    #[arg(long = "pure")]
    pure: bool,
    /// Encrypt image using the provided public key
    #[arg(short = 'E', long)]
    encrypt: Option<String>,
    #[arg(long, default_value = "128", value_parser = ["128", "256"])]
    encrypt_keylen: String,
    /// Output a non-encrypted image with encryption capabilities
    #[arg(short = 'c', long)]
    clear: bool,
    #[arg(long, default_value = "auto", value_parser = ["auto", "256", "512"])]
    hmac_sha: String,
    #[arg(long)]
    save_enctlv: bool,
    infile: String,
    outfile: String,
}

/// click's BasedIntParamType: int(value, 0).
fn parse_int(s: &str) -> Result<u64, String> {
    let l = s.to_ascii_lowercase();
    let r = match l.get(..2) {
        Some("0x") => u64::from_str_radix(&l[2..], 16),
        Some("0o") => u64::from_str_radix(&l[2..], 8),
        Some("0b") => u64::from_str_radix(&l[2..], 2),
        _ => l.parse(),
    };
    r.map_err(|_| format!("{s} is not a valid integer"))
}

fn u32_arg(v: Option<u64>, name: &str) -> Result<u32> {
    v.unwrap_or(0)
        .try_into()
        .with_context(|| format!("{name} does not fit in 32 bits"))
}

fn is_hex(path: &str) -> bool {
    Path::new(path)
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("hex"))
}

fn read_image(path: &str) -> Result<(Vec<u8>, Option<u32>)> {
    if is_hex(path) {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("Input file not found: {path}"))?;
        let (data, base) = image::hex_to_bin(&text)?;
        Ok((data, Some(base)))
    } else {
        Ok((
            std::fs::read(path).with_context(|| format!("Input file not found: {path}"))?,
            None,
        ))
    }
}

fn sign(a: SignArgs) -> Result<()> {
    let align: usize = a.align.parse()?;
    let enc = a.encrypt.as_deref().map(EncKey::load).transpose()?;
    let aes256 = a.encrypt_keylen == "256";
    let hmac_sha = if a.hmac_sha == "512" {
        Sha::S512
    } else {
        Sha::S256
    };
    let security_counter = match a.security_counter.as_deref() {
        None => None,
        Some(s) if s.eq_ignore_ascii_case("auto") => {
            let v = a.version;
            Some(((v.major as u32) << 24) + ((v.minor as u32) << 16) + v.revision as u32)
        }
        Some(s) => Some(
            u32::try_from(parse_int(s).map_err(anyhow::Error::msg)?)
                .context("security counter too large")?,
        ),
    };
    let o = Opts {
        version: a.version,
        header_size: a.header_size as usize,
        pad_header: a.pad_header,
        // confirmed/test images without a trailer make no sense
        pad: a.pad || a.confirm || a.test,
        confirm: a.confirm,
        test: a.test,
        align,
        max_align: a.max_align.map_or(Ok(align.max(8)), |m| m.parse())?,
        slot_size: a.slot_size as usize,
        max_sectors: a.max_sectors,
        overwrite_only: a.overwrite_only,
        endian: if a.endian == "big" {
            Endian::Big
        } else {
            Endian::Little
        },
        load_addr: u32_arg(a.load_addr, "--load-addr")?,
        rom_fixed: u32_arg(a.rom_fixed, "--rom-fixed")?,
        erased_val: if a.erased_val.as_deref() == Some("0") {
            0
        } else {
            0xff
        },
        security_counter,
        non_bootable: a.non_bootable,
        public_key_full: a.public_key_format == "full",
        sha: match a.sha.as_str() {
            "256" => Some(Sha::S256),
            "384" => Some(Sha::S384),
            "512" => Some(Sha::S512),
            _ => None,
        },
        pure: a.pure,
        aes256,
        clear: a.clear,
        hmac_sha,
        save_enctlv: a.save_enctlv,
        enc_tlv_len: enc
            .as_ref()
            .map(|e| e.tlv_len(if aes256 { 32 } else { 16 }, hmac_sha)),
    };

    let (data, mut base) = read_image(&a.infile)?;
    if o.pad_header {
        // the new header occupies the bytes in front of the input
        base = base.map(|b| {
            if b != 0 {
                b.wrapping_sub(o.header_size as u32)
            } else {
                b
            }
        });
    }
    let key = a.key.as_deref().map(Key::load).transpose()?;
    let mut img = image::create(&data, &o, key.as_ref(), enc.as_ref())?;

    if is_hex(&a.outfile) {
        let base = match a.hex_addr {
            Some(h) => u32::try_from(h).context("--hex-addr does not fit in 32 bits")?,
            None => {
                base.context("No address exists in input file neither was it provided by user")?
            }
        };
        let mut segs = vec![(base, img)];
        if o.pad {
            segs.extend(image::trailer_records(&o, base)?);
        }
        std::fs::write(&a.outfile, image::bin_to_hex(&segs))?;
    } else {
        if o.pad {
            image::pad_to_slot(&mut img, &o)?;
        }
        std::fs::write(&a.outfile, img)?;
    }
    Ok(())
}

fn getpub(
    key: &str,
    encoding: Option<String>,
    lang: Option<String>,
    output: Option<String>,
    suffix: &str,
) -> Result<()> {
    let enc = match (encoding.as_deref(), lang.as_deref()) {
        (Some(e), _) => e,
        (None, Some("rust")) => "lang-rust",
        _ => "lang-c",
    };
    ensure!(
        suffix.is_empty() || enc.starts_with("lang-"),
        "`--name-suffix` is only meaningful for lang-c / lang-rust encodings"
    );
    let key = Key::load(key)?;
    let out: Vec<u8> = match enc {
        "lang-c" => {
            let name = format!("{}_pub_key{suffix}", key.shortname());
            let der = key.public_der();
            let mut s = format!(
                "/* Autogenerated by fwsign, do not edit. */\nconst unsigned char {name}[] = {{"
            );
            for (i, b) in der.iter().enumerate() {
                s += if i % 8 == 0 { "\n    " } else { " " };
                s += &format!("0x{b:02x},");
            }
            s += &format!("\n}};\nconst unsigned int {name}_len = {};\n", der.len());
            s.into_bytes()
        }
        "pem" => key.public_pem().into_bytes(),
        "raw" => key.public_der(),
        // ponytail: lang-rust output skipped, add when a Rust bootloader consumer needs it
        _ => bail!("encoding {enc} is not supported yet"),
    };
    match output {
        Some(p) => std::fs::write(p, out)?,
        None => std::io::stdout().write_all(&out)?,
    }
    Ok(())
}

fn verify(key: Option<String>, imgfile: &str) -> Result<bool> {
    let key = key.as_deref().map(Key::load).transpose()?;
    let data = if is_hex(imgfile) {
        image::hex_to_bin(
            &std::fs::read_to_string(imgfile)
                .with_context(|| format!("Image file {imgfile} not found"))?,
        )?
        .0
    } else {
        std::fs::read(imgfile).with_context(|| format!("Image file {imgfile} not found"))?
    };
    match image::verify(&data, key.as_ref()) {
        Ok(v) => {
            println!("Image was correctly validated");
            println!("Image version: {}", v.version);
            if let Some(d) = &v.digest {
                println!("Image digest: {}", hex(d));
            } else if let Some(s) = &v.signature {
                println!("Image signature over image: {}", hex(s));
            }
            Ok(true)
        }
        Err(e) => {
            println!("{e}");
            Ok(false)
        }
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn main() {
    let res = match Cli::parse().cmd {
        Cmd::Keygen { password: true, .. } => Err(anyhow::anyhow!(
            "password-protected keys are not supported yet"
        )),
        Cmd::Keygen { key, kind, .. } => Key::generate(&kind, &key),
        Cmd::Getpub {
            key,
            encoding,
            lang,
            output,
            name_suffix,
        } => getpub(&key, encoding, lang, output, &name_suffix),
        Cmd::Verify { key, imgfile } => match verify(key, &imgfile) {
            Ok(false) => std::process::exit(1),
            r => r.map(|_| ()),
        },
        Cmd::Sign(a) => sign(a),
        Cmd::Version => {
            println!("{}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
    };
    if let Err(e) = res {
        eprintln!("Error: {e:#}");
        std::process::exit(2);
    }
}
