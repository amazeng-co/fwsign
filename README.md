# imgtool-rs

[![CI](https://github.com/amazeng-co/imgtool-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/amazeng-co/imgtool-rs/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

A Rust implementation of [MCUboot](https://github.com/mcu-tools/mcuboot)'s `imgtool`.

- **One binary.** About 1.3 MB, and it needs only the system C library: no Python, pip or
  `cryptography`.
- **Drop-in.** It accepts the same arguments as `scripts/imgtool.py`.
- **Verified against Python.** For unsigned and Ed25519-signed images the output is byte-identical
  to the Python tool. Every change is tested against it in CI.
- **Fast.** In a real Zephyr build the signing step takes 3.3 ms instead of 252 ms, and each run
  uses about a tenth of the memory ([benchmark](docs/benchmark.md)).

```sh
cargo build --release          # → target/release/imgtool
imgtool keygen -t ed25519 -k root.pem
imgtool sign -k root.pem -v 1.2.3 -H 0x200 --pad-header -S 0x40000 --pad --confirm zephyr.bin zephyr.signed.bin
imgtool verify -k root.pem zephyr.signed.bin
imgtool getpub -k root.pem     # C array for the bootloader
```

## Status

| Area | Supported |
|---|---|
| Commands | `sign` (`create`), `verify`, `keygen`, `getpub` (`lang-c`, `pem`, `raw`), `version` |
| Keys | Ed25519, ECDSA P-256 (PKCS#8 or SEC1 PEM, public or private) |
| Sign options | `-k -v -H -S --align --max-align --pad --pad-header --confirm --test -s/--security-counter -M --overwrite-only -e/--endian -R -x -L -F --non-bootable --public-key-format --sha --pure` |
| Encryption | `-E` with ECIES-P256 or ECIES-X25519 (HMAC-SHA256/512), `--encrypt-keylen 128/256`, `--clear`, `--save-enctlv` |
| In/out | `.bin` and Intel `.hex`, both directions |

**Not yet supported:**

- Keys and crypto: RSA (signing and RSA-OAEP encryption), ECDSA P-384, password-protected keys.
- `sign` options: `--compression`, `--vid/--cid`, `--boot-record`, `-d/--dependencies`,
  `--custom-tlv*`, `--fix-sig*`, `--vector-to-sign`, `--sig-out`, `--pad-sig`.
- Commands: `getpubhash`, `getpriv`, `keyinfo`, `dumpinfo`, and `getpub -e lang-rust`.

The CLI rejects these arguments instead of ignoring them. To request one, open an issue with the
"Missing imgtool feature" template.

## Using it with Zephyr

Tested with Zephyr v4.3.0. Signed and signed + encrypted builds produce the same images as with the
Python imgtool (see [docs/benchmark.md](docs/benchmark.md#zephyr-end-to-end-check)).

- **`west sign`:** works as is with `west sign -t imgtool -p /path/to/imgtool -- --key root.pem`.
- **CMake build** (`CONFIG_MCUBOOT_SIGNATURE_KEY_FILE`): pass `-DIMGTOOL=/path/to/imgtool`. Zephyr
  currently runs `${PYTHON_EXECUTABLE} ${IMGTOOL}` unconditionally. A change that runs native
  executables directly has been prepared for upstream Zephyr; until it lands, this path needs that
  patch.

## Compatibility testing

`tests/compat.rs` runs the Python `imgtool` and this binary side by side:

- **Byte-identical output:** about 30 `sign` configurations, plus `getpub` output. The `sign` cases
  cover bin and hex, with and without an Ed25519 key, pure, sha512, big-endian, overwrite-only,
  RAM-load and ROM-fixed images.
- **Cross-verification:** ECDSA signatures are randomized in Python, so each tool verifies images
  signed by the other.
- **Encryption:** every run uses a fresh random key and ephemeral ECDH key, so output can't be
  compared directly. Instead:
  - `--clear` images are compared with the wrapped-key TLV masked out.
  - Encrypted images from both tools are decrypted by an independent ECIES implementation (Python
    `cryptography`) and checked against the image hash.
- **Failure modes:** `verify` output for tampered images and wrong keys matches the Python tool.

```sh
git clone https://github.com/mcu-tools/mcuboot ../mcuboot
pip install 'cryptography>=40' 'intelhex>=2.2.1' click cbor2 pyyaml
IMGTOOL_PY=../mcuboot/scripts/imgtool.py cargo test
```

Without `IMGTOOL_PY` the differential test is skipped. Building needs Rust 1.85 or newer.

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for the test setup and the commit
style (Linux-style subjects, `Signed-off-by` required). Report security issues privately as described
in [SECURITY.md](SECURITY.md). This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md).

## License

Apache-2.0, the same license as MCUboot. The image format logic follows `scripts/imgtool/image.py`.
