# imgtool-rs

A Rust port of [MCUboot](https://github.com/mcu-tools/mcuboot)'s `imgtool`, built as a single static binary
(~1.3 MB) with no Python, pip or `cryptography` needed. The CLI accepts the same arguments as
`scripts/imgtool.py`. For Ed25519 and unsigned images the output is byte-identical to the Python tool.

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
| In/out | `.bin` and Intel `.hex`, both directions |

Not yet supported: RSA, ECDSA P-384, encryption (`-E`, `--clear`, `--encrypt-keylen`, `--hmac-sha`, `--save-enctlv`),
`--compression`, `--vid/--cid`, `--boot-record`, `-d/--dependencies`, `--custom-tlv*`, `--fix-sig*`,
`--vector-to-sign`, `--sig-out`, `--pad-sig`, password-protected keys, `getpubhash`, `getpriv`, `keyinfo`, `dumpinfo`
and `getpub -e lang-rust`. The CLI rejects these arguments rather than ignoring them.

## Compatibility testing

`tests/compat.rs` runs the Python `imgtool` and this binary side by side:

- **Byte-identical output:** about 30 sign configurations (bin and hex, with and without an Ed25519 key, pure, sha512, big-endian, overwrite-only, RAM-load, ROM-fixed, ...), plus `getpub` output.
- **Cross-verification:** ECDSA signatures are randomized in Python, so each tool verifies images signed by the other instead.
- **Failure modes:** `verify` output for tampered images and wrong keys matches the Python tool.

```sh
git clone https://github.com/mcu-tools/mcuboot && pip install -r mcuboot/scripts/requirements.txt
IMGTOOL_PY=$PWD/mcuboot/scripts/imgtool.py cargo test
```

Without `IMGTOOL_PY` the differential test is skipped.

## Using it with Zephyr

- `west sign -t imgtool -p /path/to/imgtool -- --key root.pem` works as is.
- The CMake build (`CONFIG_MCUBOOT_SIGNATURE_KEY_FILE`) currently always runs `${PYTHON_EXECUTABLE} ${IMGTOOL}` (`cmake/mcuboot.cmake`), so it needs a small upstream change before it can use a native binary: prefix Python only when `IMGTOOL` ends in `.py`.

## License

Apache-2.0, the same license as MCUboot. The image format logic follows `scripts/imgtool/image.py`.
