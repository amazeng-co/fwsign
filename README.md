# fwsign

[![CI](https://github.com/amazeng-co/fwsign/actions/workflows/ci.yml/badge.svg)](https://github.com/amazeng-co/fwsign/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

fwsign signs, verifies and encrypts [MCUboot](https://github.com/mcu-tools/mcuboot) firmware images.
It is written in Rust and its command line is compatible with MCUboot's `scripts/imgtool.py`.

fwsign is an independent project. It is not MCUboot's official imgtool, and it is not affiliated
with the MCUboot project. Please report fwsign problems here, not to MCUboot.

- **One binary.** About 1.3 MB, and it needs only the system C library: no Python, pip or
  `cryptography`.
- **Same arguments as imgtool.** You can swap it in for imgtool in scripts and CI.
- **Verified against imgtool.** For unsigned and Ed25519-signed images the output is byte-identical
  to imgtool's. Every change is tested against it in CI.
- **Zephyr module.** Add it to your west manifest and Zephyr's MCUboot signing step uses fwsign. No
  changes to Zephyr are needed.
- **Fast.** In a Zephyr build the signing step takes 3.3 ms instead of 252 ms, and each run uses
  about a tenth of the memory ([benchmark](docs/benchmark.md)).

## Install

```sh
cargo install --locked --git https://github.com/amazeng-co/fwsign
```

This needs Rust 1.85 or newer.

## Command line

```sh
fwsign keygen -t ed25519 -k root.pem
fwsign sign -k root.pem -v 1.2.3 -H 0x200 --pad-header -S 0x40000 --pad --confirm zephyr.bin zephyr.signed.bin
fwsign verify -k root.pem zephyr.signed.bin
fwsign getpub -k root.pem     # C array for the bootloader
```

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

fwsign rejects these arguments instead of ignoring them. To request one, open an issue with the
"Missing imgtool feature" template.

## Zephyr

This repository is also a Zephyr module. When an application is built with MCUboot signing
(`CONFIG_BOOTLOADER_MCUBOOT`), the module points Zephyr's
[`SIGNING_SCRIPT`](https://docs.zephyrproject.org/latest/build/signing/index.html#west-extending-signing)
at `zephyr/fwsign.cmake`. That script runs Zephyr's own `cmake/mcuboot.cmake`, so all
`CONFIG_MCUBOOT_*` signing options and output files stay the same; only the tool it calls changes
from imgtool to fwsign.

### 1. Add fwsign to your west manifest

```yaml
manifest:
  remotes:
    - name: zephyrproject-rtos
      url-base: https://github.com/zephyrproject-rtos
    - name: amazeng-co
      url-base: https://github.com/amazeng-co

  projects:
    - name: zephyr
      remote: zephyrproject-rtos
      revision: v4.3.0
      import: true
    - name: fwsign
      remote: amazeng-co
      revision: main        # pin a tag or commit for reproducible builds
      path: modules/tools/fwsign
```

### 2. Fetch the module and install the binary

```sh
west update fwsign
cargo install --locked --path modules/tools/fwsign
```

### 3. Build as usual

```sh
west build -b nrf52840dk/nrf52840 app -- -DCONFIG_BOOTLOADER_MCUBOOT=y \
    -DCONFIG_MCUBOOT_SIGNATURE_KEY_FILE=\"/path/to/root-ed25519.pem\"
```

The build log shows which script and binary were used:

```
-- Including signing script: .../modules/tools/fwsign/zephyr/fwsign.cmake
-- Signing MCUboot images with /home/user/.cargo/bin/fwsign
```

### Options

- fwsign is looked up on `PATH`. To use a binary elsewhere, pass `-DFWSIGN=/path/to/fwsign`.
- To go back to imgtool for one build, pass `-DCONFIG_FWSIGN=n`.
- Without a west manifest, add the module with `-DZEPHYR_EXTRA_MODULES=/path/to/fwsign`.
- If you don't use the module at all, `west sign -t imgtool -p $(which fwsign) -- --key root.pem`
  also works.

### Tested

- **Version:** Zephyr v4.3.0, unmodified. The module should work with Zephyr 4.0 or later, but only
  v4.3.0 has been tested.
- **Build:** `samples/hello_world` for `nrf52840dk/nrf52840`, signed and signed + encrypted, with and
  without the module.
- **Signed images:** identical in both builds.
- **Encrypted images:** they cannot be identical, because every run uses a random AES key. Both
  decrypt to the signed image.
- See [docs/benchmark.md](docs/benchmark.md#zephyr-end-to-end-check) for details.

## Compatibility testing

`tests/compat.rs` runs MCUboot's Python imgtool and fwsign side by side:

- **Byte-identical output:** about 30 `sign` configurations, plus `getpub` output (except the
  "Autogenerated by" comment line). The `sign` cases cover bin and hex, with and without an Ed25519
  key, pure, sha512, big-endian, overwrite-only, RAM-load and ROM-fixed images.
- **Cross-verification:** ECDSA signatures are randomized in imgtool, so each tool verifies images
  signed by the other.
- **Encryption:** every run uses a fresh random key and ephemeral ECDH key, so output can't be
  compared directly. Instead:
  - `--clear` images are compared with the wrapped-key TLV masked out.
  - Encrypted images from both tools are decrypted by an independent ECIES implementation (Python
    `cryptography`) and checked against the image hash.
- **Failure modes:** `verify` output for tampered images and wrong keys matches imgtool.

```sh
git clone https://github.com/mcu-tools/mcuboot ../mcuboot
pip install 'cryptography>=40' 'intelhex>=2.2.1' click cbor2 pyyaml
IMGTOOL_PY=../mcuboot/scripts/imgtool.py cargo test
```

Without `IMGTOOL_PY` the differential test is skipped.

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for the test setup and the commit
style (Linux-style subjects, `Signed-off-by` required). Report security issues privately as described
in [SECURITY.md](SECURITY.md). This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md).

## License

Apache-2.0, the same license as MCUboot. The image format logic follows MCUboot's
`scripts/imgtool/image.py`.
