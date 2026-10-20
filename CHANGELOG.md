# Changelog

All notable changes to fwsign are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/). Before 1.0, minor releases may change behaviour.

## [0.1.0] - 2026-10-20

First release.

### Added

- **Commands:** `sign` (alias `create`), `verify`, `keygen`, `getpub` (`lang-c`, `pem`, `raw`) and
  `version`. The command line is compatible with MCUboot's `scripts/imgtool.py`.
- **Keys:** Ed25519 and ECDSA P-256, in PKCS#8 or SEC1 PEM, public or private.
- **Encryption:** ECIES-P256 and ECIES-X25519 (HMAC-SHA256/512), AES-128/256 image keys, `--clear`
  and `--save-enctlv`.
- **Images:** `.bin` and Intel `.hex` input and output. Pure signatures, overwrite-only, RAM-load,
  ROM-fixed and big-endian images; confirm/test trailers with custom alignment.
- **Zephyr module:** sets `SIGNING_SCRIPT` so Zephyr's MCUboot signing step runs fwsign. Tested with
  Zephyr v4.3.0.
- **Differential test:** runs MCUboot's Python imgtool side by side in CI. Unsigned and Ed25519
  images are byte-identical; ECDSA and encrypted images are cross-checked.
- **Prebuilt binaries:** Linux (x86_64, aarch64; static musl), macOS (x86_64, arm64) and Windows
  (x86_64).

### Not yet supported

RSA, ECDSA P-384, compression, `--vid/--cid`, boot records, dependencies, custom TLVs, fixed
signatures, password-protected keys, `dumpinfo`, `getpubhash`, `getpriv` and `keyinfo`. These
options are rejected rather than ignored.

[0.1.0]: https://github.com/amazeng-co/fwsign/releases/tag/v0.1.0
