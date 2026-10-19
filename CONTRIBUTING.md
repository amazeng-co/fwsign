# Contributing to imgtool-rs

Thanks for your interest. imgtool-rs aims to be a drop-in replacement for MCUboot's
`scripts/imgtool.py`. The Python tool is the reference, so a change is correct when it
produces what the Python tool produces.

## Reporting bugs

Open an issue using the bug report template. The most useful report contains:

- the exact `imgtool` command line,
- the same command run with the Python `imgtool`, and its MCUboot commit or version,
- which output differs (attach both files if you can).

Do not report security vulnerabilities in public issues. See [SECURITY.md](SECURITY.md).

## Development

```sh
cargo build
cargo fmt --check
cargo clippy --all-targets -- -D warnings
```

### The differential test

`tests/compat.rs` runs the Python imgtool and this binary side by side and compares their output.
Without a Python imgtool the test is skipped, so set it up once:

```sh
git clone https://github.com/mcu-tools/mcuboot ../mcuboot
pip install 'cryptography>=40' 'intelhex>=2.2.1' click cbor2 pyyaml
IMGTOOL_PY=../mcuboot/scripts/imgtool.py cargo test
```

CI pins the MCUboot commit it tests against (see `.github/workflows/ci.yml`).

### Adding an imgtool option

1. Implement it to match `scripts/imgtool/image.py` / `main.py`: same argument names and short
   flags, same defaults, same error cases.
2. Add a case to `tests/compat.rs`:
   - Deterministic output (unsigned, Ed25519): require byte-identical output.
   - Randomized output (ECDSA, encryption): cross-verify, or decrypt, instead.
3. Move the option from "Not yet supported" to the status table in `README.md`.

Options the tool does not implement must stay rejected by the argument parser. Silently ignoring
an option would produce an image different from the one the user asked for.

### Benchmarks

`scripts/bench.py` reproduces [docs/benchmark.md](docs/benchmark.md). If a change affects
performance, include before/after numbers in the pull request.

## Commits and pull requests

The project follows the Linux kernel / Zephyr commit style:

- **Subject:** `area: short imperative summary`, at most 72 characters, for example
  `image: add RSA-3072 signing` or `tests: cover --custom-tlv`.
- **Body:** explains *why* the change is needed and anything non-obvious about *how*. Wrap at 72
  columns.
- **Scope:** one logical change per commit. Every commit must build and pass the tests.
- **Sign-off:** every commit needs a `Signed-off-by` line (`git commit -s`). By adding it you
  certify the [Developer Certificate of Origin](https://developercertificate.org/): you wrote
  the change, or otherwise have the right to submit it under the project's license.

Keep pull requests focused. Rebase on `main` rather than merging it into your branch.

## License

By contributing, you agree that your contributions are licensed under the
[Apache License 2.0](LICENSE), the same license as MCUboot.

## Code of conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md).
