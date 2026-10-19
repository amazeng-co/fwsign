# Benchmark: imgtool-rs vs Python imgtool

## Summary

- **Zephyr build:** the post-build signing step of a Zephyr `hello_world` with MCUboot signing and
  encryption takes **3.3 ms instead of 251.6 ms (≈ 76×)**. The signed images are byte-identical.
- **Per invocation:** most runs are **13–120× faster**. Python spends about 55 ms on interpreter
  startup and imports before doing any work, so short invocations gain the most.
- **Memory:** peak memory is **3–9 MiB instead of 28–115 MiB**.
- **Install size:** a **1.3 MiB** binary that needs only the system C library, instead of 21 MiB of
  Python packages plus an interpreter.

## Zephyr end-to-end check

This check uses Zephyr v4.3.0 with the proposed `cmake/mcuboot.cmake` change, which runs native
`IMGTOOL` executables directly instead of through `${PYTHON_EXECUTABLE}`. The application is
`samples/hello_world` for `nrf52840dk/nrf52840` with `CONFIG_BOOTLOADER_MCUBOOT=y` and an Ed25519
signing key (`root-ed25519.pem` from MCUboot). Each configuration was built twice, once with
`-DIMGTOOL=mcuboot/scripts/imgtool.py` and once with `-DIMGTOOL=target/release/imgtool`.

| Configuration | Output | Result |
|---|---|---|
| Signed | `zephyr.signed.bin` | identical |
| Signed | `zephyr.signed.hex` | identical |
| Signed + `CONFIG_MCUBOOT_ENCRYPTION_KEY_FILE` (X25519) | `zephyr.signed.bin` | identical |
| Signed + `CONFIG_MCUBOOT_ENCRYPTION_KEY_FILE` (X25519) | `zephyr.signed.encrypted.bin` | both decrypt to the signed image ¹ |

¹ Encrypted output cannot be identical between runs, because each run picks a random AES key and an
ephemeral ECDH key. Both files were decrypted with an independent ECIES implementation (Python
`cryptography`) and the result was checked against the image hash TLV.

`build.ninja` confirms that the native binary is called directly and the Python script still goes
through the interpreter:

```
/usr/bin/python .../mcuboot/scripts/imgtool.py sign ...
.../imgtool-rs/target/release/imgtool sign ...
```

### Signing step time in that build

The encrypted configuration runs `imgtool sign` four times after linking: `.bin`, encrypted `.bin`,
`--clear` `.hex` and encrypted `.hex` (21 KiB image, 472 KiB slot). Those four commands were taken
from `build.ninja` and run back to back, 30 times:

| | Python imgtool | imgtool-rs | Speedup |
|---|---:|---:|---:|
| 4 × `imgtool sign` | 251.6 ms ± 4.3 | 3.3 ms ± 0.2 | 75.9× |

## Micro-benchmarks

The images are random data. `sign` uses the arguments Zephyr passes for a swap-mode image:
`--version 0.0.0+0 --header-size 0x200 --slot-size 0x200000 --align 4 --pad-header`.

### Environment

| | |
|---|---|
| CPU | 12th Gen Intel Core i5-12400F (6 cores / 12 threads) |
| OS | Ubuntu 22.04.5 LTS, Linux 5.15 |
| Python imgtool | 2.5.0rc2 (mcuboot `e19ad039b486`), Python 3.10.12, cryptography 50.0.2 in a clean venv |
| imgtool-rs | 0.1.0, `cargo build --release` (rustc 1.87.0) |
| Method | 30 runs per case after 2 warm-up runs. Median wall time of the whole process ± interquartile range |

### Time per invocation

| Case | Python | Rust | Speedup |
|---|---:|---:|---:|
| startup (`version`) | 56.8 ms ± 3.6 | 0.5 ms ± 0.1 | 115.3× |
| keygen ed25519 | 58.7 ms ± 3.1 | 0.5 ms ± 0.0 | 119.2× |
| sign 32 KiB, ed25519 | 61.2 ms ± 4.4 | 0.7 ms ± 0.1 | 86.9× |
| sign 1 MiB, ed25519 | 65.2 ms ± 46.9 | 3.0 ms ± 0.3 | 21.7× |
| sign 1 MiB, ed25519, `--pad --confirm` | 65.6 ms ± 1.9 | 5.2 ms ± 1.0 | 12.7× |
| sign 1 MiB, ed25519, hex out | 318.5 ms ± 16.1 | 7.9 ms ± 0.6 | 40.5× |
| sign 1 MiB, ecdsa-p256 | 64.1 ms ± 5.3 | 4.6 ms ± 0.1 | 14.0× |
| sign + encrypt 1 MiB, ed25519 + x25519 | 65.5 ms ± 4.3 | 3.9 ms ± 1.2 | 16.6× |
| verify 1 MiB, ed25519 | 60.8 ms ± 4.5 | 2.3 ms ± 0.1 | 26.5× |

### Peak memory (RSS)

| Case | Python | Rust |
|---|---:|---:|
| startup (`version`) | 28.2 MiB | 2.8 MiB |
| keygen ed25519 | 29.7 MiB | 2.9 MiB |
| sign 32 KiB, ed25519 | 30.2 MiB | 3.0 MiB |
| sign 1 MiB, ed25519 | 33.1 MiB | 4.7 MiB |
| sign 1 MiB, ed25519, `--pad --confirm` | 41.4 MiB | 5.6 MiB |
| sign 1 MiB, ed25519, hex out | 114.7 MiB | 8.6 MiB |
| sign 1 MiB, ecdsa-p256 | 33.7 MiB | 4.7 MiB |
| sign + encrypt 1 MiB, ed25519 + x25519 | 35.8 MiB | 4.7 MiB |
| verify 1 MiB, ed25519 | 32.8 MiB | 3.7 MiB |

### Install footprint

| | Size |
|---|---:|
| Python imgtool dependencies (cryptography, cffi, pycparser, intelhex, click, cbor2, PyYAML), excluding the interpreter | 21.2 MiB |
| imgtool-rs binary (needs only the system C library) | 1.3 MiB |

## Reading the numbers

- **Startup dominates.** For the image sizes typical of MCUboot targets, Python's time is mostly
  interpreter startup plus importing `cryptography` and `click` (≈ 55 ms). The signing work itself
  is a few milliseconds in both tools. For one image per build that cost is small, but it adds up in
  CI matrices, sysbuild with several images, `twister` runs that sign hundreds of images, and on
  production-line stations.
- **Intel HEX is where Python is slowest.** Writing 1 MiB through python-intelhex takes about
  250 ms more than writing the binary.
- **Noise.** The ± 46.9 ms on one Python row is a single slow run on a desktop that was not idle.
  Medians are stable across repeated runs.
- **Same hardware, one OS.** These numbers come from one x86-64 Linux machine. Windows and macOS
  were not measured.

## Reproducing

```sh
git clone https://github.com/mcu-tools/mcuboot
python3 -m venv venv
venv/bin/pip install 'cryptography>=40' 'intelhex>=2.2.1' click cbor2 pyyaml
cargo build --release
python3 scripts/bench.py --imgtool-py mcuboot/scripts/imgtool.py \
    --imgtool-rs target/release/imgtool --python venv/bin/python > report.md
```

`scripts/bench.py` needs only the Python standard library. Peak memory is measured with
GNU `time` (`/usr/bin/time`) and reported as `n/a` if it is missing.
