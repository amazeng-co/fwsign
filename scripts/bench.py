#!/usr/bin/env python3
"""Benchmark fwsign against the Python imgtool and print a Markdown report.

usage: bench.py --imgtool-py mcuboot/scripts/imgtool.py --fwsign target/release/fwsign
                [--python venv/bin/python] [--runs 20]

Each case runs both tools on the same inputs. Wall time covers the whole
process (interpreter startup included), since that is what a build system
pays per invocation.

Peak RSS is measured separately with GNU time (/usr/bin/time -f %M). Linux
carries ru_maxrss across exec(), so a child spawned straight from this Python
process would report at least this process's own RSS; letting the small
`time` binary fork the tool avoids that.
"""

import argparse
import os
import platform
import statistics
import subprocess
import sys
import tempfile
import time


GNU_TIME = "/usr/bin/time"


def peak_rss_kib(cmd, runs=5):
    if not os.access(GNU_TIME, os.X_OK):
        return None
    with tempfile.NamedTemporaryFile("r") as f:
        peaks = []
        for _ in range(runs):
            subprocess.run([GNU_TIME, "-f", "%M", "-o", f.name, *cmd], check=True, capture_output=True)
            f.seek(0)
            peaks.append(int(f.read().split()[-1]))
    return max(peaks)


def run(cmd):
    """Run cmd, return wall seconds."""
    devnull = [(os.POSIX_SPAWN_OPEN, fd, os.devnull, os.O_WRONLY, 0) for fd in (1, 2)]
    t = time.perf_counter()
    pid = os.posix_spawnp(cmd[0], cmd, os.environ, file_actions=devnull)
    _, status = os.waitpid(pid, 0)
    dt = time.perf_counter() - t
    if os.waitstatus_to_exitcode(status) != 0:
        subprocess.run(cmd)  # rerun visibly to show the error
        sys.exit(f"failed: {' '.join(cmd)}")
    return dt


def measure(cmd, runs):
    for _ in range(2):  # warm the page cache
        run(cmd)
    times = [run(cmd) * 1000 for _ in range(runs)]
    q1, _, q3 = statistics.quantiles(times, n=4)
    return statistics.median(times), q3 - q1, peak_rss_kib(cmd)


def installed_size(python, dists):
    """Bytes installed for the given distributions (and nothing else) in `python`."""
    code = (
        "import importlib.metadata as m, os, sys\n"
        "t = 0\n"
        "for d in sys.argv[1:]:\n"
        "    dist = m.distribution(d)\n"
        "    t += sum(os.path.getsize(dist.locate_file(f)) for f in dist.files or []\n"
        "             if os.path.isfile(dist.locate_file(f)))\n"
        "print(t)\n"
    )
    return int(subprocess.check_output([python, "-c", code, *dists]))


def tool_output(cmd):
    return subprocess.check_output(cmd, text=True).strip()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--imgtool-py", required=True)
    ap.add_argument("--fwsign", required=True)
    ap.add_argument("--python", default=sys.executable, help="interpreter with imgtool's dependencies")
    ap.add_argument("--runs", type=int, default=30)
    a = ap.parse_args()

    py = [a.python, a.imgtool_py]
    rs = [a.fwsign]
    d = tempfile.mkdtemp(prefix="fwsign-bench-")
    p = lambda n: os.path.join(d, n)  # noqa: E731

    for kind, name in [("ed25519", "ed.pem"), ("ecdsa-p256", "ec.pem"), ("x25519", "x.pem")]:
        subprocess.check_call(py + ["keygen", "-t", kind, "-k", p(name)])
    with open(p("x-pub.pem"), "w") as f:
        subprocess.check_call(py + ["getpub", "-e", "pem", "-k", p("x.pem")], stdout=f)
    for name, size in [("32k.bin", 32 << 10), ("1m.bin", 1 << 20)]:
        with open(p(name), "wb") as f:
            f.write(os.urandom(size))

    # Same arguments Zephyr's cmake/mcuboot.cmake passes for a swap-mode image.
    zephyr = ["--version", "0.0.0+0", "--header-size", "0x200", "--slot-size", "0x200000", "--align", "4", "--pad-header"]
    cases = [
        ("startup (`version`)", ["version"]),
        ("keygen ed25519", ["keygen", "-t", "ed25519", "-k", p("k.pem")]),
        ("sign 32 KiB, ed25519", ["sign", *zephyr, "-k", p("ed.pem"), p("32k.bin"), p("o.bin")]),
        ("sign 1 MiB, ed25519", ["sign", *zephyr, "-k", p("ed.pem"), p("1m.bin"), p("o.bin")]),
        ("sign 1 MiB, ed25519, `--pad --confirm`", ["sign", *zephyr, "--pad", "--confirm", "-k", p("ed.pem"), p("1m.bin"), p("o.bin")]),
        ("sign 1 MiB, ed25519, hex out", ["sign", *zephyr, "-x", "0x10000", "-k", p("ed.pem"), p("1m.bin"), p("o.hex")]),
        ("sign 1 MiB, ecdsa-p256", ["sign", *zephyr, "-k", p("ec.pem"), p("1m.bin"), p("o.bin")]),
        ("sign + encrypt 1 MiB, ed25519 + x25519", ["sign", *zephyr, "-k", p("ed.pem"), "-E", p("x-pub.pem"), p("1m.bin"), p("o.bin")]),
        ("verify 1 MiB, ed25519", ["sign", *zephyr, "-k", p("ed.pem"), p("1m.bin"), p("v.bin")]),
    ]

    rows = []
    for name, args in cases:
        if name.startswith("verify"):
            subprocess.check_call(rs + args, stdout=subprocess.DEVNULL)
            args = ["verify", "-k", p("ed.pem"), p("v.bin")]
        rp, rr = measure(py + args, a.runs), measure(rs + args, a.runs)
        rows.append((name, rp, rr))
        print(f"  {name}: {rp[0]:.1f} ms vs {rr[0]:.1f} ms", file=sys.stderr)

    deps = ["cryptography", "cffi", "pycparser", "intelhex", "click", "cbor2", "PyYAML"]
    dep_bytes = installed_size(a.python, deps)
    rs_bytes = os.path.getsize(a.fwsign)
    py_ver = tool_output([a.python, "-c", "import sys, cryptography; print(sys.version.split()[0], cryptography.__version__)"]).split()

    cpu = next((l.split(":", 1)[1].strip() for l in open("/proc/cpuinfo") if l.startswith("model name")), platform.processor())
    print(f"""## Environment

| | |
|---|---|
| CPU | {cpu} |
| OS | {platform.system()} {platform.release()} |
| Python imgtool | {tool_output(py + ['version'])}, Python {py_ver[0]}, cryptography {py_ver[1]} |
| fwsign | {tool_output(rs + ['version'])}, release build |
| Runs | {a.runs} per case after 2 warm-up runs; median wall time of the whole process, ± interquartile range |

## Time per invocation

| Case | Python imgtool | fwsign | Speedup |
|---|---:|---:|---:|""")
    for name, (pm, ps, _), (rm, rsd, _) in rows:
        print(f"| {name} | {pm:.1f} ms ± {ps:.1f} | {rm:.1f} ms ± {rsd:.1f} | {pm / rm:.1f}× |")
    print("""
## Peak memory (RSS)

| Case | Python imgtool | fwsign |
|---|---:|---:|""")
    for name, (_, _, pk), (_, _, rk) in rows:
        mib = lambda k: "n/a" if k is None else f"{k / 1024:.1f} MiB"  # noqa: E731
        print(f"| {name} | {mib(pk)} | {mib(rk)} |")
    print(f"""
## Install footprint

| | Size |
|---|---:|
| Python imgtool dependencies ({', '.join(deps)}), excluding the interpreter | {dep_bytes / 2**20:.1f} MiB |
| fwsign binary (needs only the system C library) | {rs_bytes / 2**20:.1f} MiB |""")


if __name__ == "__main__":
    main()
