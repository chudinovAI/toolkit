#!/usr/bin/env python3
"""Compare command resource use with observed allocator bindings."""
import argparse
import ctypes
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import _bench

ROOT = Path(__file__).resolve().parents[2]
AUDITOR = ROOT / "build" / "liballocaudit.so"
NAMES = ("system", "jemalloc", "mimalloc")


def allocator_names(value):
    names = value.split(",")
    if not names or any(n not in NAMES for n in names) or len(set(names)) != len(names):
        raise argparse.ArgumentTypeError("choose distinct names from system,jemalloc,mimalloc")
    return names


def overrides(values):
    result = {}
    for value in values:
        name, separator, path = value.partition("=")
        if not separator or name not in NAMES[1:] or not path or name in result:
            raise _bench.BenchError("--allocator requires a unique jemalloc=PATH or mimalloc=PATH")
        resolved = Path(path).expanduser().resolve()
        if not resolved.is_file():
            raise _bench.BenchError(f"allocator library does not exist: {path}")
        result[name] = str(resolved)
    return result


def find_allocator(name):
    program = shutil.which("ldconfig")
    if not program:
        program = next((p for p in ("/sbin/ldconfig", "/usr/sbin/ldconfig") if os.path.isfile(p)), None)
    if program:
        try:
            output = subprocess.run([program, "-p"], text=True, capture_output=True, check=False).stdout
        except OSError:
            output = ""
        for line in output.splitlines():
            left, sep, path = line.partition("=>")
            if sep and left.strip().split()[0].startswith("lib" + name + ".so"):
                candidate = Path(path.strip())
                if candidate.is_file():
                    return str(candidate.resolve())
    return None


def glibc_malloc_provider():
    class DlInfo(ctypes.Structure):
        _fields_ = [("filename", ctypes.c_char_p), ("base", ctypes.c_void_p),
                    ("symbol", ctypes.c_char_p), ("address", ctypes.c_void_p)]

    try:
        libc = ctypes.CDLL("libc.so.6")
        libdl = ctypes.CDLL("libdl.so.2")
        libdl.dladdr.argtypes = [ctypes.c_void_p, ctypes.POINTER(DlInfo)]
        libdl.dladdr.restype = ctypes.c_int
        info = DlInfo()
        if not libdl.dladdr(ctypes.cast(libc.malloc, ctypes.c_void_p), ctypes.byref(info)) or not info.filename:
            raise _bench.BenchError("cannot identify glibc malloc provider using dladdr")
        path = os.path.realpath(os.fsdecode(info.filename))
        if not os.path.isfile(path):
            raise _bench.BenchError(f"glibc malloc provider is not a file: {path}")
        return path
    except (OSError, AttributeError) as exc:
        raise _bench.BenchError(f"cannot identify glibc malloc provider: {exc}") from exc


def binding_evidence(config, records, system_library=None):
    direct = [record for record in records if record["direct_image"]]
    if not any(record["kind"] == "A" for record in direct):
        raise _bench.BenchError("glibc audit helper did not report for the directly launched image; it may be static, use secure execution, or lack /proc access")
    bindings = list(dict.fromkeys(record["detail"] for record in direct if record["kind"] == "M"))
    if not bindings:
        raise _bench.BenchError("no dynamic malloc binding observed in the directly launched image; its allocator is unknown")
    override = config["library"]
    expected = override or system_library or glibc_malloc_provider()
    matches = []
    for path in bindings:
        try:
            matches.append(os.path.samefile(path, expected))
        except OSError:
            matches.append(False)
    if not any(matches):
        raise _bench.BenchError(f"{config['allocator']} malloc provider was not observed binding malloc in the directly launched image")
    if not all(matches):
        raise _bench.BenchError(f"mixed malloc providers observed for {config['allocator']}: {', '.join(bindings)}")
    return {"malloc_binding_objects": bindings, "requested_override_observed": True if override else None,
            "expected_malloc_provider": expected}


def tls_environment(surplus):
    if surplus is None:
        return {}
    key = "glibc.rtld.optional_static_tls"
    entries = [entry for entry in os.environ.get("GLIBC_TUNABLES", "").split(":")
               if entry and entry.partition("=")[0] != key]
    entries.append(f"{key}={surplus}")
    return {"GLIBC_TUNABLES": ":".join(entries)}


def main():
    parser = argparse.ArgumentParser(description="Run a command repeatedly with selected allocators; glibc LD_AUDIT verifies malloc bindings. Static, Go and custom allocators may not be instrumentable.")
    parser.add_argument("--allocators", type=allocator_names, default=["system"],
                        metavar="NAMES", help="comma-separated system,jemalloc,mimalloc (default: system)")
    parser.add_argument("--allocator", action="append", default=[], metavar="NAME=PATH",
                        help="explicit shared-library path for jemalloc or mimalloc; repeatable")
    parser.add_argument("--tls-surplus", type=_bench.bounded_int(0, 16777216), metavar="BYTES",
                        help="explicit per-thread glibc static TLS reserve for every configuration; try 65536 if LD_AUDIT plus jemalloc exhausts static TLS (default: preserve inherited policy)")
    _bench.add_common(parser)
    args = parser.parse_args()
    _bench.prepare(args, len(args.allocators))
    if platform.libc_ver()[0] != "glibc":
        raise _bench.BenchError("alloc-bench requires a glibc dynamic loader with LD_AUDIT")
    if not AUDITOR.is_file():
        raise _bench.BenchError(f"missing audit helper {AUDITOR}; build the project first")
    explicit = overrides(args.allocator)
    configs = []
    for name in args.allocators:
        library = None if name == "system" else explicit.get(name) or find_allocator(name)
        if name != "system" and not library:
            raise _bench.BenchError(f"{name} library not found; provide --allocator {name}=PATH")
        configs.append((name, {"allocator": name, "library": library}))
    system_library = glibc_malloc_provider() if "system" in args.allocators else None
    tls_env = tls_environment(args.tls_surplus)

    with tempfile.TemporaryDirectory(prefix="bench-loader-", dir="/tmp") as directory:
        auditor = _bench.loader_link(directory, "audit", AUDITOR)
        libraries = {name: _bench.loader_link(directory, name, config["library"])
                     for name, config in configs if config["library"]}

        def environment(config):
            env = {"LD_AUDIT": auditor, **tls_env}
            if config["library"]:
                env["LD_PRELOAD"] = libraries[config["allocator"]]
            return env

        report = _bench.run(args, configs, environment,
                            lambda config, records: binding_evidence(config, records, system_library))
    report["tool"] = "alloc-bench"
    report["audit_static_tls_surplus_bytes"] = args.tls_surplus
    report["limitations"] = ["LD_AUDIT observes dynamic malloc symbol bindings, not allocation counts or every allocation API.",
                             "--tls-surplus changes per-thread memory overhead equally in every configuration; unset preserves the inherited glibc policy.",
                             "Static binaries, Go runtimes, custom allocators and secure-execution programs may bypass dynamic malloc interposition.",
                             "Evidence is required from the direct process's resolved workload image (after a supported env shebang); other exec and descendant coverage is unknown.",
                             "Loader-safe symlinks preserve library-directory dependencies for ordinary filenames; a library filename containing whitespace or ':' may change $ORIGIN resolution.",
                             "Inherited LD_PRELOAD and LD_AUDIT are rejected; the audit helper is active in every configuration."]
    _bench.emit(report, args.json)


if __name__ == "__main__":
    sys.exit(_bench.main_guard(main))
