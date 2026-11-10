#!/usr/bin/env python3
"""Benchmark TCP socket options with observed libc interposition."""
import argparse
import itertools
from pathlib import Path
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import _bench

ROOT = Path(__file__).resolve().parents[2]
INTERPOSER = ROOT / "build" / "libsocketbench.so"


def choices(value):
    result = value.split(",")
    if any(item not in ("default", "on", "off") for item in result) or len(set(result)) != len(result):
        raise argparse.ArgumentTypeError("choose distinct values from default,on,off")
    return result


def buffers(value):
    result = []
    for item in value.split(","):
        if item == "default":
            parsed = None
        else:
            try:
                parsed = int(item, 10)
            except ValueError:
                raise argparse.ArgumentTypeError("buffer sizes must be default or integers in 1-2147483647") from None
            if not 1 <= parsed <= 2147483647:
                raise argparse.ArgumentTypeError("buffer sizes must be default or integers in 1-2147483647")
        if parsed in result:
            raise argparse.ArgumentTypeError("buffer sizes must be distinct")
        result.append(parsed)
    return result


def socket_evidence(config, records):
    values = []
    for record in records:
        if record["kind"] == "E":
            raise _bench.BenchError(f"socket instrumentation failed in pid {record['pid']}: {record['detail']} errno {record['values'][0]}")
        if record["kind"] == "S" and record["direct_image"]:
            family, nd, snd, rcv = record["values"]
            if config["nodelay"] != "default" and nd != int(config["nodelay"] == "on"):
                raise _bench.BenchError("TCP_NODELAY did not take the requested value")
            entry = {"address_family": family, "tcp_nodelay": nd,
                     "sndbuf_bytes": snd, "rcvbuf_bytes": rcv}
            if entry not in values:
                values.append(entry)
    if not values:
        raise _bench.BenchError("no eligible TCP sockets observed in the directly launched image; static programs, direct syscalls, "
                                "inherited sockets and unsupported runtimes can bypass libc interposition")
    return {"effective_values": values, "evidence": "successful socket/accept calls in the resolved direct workload image, up to 128 samples per process",
            "sampling_truncated": any(record["kind"] == "T" for record in records)}


def main():
    parser = argparse.ArgumentParser(description="Compare TCP options on sockets made by libc socket/accept/accept4. No sysctls are changed; direct syscalls and static binaries are not instrumented.")
    parser.add_argument("--nodelay", type=choices, default=["default", "on", "off"],
                        metavar="VALUES", help="comma-separated default,on,off")
    parser.add_argument("--sndbuf", type=buffers, default=[None], metavar="VALUES",
                        help="comma-separated default or SO_SNDBUF byte values")
    parser.add_argument("--rcvbuf", type=buffers, default=[None], metavar="VALUES",
                        help="comma-separated default or SO_RCVBUF byte values")
    _bench.add_common(parser)
    args = parser.parse_args()
    count = len(args.nodelay) * len(args.sndbuf) * len(args.rcvbuf)
    _bench.prepare(args, count)
    if not INTERPOSER.is_file():
        raise _bench.BenchError(f"missing socket interposer {INTERPOSER}; build the project first")
    configs = []
    for index, (nd, snd, rcv) in enumerate(itertools.product(args.nodelay, args.sndbuf, args.rcvbuf)):
        configs.append((str(index), {"nodelay": nd, "sndbuf_bytes": snd, "rcvbuf_bytes": rcv}))

    with tempfile.TemporaryDirectory(prefix="bench-loader-", dir="/tmp") as directory:
        interposer = _bench.loader_link(directory, "socket", INTERPOSER)

        def environment(config):
            modes = {"default": -1, "on": 1, "off": 0}
            return {"LD_PRELOAD": interposer,
                    "BENCH_TCP_NODELAY": str(modes[config["nodelay"]]),
                    "BENCH_SNDBUF": str(config["sndbuf_bytes"] if config["sndbuf_bytes"] is not None else -1),
                    "BENCH_RCVBUF": str(config["rcvbuf_bytes"] if config["rcvbuf_bytes"] is not None else -1)}

        report = _bench.run(args, configs, environment, socket_evidence)
    report["tool"] = "socket-bench"
    report["limitations"] = ["Explicit SO_SNDBUF and SO_RCVBUF can disable or alter kernel autotuning; Linux reports effective buffer sizes which can differ from requests.",
                             "Options are set before socket/accept returns; the application may later change them. Only IPv4/IPv6 TCP streams through interposed libc calls are observed.",
                             "Static executables, direct syscalls, io_uring and previously inherited sockets can bypass interposition; independently measure workload throughput and request latency.",
                             "Evidence is required from the direct process's resolved workload image (after a supported env shebang); other exec and descendant coverage is unknown.",
                             "Inherited LD_PRELOAD and LD_AUDIT are rejected for all configurations."]
    _bench.emit(report, args.json)


if __name__ == "__main__":
    sys.exit(_bench.main_guard(main))
