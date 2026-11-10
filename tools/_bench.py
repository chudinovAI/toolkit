"""Common Linux command benchmarking primitives."""
import argparse
import ctypes
import json
import math
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import statistics
import struct
import subprocess
import sys
import tempfile
import time


class BenchError(Exception):
    pass


HEADER = struct.Struct("=8s32sIIII")
RECORD = struct.Struct("=IiIiiiiIQQ512s1024s")
CAPACITY = 2048
MAGIC = b"BENCH01\0"


def bounded_int(low, high):
    def parse(value):
        try:
            result = int(value, 10)
        except ValueError:
            raise argparse.ArgumentTypeError("expected an integer") from None
        if not low <= result <= high:
            raise argparse.ArgumentTypeError(f"must be between {low} and {high}")
        return result
    return parse


def bounded_timeout(value):
    try:
        result = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError("expected a timeout in seconds") from None
    if not math.isfinite(result) or not 0.01 <= result <= 86400:
        raise argparse.ArgumentTypeError("timeout must be between 0.01 and 86400 seconds")
    return result


def add_common(parser):
    parser.add_argument("--runs", type=bounded_int(1, 1000), default=5,
                        help="measured repetitions per configuration (1-1000)")
    parser.add_argument("--warmup", type=bounded_int(0, 1000), default=1,
                        help="unmeasured repetitions per configuration (0-1000)")
    parser.add_argument("--timeout", type=bounded_timeout, default=300.0, metavar="SECONDS",
                        help="per-execution deadline, 0.01-86400 seconds (default: 300)")
    parser.add_argument("--json", action="store_true", help="emit one JSON report")
    parser.add_argument("command", nargs=argparse.REMAINDER, help="command after --")


def prepare(args, count):
    if sys.platform != "linux":
        raise BenchError("this benchmark requires Linux")
    if os.environ.get("BENCH_ACTIVE"):
        raise BenchError("nested benchmarks are not supported")
    inherited = [name for name in ("LD_PRELOAD", "LD_AUDIT") if os.environ.get(name)]
    if inherited:
        raise BenchError("unset inherited " + " and ".join(inherited) + " for a fair baseline")
    command = args.command
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        raise BenchError("provide a command after --")
    if count < 1 or count > 64 or count * (args.runs + args.warmup) > 10000:
        raise BenchError("configuration count must be 1-64 and total executions at most 10000")
    return command


def loader_link(directory, name, target):
    """glibc splits loader paths on spaces/colons, even when shell-quoted."""
    target = Path(os.path.abspath(target))
    if not any(char in target.name for char in " :\t\n"):
        # Linking the containing directory keeps $ORIGIN dependencies reachable.
        directory_link = Path(directory) / (name + "-dir")
        os.symlink(target.parent, directory_link)
        return str(directory_link / target.name)
    link = Path(directory) / name
    os.symlink(target, link)
    return str(link)


def env_interpreter(argument):
    """Resolve only unambiguous env shebang forms, without emulating a shell."""
    argument = argument.strip()
    if argument == "-S" or argument.startswith(("-S ", "-S\t")):
        words = argument[2:].split()
        if words and words[0] == "--":
            words.pop(0)
        if not words or any(not re.fullmatch(r"[A-Za-z0-9_./+-]+", word) for word in words):
            raise BenchError("unsupported or ambiguous env -S shebang; use simple unquoted arguments")
    else:
        words = [argument]
        if not argument or not re.fullmatch(r"[A-Za-z0-9_./+-]+", argument):
            raise BenchError("unsupported or ambiguous env shebang; use env PROGRAM or env -S PROGRAM ARGS")
    if words[0].startswith("-"):
        raise BenchError("env shebang options or environment assignments are unsupported")
    path = shutil.which(words[0])
    if path is None:
        raise BenchError(f"cannot find shebang interpreter: {words[0]}")
    return path


def initial_image(command):
    """Resolve the direct workload image, including simple env script launchers."""
    path = shutil.which(command)
    if path is None:
        raise BenchError(f"cannot find executable: {command}")
    for _ in range(8):
        try:
            with open(path, "rb") as executable:
                first = executable.readline(4096)
            if not first.startswith(b"#!"):
                info = os.stat(path)
                return {"path": os.path.realpath(path), "device": info.st_dev, "inode": info.st_ino}
            words = first[2:].strip().split(None, 1)
            if not words:
                raise BenchError(f"invalid script interpreter: {path}")
            interpreter = os.fsdecode(words[0])
            if os.path.basename(interpreter) == "env":
                if os.path.realpath(interpreter) != os.path.realpath("/usr/bin/env"):
                    raise BenchError(f"unsupported env shebang interpreter: {interpreter}")
                path = env_interpreter(os.fsdecode(words[1]) if len(words) > 1 else "")
            else:
                path = interpreter
        except OSError as exc:
            raise BenchError(f"cannot inspect executable {path}: {exc}") from exc
    raise BenchError("script interpreter chain is too deep")


def read_evidence(file, token, pid, image):
    file.seek(0)
    header = file.read(HEADER.size)
    if len(header) != HEADER.size:
        raise BenchError("truncated instrumentation evidence")
    magic, actual_token, version, count, overflow, _ = HEADER.unpack(header)
    if magic != MAGIC or actual_token != token or version != 1 or overflow or count > CAPACITY:
        raise BenchError("invalid or overflowed instrumentation evidence")
    records, groups = [], {}
    for _ in range(count):
        chunk = file.read(RECORD.size)
        if len(chunk) != RECORD.size:
            raise BenchError("truncated instrumentation record")
        ready, record_pid, kind, a, b, c, d, _, dev, ino, exe, detail = RECORD.unpack(chunk)
        if ready != 1:
            raise BenchError("incomplete instrumentation record")
        if kind not in (ord("A"), ord("M"), ord("S"), ord("E"), ord("T")):
            raise BenchError("invalid instrumentation record type")
        exe = os.fsdecode(exe.split(b"\0", 1)[0])
        detail = os.fsdecode(detail.split(b"\0", 1)[0])
        direct = record_pid == pid and dev == image["device"] and ino == image["inode"]
        record = {"kind": chr(kind), "pid": record_pid, "executable": exe,
                  "device": dev, "inode": ino, "direct_image": direct,
                  "values": [a, b, c, d], "detail": detail}
        records.append(record)
        key = (record_pid, dev, ino, exe)
        if key not in groups:
            groups[key] = {"pid": record_pid, "executable": exe, "device": dev,
                           "inode": ino, "direct_initial_image": direct, "record_types": []}
        if record["kind"] not in groups[key]["record_types"]:
            groups[key]["record_types"].append(record["kind"])
    return records, {"direct_pid": pid, "initial_image": image,
                     "observed_process_images": list(groups.values()),
                     "coverage": "Only recorded process images are observed; descendant and later-exec coverage is unknown."}


def kill_group(pid):
    try:
        os.killpg(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def enable_subreaper():
    libc = ctypes.CDLL(None, use_errno=True)
    previous = ctypes.c_int()
    if libc.prctl(37, ctypes.byref(previous), 0, 0, 0) != 0:
        error = ctypes.get_errno()
        raise BenchError(f"cannot inspect child-subreaper state: {os.strerror(error)}")
    if not previous.value and libc.prctl(36, 1, 0, 0, 0) != 0:
        error = ctypes.get_errno()
        raise BenchError(f"cannot enable child-subreaper: {os.strerror(error)}")
    return libc, previous.value


def restore_subreaper(state):
    libc, previous = state
    if not previous and libc.prctl(36, 0, 0, 0, 0) != 0:
        error = ctypes.get_errno()
        raise BenchError(f"cannot restore child-subreaper state: {os.strerror(error)}")


def reap_workload(child, deadline):
    """Kill the original group, then stop/reap all adopted descendants."""
    kill_group(child.pid)
    while True:
        try:
            pid, status, usage = os.wait4(child.pid, os.WNOHANG)
        except ChildProcessError as exc:
            raise BenchError("cannot reap benchmark command") from exc
        if pid:
            child.returncode = os.waitstatus_to_exitcode(status)
            break
        if time.monotonic() >= deadline:
            raise BenchError("benchmark command did not terminate during cleanup")
        time.sleep(0.01)

    children_file = f"/proc/self/task/{os.getpid()}/children"
    while True:
        try:
            pid, _ = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            return status, usage
        if pid:
            continue
        try:
            with open(children_file, encoding="ascii") as file:
                adopted = [int(item) for item in file.read().split()]
            for descendant in adopted:
                try:
                    os.kill(descendant, signal.SIGKILL)
                except ProcessLookupError:
                    pass
        except (OSError, ValueError) as exc:
            raise BenchError(f"cannot clean up benchmark descendants: {exc}") from exc
        if time.monotonic() >= deadline:
            raise BenchError("benchmark descendants did not terminate during cleanup")
        time.sleep(0.01)


def run_one(command, extra_env, inspect, timeout):
    image = initial_image(command[0])
    env = os.environ.copy()
    env.update(extra_env)
    env["BENCH_ACTIVE"] = "1"
    with tempfile.TemporaryFile(mode="w+b") as evidence:
        token = secrets.token_hex(16).encode("ascii")
        evidence.write(HEADER.pack(MAGIC, token, 1, 0, 0, 0))
        evidence.truncate(HEADER.size + CAPACITY * RECORD.size)
        evidence.flush()
        env["BENCH_EVIDENCE_FD"] = str(evidence.fileno())
        env["BENCH_EVIDENCE_TOKEN"] = token.decode("ascii")
        start = time.monotonic_ns()
        child = None
        subreaper = None
        saved_handlers = {}
        previous_timer = None
        timer_changed = False
        pending = []
        failure = None
        cleanup_failure = None
        usage = None

        def defer_signal(signum, frame):
            pending.append(signum)

        def deadline_expired(signum, frame):
            raise BenchError(f"target exceeded {timeout:g} second timeout")

        try:
            # Defer signals while Popen returns its child handle.  Otherwise an
            # interruption between fork and assignment can lose the only PID.
            for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGALRM):
                saved_handlers[signum] = signal.getsignal(signum)
                signal.signal(signum, defer_signal)
            previous_timer = signal.getitimer(signal.ITIMER_REAL)
            subreaper = enable_subreaper()
            if pending:
                raise KeyboardInterrupt
            try:
                child = subprocess.Popen(command, env=env, stdout=sys.stderr,
                                         pass_fds=(evidence.fileno(),), start_new_session=True)
            except OSError as exc:
                raise BenchError(f"cannot start {command[0]}: {exc}") from exc
            if pending:
                raise KeyboardInterrupt
            remaining = timeout - (time.monotonic_ns() - start) / 1e9
            if remaining <= 0:
                raise BenchError(f"target exceeded {timeout:g} second timeout")
            timer_changed = True
            signal.signal(signal.SIGALRM, deadline_expired)
            signal.setitimer(signal.ITIMER_REAL, remaining)
            signal.signal(signal.SIGINT, saved_handlers[signal.SIGINT])
            signal.signal(signal.SIGTERM, saved_handlers[signal.SIGTERM])
            if pending:
                raise KeyboardInterrupt
            # WNOWAIT preserves the group leader PID until the group is killed.
            os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOWAIT)
            finished = time.monotonic_ns()
        except BaseException as exc:
            failure = exc
        finally:
            # Mask interruption only in the parent, after spawn, until every
            # evidence writer is dead and reaped.  The workload never inherits
            # this mask.
            mask = signal.pthread_sigmask(signal.SIG_BLOCK,
                                          {signal.SIGINT, signal.SIGTERM, signal.SIGALRM})
            try:
                if timer_changed:
                    signal.setitimer(signal.ITIMER_REAL, 0)
                if child is not None:
                    try:
                        _, usage = reap_workload(child, time.monotonic() + 5.0)
                    except BaseException as exc:
                        cleanup_failure = exc
                if subreaper is not None:
                    try:
                        restore_subreaper(subreaper)
                    except BaseException as exc:
                        cleanup_failure = cleanup_failure or exc
                # An expiry queued during teardown belongs to our cancelled
                # deadline, not to the caller's restored alarm handler.
                if timer_changed and signal.SIGALRM in signal.sigpending():
                    signal.sigtimedwait({signal.SIGALRM}, 0)
                for signum, handler in saved_handlers.items():
                    signal.signal(signum, handler)
                if timer_changed and previous_timer is not None:
                    signal.setitimer(signal.ITIMER_REAL, *previous_timer)
            finally:
                signal.pthread_sigmask(signal.SIG_SETMASK, mask)
        if cleanup_failure is not None:
            raise BenchError(f"benchmark cleanup incomplete: {cleanup_failure}") from cleanup_failure
        if failure is not None:
            raise failure
        if pending:
            raise KeyboardInterrupt
        elapsed = (finished - start) / 1e9
        records, coverage = read_evidence(evidence, token, child.pid, image)
        if child.returncode != 0:
            failures = [r["detail"] + ": " + str(r["values"][0]) for r in records if r["kind"] == "E"]
            suffix = f"; instrumentation: {', '.join(failures[:5])}" if failures else ""
            raise BenchError(f"target exited with status {child.returncode}{suffix}")
        observed = inspect(records)
        observed["process_image_coverage"] = coverage
        return {"wall_seconds": elapsed, "user_seconds": usage.ru_utime,
                "system_seconds": usage.ru_stime, "peak_rss_kib": usage.ru_maxrss,
                "minor_faults": usage.ru_minflt, "major_faults": usage.ru_majflt,
                "instrumentation": observed}


def run(args, configs, make_env, inspect):
    command = prepare(args, len(configs))
    results = {key: [] for key, _ in configs}
    for cycle in range(args.warmup + args.runs):
        order = cycle % len(configs)
        for key, config in configs[order:] + configs[:order]:
            result = run_one(command, make_env(config), lambda records: inspect(config, records), args.timeout)
            if cycle >= args.warmup:
                results[key].append(result)
    summary = []
    for key, config in configs:
        samples = results[key]
        metrics = ("wall_seconds", "user_seconds", "system_seconds", "peak_rss_kib",
                   "minor_faults", "major_faults")
        summary.append({"configuration": config, "samples": samples,
                        "median": {name: statistics.median(s[name] for s in samples)
                                   for name in metrics}})
    return {"command": command, "runs": args.runs, "warmup": args.warmup,
            "timeout_seconds": args.timeout, "execution_order": "rotating", "results": summary,
            "resource_scope": "wait4 child and its waited-for descendants; peak RSS in KiB on Linux"}


def emit(report, as_json):
    if as_json:
        print(json.dumps(report, indent=2))
        return
    print(f"{report['tool']}: {report['runs']} measured runs, {report['warmup']} warmups per configuration")
    print("Command:", " ".join(json.dumps(arg) for arg in report["command"]))
    print("Execution order: rotating")
    for item in report["results"]:
        print("\nConfiguration:", json.dumps(item["configuration"], sort_keys=True))
        print("  Medians:", ", ".join(f"{name}={value}" for name, value in item["median"].items()))
        for number, sample in enumerate(item["samples"], 1):
            print(f"  Run {number} instrumentation:", json.dumps(sample["instrumentation"], sort_keys=True))
    print("\nResource scope:", report["resource_scope"])
    for note in report.get("limitations", []):
        print("Note:", note)


def main_guard(function):
    def interrupted(signum, frame):
        raise KeyboardInterrupt
    old_term = signal.signal(signal.SIGTERM, interrupted)
    try:
        function()
    except (BenchError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130
    finally:
        signal.signal(signal.SIGTERM, old_term)
    return 0
