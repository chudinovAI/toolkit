#!/usr/bin/env python3
"""Rank sampled cache-line contention without claiming to prove false sharing."""

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tempfile

MAX_REPORT = 64 * 1024 * 1024
CAVEATS = [
    "HITM samples indicate cache-line sharing, not proof of false sharing.",
    "Sample counts depend on workload, duration, events and sampling settings.",
    "Unresolved symbols and omitted report rows limit attribution.",
]


class ReportError(ValueError):
    pass


def bounded_int(value):
    result = int(value)
    if not 1 <= result <= 10000:
        raise argparse.ArgumentTypeError("must be between 1 and 10000")
    return result


def read_text(path):
    with Path(path).open("rb") as stream:
        content = stream.read(MAX_REPORT + 1)
    if len(content) > MAX_REPORT:
        raise ReportError("report exceeds the 64 MiB analysis limit")
    return content.decode("utf-8", errors="replace")


def columns(lines, start, end, required):
    """Use perf's dotted column ruler, retaining multi-line group headings."""
    for position in range(start, end):
        ruler = lines[position]
        spans = list(re.finditer(r"\.{2,}", ruler))
        if len(spans) < 3 or position == 0:
            continue
        header = lines[position - 1]
        labels = (required,) if isinstance(required, str) else required
        if not any(re.search(r"\b" + re.escape(label) + r"\b", header) for label in labels):
            continue
        groups = lines[position - 2] if position >= 2 else ""
        group_spans = list(re.finditer(r"-{2,}\s*([^-]+?)\s*-{2,}", groups))
        result = []
        for span in spans:
            center = (span.start() + span.end()) / 2
            group = next((match.group(1).strip() for match in group_spans
                          if match.start() <= center <= match.end()), "")
            result.append((span.start(), span.end(), header[span.start():span.end()].strip(), group))
        return position + 1, result
    raise ReportError("unrecognized perf c2c table header; export a full --stdio report")


def cells(line, layout):
    return [line[start:end].strip() for start, end, _, _ in layout]


def field(layout, names, group=None):
    for index, (_, _, name, heading) in enumerate(layout):
        if name.lower() in names and (group is None or group in heading.lower()):
            return index
    return None


def integer(value, label):
    try:
        number = int(value.replace(",", ""))
    except ValueError as exc:
        raise ReportError(f"invalid {label} value in perf report: {value!r}") from exc
    if number < 0:
        raise ReportError(f"negative {label} value in perf report")
    return number


def parse_report(text):
    lines = text.splitlines()
    # Some published perf reports are exported through nl(1).
    if sum(bool(re.match(r"^\s*\d+\t", line)) for line in lines[:30]) > 5:
        lines = [re.sub(r"^\s*\d+\t", "", line) for line in lines]
    try:
        shared = next(i for i, line in enumerate(lines) if "Shared Data Cache Line Table" in line)
    except StopIteration as exc:
        raise ReportError("not a complete perf c2c --stdio report: shared cache-line table missing") from exc
    pareto = next((i for i in range(shared + 1, len(lines))
                   if "Shared Cache Line Distribution Pareto" in lines[i]), len(lines))
    stats = {}
    for line in lines[:shared]:
        match = re.match(r"\s*([^:#]+?)\s*:\s*([\d,]+)\s*$", line)
        if match:
            stats[match.group(1).strip()] = integer(match.group(2), "statistic")
    row_start, layout = columns(lines, shared, pareto, "Index")
    address_column = field(layout, {"address", "cacheline"})
    local_column = field(layout, {"lclhitm"})
    remote_column = field(layout, {"rmthitm"})
    if local_column is None:
        local_column = field(layout, {"lcl", "local"}, "hitm")
    if remote_column is None:
        remote_column = field(layout, {"rmt", "remote"}, "hitm")
    total_column = field(layout, {"total"}, "hitm")
    if address_column is None or local_column is None or remote_column is None:
        raise ReportError("HITM columns not recognized (peer-only reports are not supported)")
    record_column = field(layout, {"records"})
    cachelines = []
    by_address = {}
    for line in lines[row_start:pareto]:
        if not line.strip() or line.lstrip().startswith(("#", "=", "-")):
            continue
        if not re.match(r"\s*\d+\s+0x[0-9a-fA-F]+\s", line):
            continue
        values = cells(line, layout)
        address = values[address_column]
        if not re.fullmatch(r"0x[0-9a-fA-F]+", address):
            raise ReportError("cache-line address exceeds the recognized report column")
        address = hex(int(address, 16))
        local = integer(values[local_column], "local HITM")
        remote = integer(values[remote_column], "remote HITM")
        total = local + remote
        if total_column is not None and integer(values[total_column], "total HITM") != total:
            raise ReportError("inconsistent local/remote/total HITM counts")
        if address in by_address:
            raise ReportError(f"duplicate cache-line address in summary: {address}")
        row = {"address": address, "local_hitm": local, "remote_hitm": remote,
               "total_hitm": total, "records": integer(values[record_column], "records")
               if record_column is not None else None, "accesses": []}
        cachelines.append(row)
        by_address[address] = row
    if not cachelines and re.search(r"\b0x[0-9a-fA-F]+\b", "\n".join(lines[row_start:pareto])):
        raise ReportError("cache-line rows exist but their format is not recognized")
    warnings = list(CAVEATS)
    if pareto < len(lines):
        detail_start, detail_layout = columns(lines, pareto, len(lines), ("Offset", "Off"))
        offset_col = field(detail_layout, {"offset", "off"})
        pid_col = field(detail_layout, {"pid"})
        tid_col = field(detail_layout, {"tid"})
        symbol_col = field(detail_layout, {"symbol"})
        object_col = field(detail_layout, {"object", "shared object", "dso"})
        source_col = field(detail_layout, {"source:line"})
        current = None
        unparsed = 0
        for line in lines[detail_start:]:
            if not line.strip() or line.lstrip().startswith(("#", "=", "-")):
                continue
            summary = re.match(r"\s*\d+\s+(?:[\d,]+\s+){2,}(0x[0-9a-fA-F]+)\s*$", line)
            if summary:
                current = by_address.get(hex(int(summary.group(1), 16)))
                continue
            if "%" not in line or current is None:
                continue
            values = cells(line, detail_layout)
            if offset_col is None or not re.fullmatch(r"0x[0-9a-fA-F]+", values[offset_col]):
                unparsed += 1
                continue
            access = {"offset": int(values[offset_col], 16), "pid": None, "tid": None,
                      "symbol": values[symbol_col] if symbol_col is not None else None,
                      "object": values[object_col] if object_col is not None else None,
                      "source": values[source_col] if source_col is not None else None}
            for name, index in (("pid", pid_col), ("tid", tid_col)):
                if index is not None:
                    identifier = re.fullmatch(r"(\d+)(?::.*)?", values[index])
                    if identifier:
                        access[name] = int(identifier.group(1))
            # Preserve full-width symbols even in old reports with overflowing columns.
            tail = re.search(r"(?:0x[0-9a-fA-F]+)\s+[\d.]+\s+[\d.]+\s+[\d.]+\s+\d+\s+(\[[.k?]\].*)$", line)
            if tail:
                parts = re.split(r"\s{2,}", tail.group(1).strip(), maxsplit=3)
                access["symbol"] = parts[0]
                if len(parts) > 1:
                    access["object"] = parts[1]
                if len(parts) > 2:
                    access["source"] = parts[2]
            current["accesses"].append(access)
        if unparsed:
            warnings.append(f"Could not attribute {unparsed} offset rows; aggregate HITM counts remain available.")
    else:
        warnings.append("Offset/thread distribution is absent from this report.")
    global_local = stats.get("Load Local HITM")
    global_remote = stats.get("Load Remote HITM")
    global_hitm = global_local + global_remote if global_local is not None and global_remote is not None else None
    load_samples = stats.get("Load Operations")
    listed_hitm = sum(row["total_hitm"] for row in cachelines)
    if global_hitm is not None and listed_hitm > global_hitm:
        raise ReportError("listed HITM counts exceed global HITM samples")
    for row in cachelines:
        row["percent_of_all_hitm"] = 100 * row["total_hitm"] / global_hitm if global_hitm else None
        row["offsets"] = sorted({item["offset"] for item in row["accesses"]})
        row["tids"] = sorted({item["tid"] for item in row["accesses"] if item["tid"] is not None})
        row["pids"] = sorted({item["pid"] for item in row["accesses"] if item["pid"] is not None})
    return {"statistics": stats, "summary": {"load_samples": load_samples,
            "total_hitm": global_hitm, "listed_hitm": listed_hitm,
            "listed_cachelines": len(cachelines),
            "hitm_per_1000_load_samples": global_hitm * 1000 / load_samples
            if global_hitm is not None and load_samples else None},
            "cachelines": sorted(cachelines, key=lambda row: (-row["total_hitm"], row["address"])),
            "warnings": warnings}


def perf_binary():
    if sys.platform != "linux":
        raise ReportError("perf recording and binary input require Linux; --text analysis is portable")
    binary = shutil.which("perf")
    if not binary:
        raise ReportError("perf is not installed; install a kernel-compatible perf or use an exported --text report")
    return binary


def load_report(path, text_mode):
    if text_mode:
        result = parse_report(read_text(path))
    else:
        if not Path(path).is_file():
            raise ReportError(f"input is not a file: {path}")
        command = [perf_binary(), "c2c", "report", "--stdio", "--show-all", "--full-symbols",
                   "-c", "pid,tid,iaddr", "-i", str(path)]
        environment = dict(os.environ, LC_ALL="C", PERF_PAGER="cat")
        with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
            completed = subprocess.run(command, stdout=output, stderr=errors, env=environment, timeout=120)
            if completed.returncode:
                errors.seek(0)
                detail = errors.read(8192).decode(errors="replace").strip()
                raise ReportError(f"perf c2c report failed ({completed.returncode}): {detail}")
            output.seek(0)
            content = output.read(MAX_REPORT + 1)
            if len(content) > MAX_REPORT:
                raise ReportError("perf report exceeds the 64 MiB analysis limit")
            result = parse_report(content.decode(errors="replace"))
    result["input"] = str(path)
    return result


def record(args):
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        raise ReportError("record requires a workload after --")
    output = Path(args.output).expanduser().absolute()
    if output.exists():
        raise ReportError(f"refusing to overwrite existing recording: {output}")
    perf = perf_binary()
    # perf can rename an existing output to .old. Keep all its writes private,
    # then publish with link(2), which atomically refuses an existing target.
    with tempfile.TemporaryDirectory(prefix=".cacheline-scout-", dir=output.parent) as directory:
        temporary = Path(directory) / "perf.data"
        invocation = [perf, "c2c", "record", "--", "-o", str(temporary), "--", *command]
        child = subprocess.Popen(invocation, stdout=sys.stderr, stderr=sys.stderr, start_new_session=True)
        try:
            code = child.wait()
        except KeyboardInterrupt:
            try:
                os.killpg(child.pid, signal.SIGINT)
            except ProcessLookupError:
                pass
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid, signal.SIGKILL)
                child.wait()
            raise
        if code:
            raise ReportError(f"perf c2c record failed ({code}); check memory-event PMU support and perf permissions; no settings were changed")
        if not temporary.is_file() or temporary.stat().st_size == 0:
            raise ReportError("perf completed without a nonempty recording")
        try:
            os.link(temporary, output)
        except FileExistsError as exc:
            raise ReportError(f"refusing to replace a recording created during capture: {output}") from exc
    result = {"output": str(output), "command": command}
    if args.json:
        print(json.dumps(result))
    else:
        print(f"Recorded: {output}")
    return 0


def print_report(result, top):
    summary = result["summary"]
    print(f"Input: {result['input']}")
    print(f"HITM samples: {summary['total_hitm']} | load samples: {summary['load_samples']} | listed lines: {summary['listed_cachelines']}")
    for row in result["cachelines"][:top]:
        share = f"{row['percent_of_all_hitm']:.2f}%" if row["percent_of_all_hitm"] is not None else "unknown share"
        print(f"  {row['address']}  HITM={row['total_hitm']} local={row['local_hitm']} remote={row['remote_hitm']} ({share})")
        print(f"    offsets={','.join(hex(offset) for offset in row['offsets']) or 'unavailable'} tids={row['tids'] or 'unavailable'}")
        seen = set()
        for access in row["accesses"]:
            site = (access["symbol"], access["object"], access["source"])
            if site not in seen:
                print(f"    {access['symbol'] or '?'} | {access['object'] or '?'} | {access['source'] or '?'}")
                seen.add(site)
    for warning in result["warnings"]:
        print(f"Note: {warning}")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, epilog="Record requires supported memory-event PMUs and perf permission. No sysctl changes or automatic sudo. HITM is evidence of sharing, not proof of false sharing.")
    commands = parser.add_subparsers(dest="action", required=True)
    capture = commands.add_parser("record", help="Record memory events for a workload using perf c2c")
    capture.add_argument("-o", "--output", default="perf.data")
    capture.add_argument("--json", action="store_true")
    capture.add_argument("command", nargs=argparse.REMAINDER, help="Workload after --")
    report = commands.add_parser("report", help="Rank lines and attribute sampled accesses")
    source = report.add_mutually_exclusive_group(required=True)
    source.add_argument("--input", help="perf.data recording")
    source.add_argument("--text", help="Exported perf c2c report --stdio --show-all --full-symbols")
    report.add_argument("--top", type=bounded_int, default=10)
    report.add_argument("--json", action="store_true")
    compare = commands.add_parser("compare", help="Compare sampled HITM rates; not a workload speedup measurement")
    compare.add_argument("--before", required=True)
    compare.add_argument("--after", required=True)
    compare.add_argument("--text", action="store_true", help="Both inputs are exported text reports")
    compare.add_argument("--top", type=bounded_int, default=10)
    compare.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.action == "record":
            return record(args)
        if args.action == "report":
            result = load_report(args.text or args.input, bool(args.text))
            if args.json:
                result["cachelines"] = result["cachelines"][:args.top]
                print(json.dumps(result))
            else:
                print_report(result, args.top)
        else:
            before = load_report(args.before, args.text)
            after = load_report(args.after, args.text)
            left = before["summary"]["hitm_per_1000_load_samples"]
            right = after["summary"]["hitm_per_1000_load_samples"]
            result = {"before": before, "after": after,
                      "hitm_per_1000_load_samples_delta": right - left if left is not None and right is not None else None,
                      "warnings": ["Addresses are not joined across runs because ASLR and allocation can change them.",
                                   "Only compare equivalent workload and sampling settings; this is not a speedup measurement."]}
            if args.json:
                before["cachelines"] = before["cachelines"][:args.top]
                after["cachelines"] = after["cachelines"][:args.top]
                print(json.dumps(result))
            else:
                print_report(before, args.top)
                print_report(after, args.top)
                print(f"HITM / 1000 load samples delta: {result['hitm_per_1000_load_samples_delta']}")
                for warning in result["warnings"]:
                    print(f"Note: {warning}")
        return 0
    except (OSError, ReportError, subprocess.SubprocessError) as exc:
        print(f"cacheline-scout: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("cacheline-scout: interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
