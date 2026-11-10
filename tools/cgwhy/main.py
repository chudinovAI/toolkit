#!/usr/bin/env python3
"""Read-only cgroup v2 ancestry and pressure observations."""
import argparse
import json
import os
import re
import sys
import time
from pathlib import Path, PurePosixPath


class DiagnosticError(Exception):
    pass


def unescape_mount(value):
    return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), value)


def absolute_parts(value):
    path = PurePosixPath(value)
    if not path.is_absolute() or '..' in path.parts:
        raise DiagnosticError('invalid absolute path in proc data')
    return path.parts[1:]


def parse_membership(text):
    for line in text.splitlines():
        parts = line.split(':', 2)
        if len(parts) == 3 and parts[0] == '0' and parts[1] == '':
            absolute_parts(parts[2])
            return parts[2]
    raise DiagnosticError('unified cgroup v2 membership unavailable (cgroup v1 is unsupported)')


def parse_mounts(text):
    mounts = []
    for line in text.splitlines():
        fields = line.split()
        try:
            sep = fields.index('-')
            if sep < 6 or len(fields) <= sep + 1 or fields[sep + 1] != 'cgroup2':
                continue
            root, point = unescape_mount(fields[3]), unescape_mount(fields[4])
            absolute_parts(root)
            absolute_parts(point)
            mounts.append((root, point))
        except ValueError:
            continue
    return mounts


def candidate_relative_paths(membership, root):
    """Produce both host-root and cgroup-namespace interpretations if plausible."""
    member_parts, root_parts = absolute_parts(membership), absolute_parts(root)
    results = []
    if member_parts[:len(root_parts)] == root_parts:
        results.append(member_parts[len(root_parts):])
    if member_parts not in results:
        results.append(member_parts)
    return results


def resolve_cgroup(pid, membership, mounts):
    candidates = []
    denied = False
    for root, point in mounts:
        base = Path('/proc') / str(pid) / 'root' / Path(point).relative_to('/')
        for relative in candidate_relative_paths(membership, root):
            leaf = base.joinpath(*relative)
            try:
                # cgroup.controllers is present at every v2 cgroup, even if empty.
                with (leaf / 'cgroup.controllers').open('r'):
                    pass
            except PermissionError:
                denied = True
                continue
            except OSError:
                continue
            candidates.append((base, leaf, root, point, relative))
    # Directory existence alone cannot identify a cgroup, including when only
    # one mount interpretation is visible. Confirm membership before reporting.
    matching = []
    for item in candidates:
        for name in ('cgroup.procs', 'cgroup.threads'):
            try:
                with (item[1] / name).open() as members:
                    if any(line.strip() == str(pid) for line in members):
                        matching.append(item)
                        break
            except PermissionError:
                denied = True
            except OSError:
                pass
    candidates = matching
    if not candidates:
        if denied:
            raise DiagnosticError('cannot verify process membership in the cgroup v2 hierarchy: permission denied')
        raise DiagnosticError('no visible cgroup v2 candidate confirms process membership; the process may have moved or its namespace may hide it')
    # Different mount roots imply different visible ancestry, even when the
    # relative membership string happens to match. Never guess between them.
    distinct = {(item[2], item[4]) for item in candidates}
    if len(distinct) > 1:
        raise DiagnosticError('ambiguous cgroup namespace/mount-root mapping; refusing to guess ancestry')
    return candidates[0]


def proc_text(pid, name):
    path = Path('/proc') / str(pid) / name
    try:
        return path.read_text()
    except PermissionError as exc:
        raise DiagnosticError(f'permission denied reading {path}') from exc
    except FileNotFoundError as exc:
        if not (Path('/proc') / str(pid)).exists():
            raise DiagnosticError(f'process {pid} is gone') from exc
        raise DiagnosticError(f'{path} is unavailable') from exc
    except OSError as exc:
        raise DiagnosticError(f'cannot read {path}: {exc.strerror}') from exc


def read_value(path, parser=lambda x: x.strip()):
    try:
        return {'status': 'ok', 'value': parser(path.read_text())}
    except PermissionError:
        return {'status': 'denied'}
    except FileNotFoundError:
        return {'status': 'unavailable'}
    except (OSError, ValueError, IndexError) as exc:
        return {'status': 'error', 'detail': str(exc)}


def parse_counters(text):
    result = {}
    for line in text.splitlines():
        name, value = line.split()
        result[name] = int(value)
    return result


def parse_cpu_max(text):
    quota, period = text.split()
    return {'quota_us': None if quota == 'max' else int(quota), 'period_us': int(period)}


def parse_pressure(text):
    result = {}
    for line in text.splitlines():
        parts = line.split()
        if not parts:
            continue
        values = {}
        for item in parts[1:]:
            key, value = item.split('=', 1)
            values[key] = int(value) if key == 'total' else float(value)
        result[parts[0]] = values
    return result


def delta(before, after):
    if before['status'] != 'ok' or after['status'] != 'ok':
        return {'status': 'unavailable', 'before': before, 'after': after}
    values, reset, missing = {}, [], []
    for key in sorted(before['value'].keys() | after['value'].keys()):
        if key not in before['value'] or key not in after['value']:
            missing.append(key)
        elif after['value'][key] < before['value'][key]:
            reset.append(key)
        else:
            values[key] = after['value'][key] - before['value'][key]
    return {'status': 'partial' if reset or missing else 'ok', 'values': values,
            'counter_reset': reset, 'missing': missing}


def snapshot(levels):
    result = []
    for display, path in levels:
        result.append({'cgroup': display,
            'cpu.max': read_value(path / 'cpu.max', parse_cpu_max),
            'cpu.stat': read_value(path / 'cpu.stat', parse_counters),
            'memory.high': read_value(path / 'memory.high'),
            'memory.max': read_value(path / 'memory.max'),
            'memory.current': read_value(path / 'memory.current'),
            'memory.events': read_value(path / 'memory.events', parse_counters),
            'cpuset.cpus.effective': read_value(path / 'cpuset.cpus.effective'),
            'cpu.pressure': read_value(path / 'cpu.pressure', parse_pressure),
            'memory.pressure': read_value(path / 'memory.pressure', parse_pressure),
            'io.pressure': read_value(path / 'io.pressure', parse_pressure)})
    return result


def observe(pid, seconds, watch):
    membership = parse_membership(proc_text(pid, 'cgroup'))
    mounts = parse_mounts(proc_text(pid, 'mountinfo'))
    if not mounts:
        raise DiagnosticError('no visible cgroup v2 mount in target mount namespace')
    base, leaf, root, point, relative = resolve_cgroup(pid, membership, mounts)
    levels = []
    for count in range(len(relative), -1, -1):
        rel = relative[:count]
        levels.append(('/' + '/'.join(rel), base.joinpath(*rel)))
    before = snapshot(levels)
    started = time.monotonic()
    while True:
        time.sleep(seconds)
        now = time.monotonic()
        # A move invalidates attribution of the interval to the process.
        current_membership = parse_membership(proc_text(pid, 'cgroup'))
        after = snapshot(levels)
        for old, new in zip(before, after):
            new['cpu.stat_delta'] = delta(old['cpu.stat'], new['cpu.stat'])
            new['memory.events_delta'] = delta(old['memory.events'], new['memory.events'])
        report = {'pid': pid, 'membership': membership, 'mount_root': root,
                  'mount_point': point, 'observation_seconds': now - started,
                  'membership_changed': current_membership != membership,
                  'levels_leaf_to_mount_root': after,
                  'interpretation': 'Values describe each whole cgroup subtree, not individual process usage. Quotas, cpusets and ancestor constraints interact; quota alone is not an effective CPU share. Pressure and throttling are evidence, not proof of cause.'}
        yield report
        if not watch:
            return
        if current_membership != membership:
            raise DiagnosticError('process cgroup membership changed; restart observation')
        before, started = after, now


def positive_seconds(value):
    try:
        n = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError('must be a number') from exc
    if not 0 < n <= 3600:
        raise argparse.ArgumentTypeError('must be greater than zero and at most 3600 seconds')
    return n


def positive_pid(value):
    try:
        pid = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError('must be an integer PID') from exc
    if pid <= 0:
        raise argparse.ArgumentTypeError('must be a positive PID')
    return pid


def main(argv=None):
    parser = argparse.ArgumentParser(description='Observe cgroup v2 constraints and pressure at the process cgroup and visible ancestors (read-only).')
    parser.add_argument('--pid', required=True, type=positive_pid)
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--duration', type=positive_seconds, help='single observation window in seconds (default: 1)')
    group.add_argument('--watch', action='store_true', help='emit repeated bounded observations until interrupted')
    parser.add_argument('--interval', type=positive_seconds, help='watch window in seconds, or single window when duration is omitted')
    parser.add_argument('--json', action='store_true', help='JSON document; watch streams an array closed on interruption')
    args = parser.parse_args(argv)
    if args.duration is not None and args.interval is not None:
        parser.error('--duration and --interval cannot be combined')
    if not sys.platform.startswith('linux'):
        print('cgwhy: Linux is required', file=sys.stderr)
        return 1
    array_open = False
    first_report = True
    try:
        for report in observe(args.pid, args.duration or args.interval or 1.0, args.watch):
            if args.json:
                if args.watch:
                    if not array_open:
                        print('[', end='', flush=True)
                        array_open = True
                    print(('' if first_report else ',') + json.dumps(report), end='', flush=True)
                    first_report = False
                else:
                    print(json.dumps(report), flush=True)
            else:
                print(f"PID {report['pid']}, membership {report['membership']}, window {report['observation_seconds']:.3f}s; mount {report['mount_point']} (root {report['mount_root']})")
                if report['membership_changed']:
                    print('WARNING: membership changed during observation; attribution is uncertain')
                for level in report['levels_leaf_to_mount_root']:
                    print(f"\nCgroup {level['cgroup']} (relative to mount root):")
                    for name, value in level.items():
                        if name != 'cgroup':
                            print(f'  {name}: {json.dumps(value, sort_keys=True)}')
                print('\n' + report['interpretation'], flush=True)
        return 0
    except (DiagnosticError, OSError) as exc:
        print(f'cgwhy: {exc}', file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130
    finally:
        if array_open:
            print(']', flush=True)


if __name__ == '__main__':
    sys.exit(main())
