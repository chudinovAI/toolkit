#!/usr/bin/env python3
"""Compare observable process context without entering namespaces."""
import argparse
import errno
import json
import os
import re
import stat
import sys
from pathlib import Path


NAMESPACES = ('net', 'mnt', 'user', 'pid', 'uts', 'ipc', 'cgroup', 'time')
STATUS_FIELDS = ('Uid', 'Gid', 'CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb', 'Cpus_allowed_list')
SECRET_NAME = re.compile(r'(?i)(pass(word|wd)?|secret|token|credential|api.?key|access.?key|private.?key|(?:^|_)key(?:_|$)|auth|cookie|session|bearer)')
SECRET_VALUE = re.compile(r'(?i)(?:[a-z][a-z0-9+.-]*://[^/\s@]*@|\b(?:password|passwd|secret|token|credential|api[_-]?key|private[_-]?key|authorization|cookie|bearer)\b)')


def ok(value):
    return {'status': 'ok', 'value': value}


def failure(exc):
    if isinstance(exc, PermissionError):
        return {'status': 'denied'}
    if isinstance(exc, FileNotFoundError):
        return {'status': 'unavailable'}
    return {'status': 'error', 'detail': str(exc)}


def read_bytes(path, max_bytes=1048576):
    try:
        with open(path, 'rb') as handle:
            data = handle.read(max_bytes + 1)
        if len(data) > max_bytes:
            return {'status': 'error', 'detail': 'file exceeds safe read limit'}
        return ok(data)
    except OSError as exc:
        return failure(exc)


def parse_status(text):
    result = {}
    for line in text.splitlines():
        name, sep, value = line.partition(':')
        if sep and name in STATUS_FIELDS:
            result[name] = value.strip()
    return result


def parse_limits(text):
    result = {}
    for line in text.splitlines()[1:]:
        # /proc/PID/limits uses a 25-column name followed by fixed-width
        # values. Some limits have no units, so splitting from the right fails.
        name, values = line[:25].strip(), line[25:].split()
        if not name or len(values) not in (2, 3):
            raise ValueError('malformed /proc limits row')
        result[name] = {'soft': values[0], 'hard': values[1], 'units': values[2] if len(values) == 3 else None}
    return result


def parse_cgroups(text):
    result = []
    for line in text.splitlines():
        fields = line.split(':', 2)
        if len(fields) != 3 or not fields[0].isdigit() or not fields[2].startswith('/'):
            raise ValueError('malformed /proc cgroup row')
        result.append({'hierarchy': int(fields[0]), 'controllers': sorted(filter(None, fields[1].split(','))), 'path': fields[2]})
    return sorted(result, key=lambda item: (item['hierarchy'], item['controllers'], item['path']))


def parse_resolv(text):
    # Only resolver configuration directives are relevant; comments and unknown
    # directives may contain arbitrary data and are deliberately not reported.
    result = []
    for line in text.splitlines():
        line = line.split('#', 1)[0].split(';', 1)[0].strip()
        fields = line.split()
        if fields and fields[0] in ('nameserver', 'domain', 'search', 'options', 'sortlist'):
            values = []
            for field in fields[1:]:
                values.append('[REDACTED]' if SECRET_NAME.search(field) or SECRET_VALUE.search(field) else field)
            result.append({'directive': fields[0], 'values': values})
    return result


def resolver_bytes(pid):
    """Follow resolv.conf symlinks within the target root, never the observer root.

    Traverse using directory fds and O_NOFOLLOW to avoid escaping that root via
    symlink swaps. Only the final regular resolver file is read, with a size cap.
    """
    fds = []
    try:
        root = os.open(f'/proc/{pid}/root', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        fds.append(root)
        pending = ['etc', 'resolv.conf']
        links = 0
        while pending:
            part = pending.pop(0)
            if part in ('', '.'):
                continue
            if part == '..':
                if len(fds) > 1:
                    os.close(fds.pop())
                continue
            parent = fds[-1]
            try:
                target = os.readlink(part, dir_fd=parent)
            except OSError as exc:
                if exc.errno != errno.EINVAL:  # Not a symlink.
                    raise
            else:
                links += 1
                if links > 40:
                    raise ValueError('too many resolver symlinks')
                if target.startswith('/'):
                    while len(fds) > 1:
                        os.close(fds.pop())
                pending = target.split('/') + pending
                continue
            flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
            if pending:
                fd = os.open(part, flags | os.O_DIRECTORY, dir_fd=parent)
                fds.append(fd)
            else:
                fd = os.open(part, flags, dir_fd=parent)
                fds.append(fd)
                if not stat.S_ISREG(os.fstat(fd).st_mode):
                    raise ValueError('resolver is not a regular file')
                chunks, total = [], 0
                while True:
                    chunk = os.read(fd, min(8192, 65537 - total))
                    if not chunk:
                        return ok(b''.join(chunks))
                    chunks.append(chunk)
                    total += len(chunk)
                    if total > 65536:
                        raise ValueError('resolver exceeds safe read limit')
        raise ValueError('resolver path resolves to a directory')
    except (OSError, ValueError) as exc:
        return failure(exc)
    finally:
        for fd in reversed(fds):
            os.close(fd)


def decoded(value, parser):
    if value['status'] != 'ok':
        return value
    try:
        return ok(parser(value['value'].decode('utf-8', errors='replace')))
    except (ValueError, IndexError) as exc:
        return {'status': 'error', 'detail': str(exc)}


def path_identity(path):
    try:
        link = os.readlink(path)
        info = os.stat(path)
        return ok({'path': link, 'device': info.st_dev, 'inode': info.st_ino})
    except OSError as exc:
        return failure(exc)


def namespace_identity(path):
    try:
        info = os.stat(path)
        return ok({'device': info.st_dev, 'inode': info.st_ino})
    except OSError as exc:
        return failure(exc)


def selected_environment(raw, names):
    if raw['status'] != 'ok':
        return {name: raw for name in names}
    selected = {}
    wanted = set(names)
    for entry in raw['value'].split(b'\0'):
        name, sep, value = entry.partition(b'=')
        if not sep:
            continue
        name = name.decode('utf-8', errors='replace')
        if name not in wanted:
            continue
        value = value.decode('utf-8', errors='replace')
        if SECRET_NAME.search(name) or SECRET_VALUE.search(value):
            selected[name] = {'status': 'redacted'}
        else:
            selected[name] = ok(value)
    for name in names:
        if name not in selected:
            selected[name] = {'status': 'absent'}
    return selected


def collect(pid, env_names):
    base = Path('/proc') / str(pid)
    if not base.exists():
        raise ProcessLookupError(f'process {pid} is gone or inaccessible')
    fields = {}
    for name in NAMESPACES:
        fields['namespace.' + name] = namespace_identity(base / 'ns' / name)
    for name in ('root', 'cwd'):
        fields[name] = path_identity(base / name)
    status = decoded(read_bytes(base / 'status'), parse_status)
    for name in STATUS_FIELDS:
        if status['status'] == 'ok':
            fields['status.' + name] = ok(status['value'][name]) if name in status['value'] else {'status': 'unavailable'}
        else:
            fields['status.' + name] = status
    fields['cgroup.memberships'] = decoded(read_bytes(base / 'cgroup'), parse_cgroups)
    fields['resolver'] = decoded(resolver_bytes(pid), parse_resolv)
    if fields['resolver']['status'] == 'ok' and any(
            '[REDACTED]' in row['values'] for row in fields['resolver']['value']):
        fields['resolver']['status'] = 'redacted'
    limits = decoded(read_bytes(base / 'limits'), parse_limits)
    if limits['status'] == 'ok':
        for name, value in limits['value'].items():
            fields['limit.' + name] = ok(value)
    else:
        fields['limits'] = limits
    if env_names:
        env = selected_environment(read_bytes(base / 'environ'), env_names)
        for name, value in env.items():
            fields['env.' + name] = value
    if not base.exists():
        raise ProcessLookupError(f'process {pid} disappeared during collection')
    return fields


def compare(left, right):
    rows = []
    for field in sorted(left.keys() | right.keys()):
        a = left.get(field, {'status': 'unavailable'})
        b = right.get(field, {'status': 'unavailable'})
        if a['status'] not in ('ok', 'absent') or b['status'] not in ('ok', 'absent'):
            result = 'unknown'
        elif a == b:
            result = 'equal'
        else:
            result = 'different'
        rows.append({'field': field, 'result': result, 'target': a, 'against': b})
    return rows


def positive_pid(value):
    try:
        pid = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError('must be an integer PID') from exc
    if pid <= 0:
        raise argparse.ArgumentTypeError('must be a positive PID')
    return pid


def env_name(value):
    if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', value):
        raise argparse.ArgumentTypeError('must be an environment variable name')
    return value


def main(argv=None):
    parser = argparse.ArgumentParser(description='Compare visible process namespace and execution context evidence without entering namespaces. Unavailable data is unknown, not equal; differences do not prove causation.')
    parser.add_argument('--pid', required=True, type=positive_pid)
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--against-pid', type=positive_pid, help='comparison process (default: this tool)')
    group.add_argument('--against-self', action='store_true', help='compare against this tool process')
    parser.add_argument('--env', type=env_name, action='append', default=[], metavar='NAME', help='compare only this named environment variable; secret names and credentials are redacted (repeatable)')
    parser.add_argument('--json', action='store_true', help='emit one JSON document')
    args = parser.parse_args(argv)
    if not sys.platform.startswith('linux'):
        print('ns-diff: Linux is required', file=sys.stderr)
        return 1
    against = args.against_pid or os.getpid()
    try:
        left = collect(args.pid, args.env)
        right = collect(against, args.env)
        rows = compare(left, right)
        report = {'pid': args.pid, 'against_pid': against, 'comparisons': rows,
                  'interpretation': 'These are observable context differences, not proof of causation. Unknown or redacted fields cannot be compared. Snapshots are not atomic.'}
        if args.json:
            print(json.dumps(report))
        else:
            print(f'PID {args.pid} compared with PID {against}:')
            for row in rows:
                if row['result'] != 'equal':
                    print(f"  {row['field']}: {row['result']}\n    target: {json.dumps(row['target'], sort_keys=True)}\n    against: {json.dumps(row['against'], sort_keys=True)}")
            print(f"Equal fields: {sum(row['result'] == 'equal' for row in rows)}")
            print(report['interpretation'])
        return 0
    except (OSError, ValueError) as exc:
        print(f'ns-diff: {exc}', file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == '__main__':
    sys.exit(main())
