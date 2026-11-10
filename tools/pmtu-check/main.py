#!/usr/bin/env python3
"""Bounded IPv4 UDP path-MTU observations with a temporary cooperating peer."""
import argparse
import errno
import hashlib
import hmac
import json
import math
import secrets
import select
import socket
import struct
import sys
import time

MAGIC = b'PMT1'
HEADER = struct.Struct('!4sB16sIII')
EXT_ERR = struct.Struct('=IBBBBII')
IP_MTU_DISCOVER = getattr(socket, 'IP_MTU_DISCOVER', 10)
IP_PMTUDISC_DO = getattr(socket, 'IP_PMTUDISC_DO', 2)
IP_RECVERR = getattr(socket, 'IP_RECVERR', 11)
MSG_ERRQUEUE = getattr(socket, 'MSG_ERRQUEUE', 0x2000)
OVERHEAD = 28
MIN_SIZE = OVERHEAD + HEADER.size
MAX_SIZE = 65535
HELLO, CHALLENGE, CONFIRM, READY, UP, UP_ACK, DOWN_REQUEST, DOWN, DOWN_ACK, ERROR = range(1, 11)
SESSION_LIFETIME = 300.0
MAX_SESSIONS = 32
MAX_RESPONSES = 512
COOKIE_EPOCH = 15
MAX_UNATTRIBUTED = 1024


def challenge_cookie(secret, peer, epoch):
    message = socket.inet_aton(peer[0]) + struct.pack('!HQ', peer[1], epoch)
    return hmac.new(secret, message, hashlib.sha256).digest()[:16]


def valid_cookie(secret, peer, token, now):
    epoch = int(now // COOKIE_EPOCH)
    return any(secrets.compare_digest(token, challenge_cookie(secret, peer, candidate))
               for candidate in (epoch, epoch - 1) if candidate >= 0)


def packet(kind, token, seq=0, size=0, aux=0, payload_size=None):
    header = HEADER.pack(MAGIC, kind, token, seq, size, aux)
    if payload_size is None:
        return header
    if not HEADER.size <= payload_size <= MAX_SIZE - OVERHEAD:
        raise ValueError('invalid datagram payload size')
    return header + bytes(payload_size - HEADER.size)


def decode(data):
    if len(data) < HEADER.size:
        return None
    magic, kind, token, seq, size, aux = HEADER.unpack_from(data)
    if magic != MAGIC or kind not in range(HELLO, ERROR + 1):
        return None
    return kind, token, seq, size, aux


def parse_extended_error(data):
    """Decode Linux sock_extended_err without assuming an offender address."""
    if len(data) < EXT_ERR.size:
        return None
    number, origin, icmp_type, code, _pad, info, extra = EXT_ERR.unpack_from(data)
    if number == errno.EMSGSIZE:
        category = 'fragmentation_needed' if origin == 2 and icmp_type == 3 and code == 4 else 'message_too_large'
    elif number in (errno.ENETUNREACH, errno.EHOSTUNREACH, errno.ECONNREFUSED, errno.EACCES):
        category = 'unreachable'
    else:
        category = 'network_error'
    return {'errno': number, 'origin': {1: 'local', 2: 'icmp', 3: 'icmp6'}.get(origin, str(origin)),
            'icmp_type': icmp_type, 'icmp_code': code, 'mtu': info if number == errno.EMSGSIZE and info else None,
            'category': category, 'data': extra}


def socket_error(number, mtu=None):
    return {'errno': number, 'origin': 'send', 'icmp_type': None, 'icmp_code': None,
            'mtu': mtu or None, 'category': ('message_too_large' if number == errno.EMSGSIZE else
            'unreachable' if number in (errno.ENETUNREACH, errno.EHOSTUNREACH, errno.ECONNREFUSED, errno.EACCES) else 'network_error'), 'data': 0}


def drain_errors(sock):
    results = []
    while True:
        try:
            data, ancillary, _flags, address = sock.recvmsg(65535, 512, MSG_ERRQUEUE | socket.MSG_DONTWAIT)
        except BlockingIOError:
            break
        except OSError as exc:
            if exc.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                break
            raise
        for level, kind, value in ancillary:
            if level == socket.IPPROTO_IP and kind == IP_RECVERR:
                error = parse_extended_error(value)
                if error is not None:
                    results.append((decode(data), error, address))
    return results


def record_unattributed(evidence, error, reason, original=None, peer=None):
    if len(evidence) >= MAX_UNATTRIBUTED:
        return
    entry = {'reason': reason, 'error': error}
    if original is not None:
        entry['quoted_kind'] = original[0]
        entry['quoted_sequence'] = original[2]
    if peer:
        entry['destination'] = {'ipv4': peer[0], 'port': peer[1]}
    evidence.append(entry)


def partition_error_events(events, expected, evidence):
    """Only attribute a queue event when its complete quoted header matches."""
    matched = []
    for original, error, peer in events:
        if original is not None and expected is not None and original == expected:
            matched.append(error)
        else:
            record_unattributed(evidence, error, 'unmatched_or_truncated_quote', original, peer)
    return matched


def mark_ambiguous_timeouts(results, evidence):
    if any(item['error']['category'] in ('message_too_large', 'fragmentation_needed') for item in evidence):
        for rows in results.values():
            for row in rows:
                row['inconclusive'] += row['timeouts']
                row['timeouts'] = 0
        return True
    return False


def open_socket():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.IPPROTO_IP, IP_MTU_DISCOVER, IP_PMTUDISC_DO)
        sock.setsockopt(socket.IPPROTO_IP, IP_RECVERR, 1)
        sock.setblocking(False)
        return sock
    except Exception:
        sock.close()
        raise


def evidence_summary(observations):
    successful = [r['packet_size'] for r in observations if r['received']]
    highest = max(successful) if successful else None
    blackhole = any(highest is not None and r['packet_size'] > highest and
                    r['timeouts'] > 0 and r['timeouts'] == r.get('attempts', r['timeouts']) and
                    not r['received'] and not r['errors']
                    for r in observations)
    return {'largest_confirmed_packet_size': highest,
            'largest_confirmed_payload_size': highest - OVERHEAD if highest is not None else None,
            'possible_black_hole': blackhole}


def sizes_between(low, high, count):
    if low == high:
        return [low]
    return sorted({low + (high - low) * n // (count - 1) for n in range(count)})


def error_for_wire(err):
    # Compact error report: origin, ICMP type and code are sent in the upper bits.
    origin = {'send': 0, 'local': 1, 'icmp': 2, 'icmp6': 3}.get(err['origin'], 0)
    packed = (origin << 24) | ((err['icmp_type'] or 0) << 16) | ((err['icmp_code'] or 0) << 8)
    return packed | min(err['errno'], 255)


def error_from_wire(value, mtu):
    number = value & 255
    origin = (value >> 24) & 255
    icmp_type = (value >> 16) & 255
    code = (value >> 8) & 255
    if origin:
        return parse_extended_error(EXT_ERR.pack(number, origin, icmp_type, code, 0, mtu, 0))
    return socket_error(number, mtu)


class Bucket:
    def __init__(self, rate, capacity):
        self.rate = rate
        self.capacity = capacity
        self.tokens = capacity
        self.updated = time.monotonic()

    def take(self):
        now = time.monotonic()
        self.tokens = min(self.capacity, self.tokens + (now - self.updated) * self.rate)
        self.updated = now
        if self.tokens < 1:
            return False
        self.tokens -= 1
        return True


def listen(args):
    sessions = {}
    cookie_secret = secrets.token_bytes(32)
    unattributed = []
    stats = {'authenticated_sessions': 0, 'up_received': 0, 'down_sent': 0,
             'down_acknowledged': 0, 'send_errors': 0}
    global_bucket = Bucket(100, 100)
    with open_socket() as sock:
        sock.bind((args.bind, args.port))
        address = sock.getsockname()
        print('Listening on %s:%d for %.1f seconds (IPv4)' % (*address, args.duration), file=sys.stderr, flush=True)
        deadline = time.monotonic() + args.duration

        def send(data, peer, session=None):
            if not global_bucket.take() or (session is not None and not session['bucket'].take()):
                return None
            try:
                sock.sendto(data, peer)
                return True
            except OSError as exc:
                stats['send_errors'] += 1
                record_unattributed(unattributed, socket_error(exc.errno or errno.EIO),
                                    'listener_send_exception', peer=peer)
                return False

        def notify_errors():
            for original, error, peer in drain_errors(sock):
                session = sessions.get(peer)
                if original is not None:
                    kind, token, seq, size, aux = original
                    if (session and kind == DOWN and secrets.compare_digest(token, session['token'])
                            and session['outstanding'].get(seq) == size and aux == 0):
                        send(packet(ERROR, token, seq, error_for_wire(error), error['mtu'] or 0), peer, session)
                        continue
                record_unattributed(unattributed, error, 'unmatched_or_truncated_quote', original, peer)
                if (session and session['unattributed_notifications'] < 8
                        and (original is None or secrets.compare_digest(original[1], session['token']))):
                    session['unattributed_notifications'] += 1
                    send(packet(ERROR, session['token'], 0, error_for_wire(error), error['mtu'] or 0), peer, session)

        while time.monotonic() < deadline:
            now = time.monotonic()
            for peer in list(sessions):
                if now - sessions[peer]['created'] > SESSION_LIFETIME:
                    del sessions[peer]
            readable, _, exceptional = select.select([sock], [], [sock], min(0.2, max(0, deadline - now)))
            if readable or exceptional:
                notify_errors()
            if not readable:
                continue
            try:
                data, peer = sock.recvfrom(65535)
            except BlockingIOError:
                continue
            except OSError:
                notify_errors()
                continue
            decoded = decode(data)
            if decoded is None:
                continue
            kind, token, seq, size, aux = decoded
            session = sessions.get(peer)
            if kind == HELLO:
                if len(data) != HEADER.size:
                    continue
                cookie = (session['token'] if session else
                          challenge_cookie(cookie_secret, peer, int(now // COOKIE_EPOCH)))
                send(packet(CHALLENGE, cookie, seq), peer, session)
                continue
            if kind == CONFIRM and len(data) == HEADER.size:
                if session is None:
                    if len(sessions) >= MAX_SESSIONS or not valid_cookie(cookie_secret, peer, token, now):
                        continue
                    session = {'token': token, 'created': now, 'bucket': Bucket(40, 40),
                               'responses': 0, 'outstanding': {}, 'unattributed_notifications': 0}
                    sessions[peer] = session
                    stats['authenticated_sessions'] += 1
                if secrets.compare_digest(token, session['token']):
                    send(packet(READY, token, seq), peer, session)
                continue
            if session is None or not secrets.compare_digest(token, session['token']):
                continue
            if kind == UP and MIN_SIZE <= size <= MAX_SIZE and len(data) + OVERHEAD == size:
                stats['up_received'] += 1
                send(packet(UP_ACK, token, seq, size), peer, session)
            elif kind == DOWN_REQUEST and len(data) == HEADER.size and MIN_SIZE <= size <= MAX_SIZE:
                if session['responses'] >= MAX_RESPONSES or seq in session['outstanding']:
                    continue
                session['responses'] += 1
                session['outstanding'][seq] = size
                result = send(packet(DOWN, token, seq, size, payload_size=size - OVERHEAD), peer, session)
                if result is True:
                    stats['down_sent'] += 1
                elif result is False:
                    notify_errors()
            elif kind == DOWN_ACK and len(data) == HEADER.size and session['outstanding'].get(seq) == size:
                del session['outstanding'][seq]
                stats['down_acknowledged'] += 1
        notify_errors()
    return {'mode': 'listen', 'bind': address[0], 'port': address[1], 'duration_seconds': args.duration,
            'unattributed_errors': unattributed, 'unattributed_errors_may_be_truncated': len(unattributed) >= MAX_UNATTRIBUTED,
            **stats}


def exchange(sock, outgoing, expected_kind, token, seq, timeout, unattributed, expected_size=None):
    errors = []
    inconclusive = False
    expected_quote = decode(outgoing)
    previous = drain_errors(sock)
    partition_error_events(previous, None, unattributed)
    if previous:
        inconclusive = True
    try:
        sock.send(outgoing)
    except OSError as exc:
        # The error may refer to an older datagram, even for EMSGSIZE.
        record_unattributed(unattributed, socket_error(exc.errno or errno.EIO), 'send_exception')
        errors.extend(partition_error_events(drain_errors(sock), expected_quote, unattributed))
        return None, errors, True
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        readable, _, exceptional = select.select([sock], [], [sock], max(0, deadline - time.monotonic()))
        if readable or exceptional:
            events = drain_errors(sock)
            matched = partition_error_events(events, expected_quote, unattributed)
            errors.extend(matched)
            if len(events) != len(matched):
                inconclusive = True
        if not readable:
            continue
        try:
            data = sock.recv(65535)
        except BlockingIOError:
            continue
        except OSError as exc:
            record_unattributed(unattributed, socket_error(exc.errno or errno.EIO), 'receive_exception')
            inconclusive = True
            continue
        decoded = decode(data)
        if decoded is None:
            continue
        kind, received_token, received_seq, size, aux = decoded
        if token is not None and not secrets.compare_digest(token, received_token):
            continue
        if kind == ERROR and token is not None and len(data) == HEADER.size:
            if received_seq == seq and expected_kind == DOWN:
                errors.append(error_from_wire(size, aux))
            else:
                record_unattributed(unattributed, error_from_wire(size, aux), 'unmatched_peer_error')
                inconclusive = True
            continue
        if received_seq != seq or kind != expected_kind:
            continue
        if expected_size is not None:
            if size != expected_size or (kind == DOWN and len(data) + OVERHEAD != size):
                continue
            if kind == UP_ACK and len(data) != HEADER.size:
                continue
        elif len(data) != HEADER.size:
            continue
        return decoded, errors, inconclusive
    return None, errors, inconclusive


def probe(args):
    candidates = socket.getaddrinfo(args.host, args.port, socket.AF_INET, socket.SOCK_DGRAM)
    if not candidates:
        raise ValueError('no IPv4 address found')
    peer = candidates[0][4]
    unattributed = []
    handshake_errors = []
    with open_socket() as sock:
        sock.connect(peer)
        token = secrets.token_bytes(16)
        challenge = None
        for _ in range(args.attempts):
            challenge, errors, _ = exchange(sock, packet(HELLO, token, 0), CHALLENGE, None, 0, args.timeout, unattributed)
            handshake_errors.extend(errors)
            if challenge:
                break
        if not challenge:
            raise ValueError('peer handshake failed; error evidence: %s' % json.dumps(handshake_errors + unattributed))
        token = challenge[1]
        ready = None
        for _ in range(args.attempts):
            ready, errors, _ = exchange(sock, packet(CONFIRM, token, 0), READY, token, 0, args.timeout, unattributed)
            handshake_errors.extend(errors)
            if ready:
                break
        if not ready:
            raise ValueError('peer did not confirm the reachability handshake; error evidence: %s' % json.dumps(handshake_errors + unattributed))
        results = {'client_to_peer': [], 'peer_to_client': []}
        seq = 0
        for size in sizes_between(args.min_size, args.max_size, args.samples):
            for direction in results:
                row = {'packet_size': size, 'payload_size': size - OVERHEAD,
                       'attempts': args.attempts, 'received': 0, 'timeouts': 0, 'inconclusive': 0, 'errors': []}
                for _ in range(args.attempts):
                    seq += 1
                    if direction == 'client_to_peer':
                        outgoing = packet(UP, token, seq, size, payload_size=size - OVERHEAD)
                        expected = UP_ACK
                    else:
                        outgoing = packet(DOWN_REQUEST, token, seq, size)
                        expected = DOWN
                    response, errors, inconclusive = exchange(sock, outgoing, expected, token, seq, args.timeout, unattributed, size)
                    row['errors'].extend(errors)
                    if response:
                        row['received'] += 1
                        if direction == 'peer_to_client':
                            try:
                                sock.send(packet(DOWN_ACK, token, seq, size))
                            except OSError as exc:
                                record_unattributed(unattributed, socket_error(exc.errno or errno.EIO), 'ack_send_exception')
                    elif not errors:
                        if inconclusive:
                            row['inconclusive'] += 1
                        else:
                            row['timeouts'] += 1
                    time.sleep(0.03)
                results[direction].append(row)
        partition_error_events(drain_errors(sock), None, unattributed)
    ambiguous_mtu = mark_ambiguous_timeouts(results, unattributed)
    summaries = {direction: evidence_summary(rows) for direction, rows in results.items()}
    a = summaries['client_to_peer']['largest_confirmed_packet_size']
    b = summaries['peer_to_client']['largest_confirmed_packet_size']
    return {'mode': 'probe', 'peer': {'ipv4': peer[0], 'port': peer[1]},
            'ipv4_udp_overhead_bytes': OVERHEAD, 'observations': results, 'summary': summaries,
            'handshake_errors': handshake_errors, 'unattributed_errors': unattributed,
            'unattributed_errors_may_be_truncated': len(unattributed) >= MAX_UNATTRIBUTED,
            'timeouts_inconclusive_due_to_unattributed_mtu': ambiguous_mtu,
            'observed_asymmetry': None if a is None or b is None else a != b,
            'interpretation': 'Sampled confirmations are lower bounds, not exact PMTUs. Timeouts may reflect loss, filtering, rate limits, or a PMTU black hole. Unattributed MTU evidence makes all otherwise timed-out attempts inconclusive. Different confirmed maxima do not prove a path-MTU difference.'}


def bounded_int(low, high):
    def parse(value):
        try:
            number = int(value)
        except ValueError:
            raise argparse.ArgumentTypeError('must be an integer')
        if not low <= number <= high:
            raise argparse.ArgumentTypeError('must be between %d and %d' % (low, high))
        return number
    return parse


def bounded_float(low, high):
    def parse(value):
        try:
            number = float(value)
        except ValueError:
            raise argparse.ArgumentTypeError('must be a number')
        if not math.isfinite(number) or not low <= number <= high:
            raise argparse.ArgumentTypeError('must be between %s and %s' % (low, high))
        return number
    return parse


def main(argv=None):
    parser = argparse.ArgumentParser(description='Measure sampled bidirectional IPv4 UDP packet sizes with a temporary cooperating peer. IPv6 is not supported; packet sizes include the 28-byte IPv4/UDP header without IP options.')
    parser.add_argument('--json', action='store_true', help='emit one JSON result')
    sub = parser.add_subparsers(dest='mode', required=True)
    listener = sub.add_parser('listen', help='run a bounded foreground peer; loopback by default')
    listener.add_argument('--json', action='store_true', default=argparse.SUPPRESS, help='emit one JSON result')
    listener.add_argument('--bind', default='127.0.0.1', help='IPv4 bind address (default: 127.0.0.1; external access requires an explicit address)')
    listener.add_argument('--port', type=bounded_int(1, 65535), default=33445)
    listener.add_argument('--duration', type=bounded_float(0.1, 3600), default=60.0, help='foreground lifetime in seconds (0.1–3600; default: 60)')
    client = sub.add_parser('probe', help='sample sizes in both directions; a peer must already be listening')
    client.add_argument('--json', action='store_true', default=argparse.SUPPRESS, help='emit one JSON result')
    client.add_argument('host', help='peer hostname or IPv4 address (IPv6 unsupported)')
    client.add_argument('--port', type=bounded_int(1, 65535), default=33445)
    client.add_argument('--min-size', type=bounded_int(MIN_SIZE, MAX_SIZE), default=100, help='minimum total IPv4 packet bytes, including 28 bytes of headers (default: 100)')
    client.add_argument('--max-size', type=bounded_int(MIN_SIZE, MAX_SIZE), default=1500, help='maximum total IPv4 packet bytes, including 28 bytes of headers (default: 1500)')
    client.add_argument('--samples', type=bounded_int(2, 16), default=8, help='number of evenly spaced sizes, including endpoints (2–16; default: 8)')
    client.add_argument('--attempts', type=bounded_int(2, 5), default=3, help='attempts per size and direction (2–5; default: 3)')
    client.add_argument('--timeout', type=bounded_float(0.05, 1), default=0.4, help='seconds per attempt (0.05–1; default: 0.4)')
    args = parser.parse_args(argv)
    if not sys.platform.startswith('linux'):
        parser.exit(2, 'pmtu-check: Linux is required (IPv4 error queue and PMTU discovery)\n')
    if args.mode == 'probe' and args.min_size > args.max_size:
        parser.error('--min-size must not exceed --max-size')
    try:
        if args.mode == 'listen':
            # Reject hostnames and IPv6; binding must be an explicitly chosen IPv4 interface.
            socket.inet_pton(socket.AF_INET, args.bind)
            result = listen(args)
        else:
            result = probe(args)
    except KeyboardInterrupt:
        print('pmtu-check: interrupted', file=sys.stderr)
        return 130
    except (OSError, ValueError) as exc:
        print('pmtu-check: %s' % exc, file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(result, sort_keys=True))
    elif args.mode == 'listen':
        print('Peer stopped: %d authenticated sessions, %d packets received, %d reverse packets sent, %d acknowledged, %d send errors.' %
              (result['authenticated_sessions'], result['up_received'], result['down_sent'], result['down_acknowledged'], result['send_errors']))
        if result['unattributed_errors']:
            print('Unattributed error evidence: ' + json.dumps(result['unattributed_errors']))
    else:
        print('Peer %s:%s; packet sizes include %d bytes IPv4/UDP overhead.' % (peer_label(result), result['peer']['port'], OVERHEAD))
        for direction, rows in result['observations'].items():
            print(direction.replace('_', ' ') + ':')
            for row in rows:
                print('  packet %d B, payload %d B: %d/%d received, %d timeouts, %d inconclusive, %d errors%s' %
                      (row['packet_size'], row['payload_size'], row['received'], row['attempts'], row['timeouts'], row['inconclusive'], len(row['errors']),
                       ' ' + json.dumps(row['errors']) if row['errors'] else ''))
            print('  ' + json.dumps(result['summary'][direction]))
        print('Observed asymmetry: %s' % result['observed_asymmetry'])
        if result['handshake_errors'] or result['unattributed_errors']:
            print('Handshake errors: ' + json.dumps(result['handshake_errors']))
            print('Unattributed error evidence: ' + json.dumps(result['unattributed_errors']))
        print(result['interpretation'])
    return 0


def peer_label(result):
    return result['peer']['ipv4']


if __name__ == '__main__':
    sys.exit(main())
