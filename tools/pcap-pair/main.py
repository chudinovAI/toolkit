#!/usr/bin/env python3
"""Compare TCP byte coverage in two offline packet captures."""

import argparse
import ipaddress
import json
import struct
import sys
from dataclasses import dataclass, field

MAX_BLOCK = 64 * 1024 * 1024
MAX_RECORDS = 500_000
MAX_FLOWS = 10_000
HALF = 1 << 31
MASK = (1 << 32) - 1
SUPPORTED_LINKS = {1, 101, 113, 228, 229, 276}


class CaptureError(Exception):
    pass


def require(condition, message):
    if not condition:
        raise CaptureError(message)


def read_exact(stream, size, what):
    data = stream.read(size)
    require(len(data) == size, f"truncated {what}")
    return data


def timestamp_ns(ticks, denominator, offset=0):
    return offset * 1_000_000_000 + ticks * 1_000_000_000 // denominator


def capture_packets(stream):
    """Yield (link type, packet bytes, timestamp in nanoseconds)."""
    magic = read_exact(stream, 4, "capture header")
    classic = {
        b'\xd4\xc3\xb2\xa1': ('<', 1_000_000),
        b'\xa1\xb2\xc3\xd4': ('>', 1_000_000),
        b'\x4d\x3c\xb2\xa1': ('<', 1_000_000_000),
        b'\xa1\xb2\x3c\x4d': ('>', 1_000_000_000),
    }
    if magic in classic:
        endian, resolution = classic[magic]
        major, minor, _, _, snaplen, linkword = struct.unpack(endian + 'HHiIII', read_exact(stream, 20, 'pcap header'))
        require((major, minor) == (2, 4), f'unsupported pcap version {major}.{minor}')
        require(0 < snaplen <= MAX_BLOCK, 'invalid or excessive pcap snaplen')
        link = linkword & 0xffff
        require(link in SUPPORTED_LINKS, f'unsupported link type {link}')
        while True:
            header = stream.read(16)
            if not header:
                return
            require(len(header) == 16, 'truncated pcap packet header')
            sec, fraction, captured, original = struct.unpack(endian + 'IIII', header)
            require(fraction < resolution, 'invalid pcap timestamp fraction')
            require(captured <= snaplen and captured <= MAX_BLOCK and captured <= original, 'invalid pcap packet length')
            require(captured == original, 'truncated packet in capture (snaplen); byte absence cannot be inferred')
            yield link, read_exact(stream, captured, 'pcap packet'), timestamp_ns(sec * resolution + fraction, resolution)
    elif magic == b'\x0a\x0d\x0d\x0a':
        endian = None
        interfaces = []
        first = True
        while True:
            if first:
                block_type = magic
                first = False
            else:
                block_type = stream.read(4)
                if not block_type:
                    return
                require(len(block_type) == 4, 'truncated pcapng block type')
            length_bytes = read_exact(stream, 4, 'pcapng block length')
            if block_type == b'\x0a\x0d\x0d\x0a':
                bom = read_exact(stream, 4, 'pcapng byte-order magic')
                if bom == b'\x4d\x3c\x2b\x1a':
                    endian = '<'
                elif bom == b'\x1a\x2b\x3c\x4d':
                    endian = '>'
                else:
                    raise CaptureError('invalid pcapng byte-order magic')
                length = struct.unpack(endian + 'I', length_bytes)[0]
                require(28 <= length <= MAX_BLOCK and length % 4 == 0, 'invalid pcapng section block length')
                rest = read_exact(stream, length - 12, 'pcapng section block')
                require(struct.unpack(endian + 'I', rest[-4:])[0] == length, 'pcapng block length trailer mismatch')
                major, minor = struct.unpack(endian + 'HH', rest[:4])
                require((major, minor) == (1, 0), f'unsupported pcapng version {major}.{minor}')
                list(parse_options(rest[12:-4], endian))
                interfaces = []
                continue
            require(endian is not None, 'pcapng missing section header')
            length = struct.unpack(endian + 'I', length_bytes)[0]
            require(12 <= length <= MAX_BLOCK and length % 4 == 0, 'invalid pcapng block length')
            rest = read_exact(stream, length - 8, 'pcapng block')
            require(struct.unpack(endian + 'I', rest[-4:])[0] == length, 'pcapng block length trailer mismatch')
            body = rest[:-4]
            kind = struct.unpack(endian + 'I', block_type)[0]
            if kind == 1:
                require(len(body) >= 8, 'short pcapng interface block')
                link, _, snaplen = struct.unpack_from(endian + 'HHI', body)
                require(link in SUPPORTED_LINKS, f'unsupported link type {link}')
                require(snaplen <= MAX_BLOCK, 'excessive pcapng snaplen')
                denominator, offset = 1_000_000, 0
                for code, value in parse_options(body[8:], endian):
                    if code == 9:
                        require(len(value) == 1, 'invalid pcapng if_tsresol option')
                        exponent = value[0] & 0x7f
                        require(exponent <= 63, 'excessive pcapng timestamp resolution')
                        denominator = (2 if value[0] & 0x80 else 10) ** exponent
                    elif code == 14:
                        require(len(value) == 8, 'invalid pcapng if_tsoffset option')
                        offset = struct.unpack(endian + 'q', value)[0]
                interfaces.append((link, snaplen, denominator, offset))
                require(len(interfaces) <= MAX_FLOWS, 'too many pcapng interfaces')
            elif kind == 6:
                require(len(body) >= 20, 'short pcapng enhanced packet block')
                index, hi, lo, captured, original = struct.unpack_from(endian + 'IIIII', body)
                require(index < len(interfaces), 'pcapng packet references unknown interface')
                link, snaplen, denominator, offset = interfaces[index]
                require(captured <= MAX_BLOCK and captured <= original and (snaplen == 0 or captured <= snaplen), 'invalid pcapng packet length')
                padded = (captured + 3) & ~3
                require(20 + padded <= len(body), 'truncated pcapng packet data')
                require(captured == original, 'truncated packet in capture (snaplen); byte absence cannot be inferred')
                list(parse_options(body[20 + padded:], endian))
                yield link, body[20:20 + captured], timestamp_ns((hi << 32) | lo, denominator, offset)
            elif kind in (2, 3):
                raise CaptureError('unsupported pcapng packet block (only enhanced packet blocks are supported)')
    else:
        raise CaptureError('unrecognized capture format (expected classic pcap or pcapng)')


def parse_options(data, endian):
    pos = 0
    while pos < len(data):
        require(len(data) - pos >= 4, 'truncated pcapng option')
        code, size = struct.unpack_from(endian + 'HH', data, pos)
        pos += 4
        require(pos + ((size + 3) & ~3) <= len(data), 'truncated pcapng option value')
        if code == 0:
            require(size == 0 and all(b == 0 for b in data[pos:]), 'invalid pcapng end-of-options')
            return
        yield code, data[pos:pos + size]
        pos += (size + 3) & ~3


def decode_packet(link, data):
    if link == 1:
        require(len(data) >= 14, 'short Ethernet header')
        protocol = struct.unpack_from('!H', data, 12)[0]
        pos = 14
        while protocol in (0x8100, 0x88a8, 0x9100):
            require(len(data) >= pos + 4, 'short VLAN header')
            protocol = struct.unpack_from('!H', data, pos + 2)[0]
            pos += 4
            require(pos <= 14 + 4 * 8, 'too many VLAN tags')
    elif link in (113, 276):
        size, proto_pos = (16, 14) if link == 113 else (20, 0)
        require(len(data) >= size, 'short Linux cooked header')
        protocol = struct.unpack_from('!H', data, proto_pos)[0]
        pos = size
    else:
        require(data, 'empty raw IP packet')
        version = data[0] >> 4
        protocol = 0x0800 if version == 4 else 0x86dd if version == 6 else 0
        require(protocol != 0, 'invalid raw IP version')
        if link == 228:
            require(version == 4, 'raw IPv4 link contains non-IPv4 packet')
        if link == 229:
            require(version == 6, 'raw IPv6 link contains non-IPv6 packet')
        pos = 0
    if protocol == 0x0800:
        require(len(data) >= pos + 20, 'short IPv4 header')
        require(data[pos] >> 4 == 4, 'invalid IPv4 version')
        ihl = (data[pos] & 15) * 4
        total = struct.unpack_from('!H', data, pos + 2)[0]
        require(ihl >= 20 and total >= ihl and len(data) >= pos + total, 'malformed or truncated IPv4 packet')
        frag = struct.unpack_from('!H', data, pos + 6)[0]
        require(not (frag & 0x3fff), 'IPv4 fragments are unsupported; cannot infer byte absence')
        if data[pos + 9] != 6:
            return None
        src = str(ipaddress.IPv4Address(data[pos + 12:pos + 16]))
        dst = str(ipaddress.IPv4Address(data[pos + 16:pos + 20]))
        end = pos + total
        pos += ihl
    elif protocol == 0x86dd:
        require(len(data) >= pos + 40 and data[pos] >> 4 == 6, 'short or invalid IPv6 header')
        size = struct.unpack_from('!H', data, pos + 4)[0]
        require(size != 0, 'IPv6 jumbograms are unsupported')
        end = pos + 40 + size
        require(len(data) >= end, 'truncated IPv6 packet')
        nxt = data[pos + 6]
        src = str(ipaddress.IPv6Address(data[pos + 8:pos + 24]))
        dst = str(ipaddress.IPv6Address(data[pos + 24:pos + 40]))
        pos += 40
        extensions = 0
        while nxt in (0, 43, 44, 51, 60, 135, 139, 140):
            require(nxt != 44, 'IPv6 fragments are unsupported; cannot infer byte absence')
            require(pos + 2 <= end, 'short IPv6 extension header')
            new_nxt = data[pos]
            length = (data[pos + 1] + 2) * 4 if nxt == 51 else (data[pos + 1] + 1) * 8
            require(pos + length <= end, 'truncated IPv6 extension header')
            pos += length
            nxt = new_nxt
            extensions += 1
            require(extensions <= 16, 'too many IPv6 extension headers')
        require(nxt != 50, 'IPv6 ESP is unsupported; encapsulated TCP cannot be inspected')
        if nxt != 6:
            return None
    else:
        return None
    require(pos + 20 <= end, 'short TCP header')
    sport, dport, seq, ack = struct.unpack_from('!HHII', data, pos)
    hlen = (data[pos + 12] >> 4) * 4
    require(hlen >= 20 and pos + hlen <= end, 'invalid TCP header length')
    flags = data[pos + 13]
    return (src, sport), (dst, dport), seq, ack, flags, end - pos - hlen


@dataclass
class Conversation:
    # Direction is relative to the sorted endpoint pair while collecting.
    payload: list = field(default_factory=lambda: [[], []])
    acks: list = field(default_factory=lambda: [[], []])
    syn: list = field(default_factory=lambda: [set(), set()])
    initiators: set = field(default_factory=set)
    packets: int = 0


def load_capture(path, selector):
    flows = {}
    records = 0
    first_ts = last_ts = None
    try:
        with open(path, 'rb') as stream:
            for link, packet, ts in capture_packets(stream):
                records += 1
                require(records <= MAX_RECORDS, 'capture exceeds packet limit')
                first_ts = ts if first_ts is None else min(first_ts, ts)
                last_ts = ts if last_ts is None else max(last_ts, ts)
                segment = decode_packet(link, packet)
                if segment is None:
                    continue
                src, dst, seq, ack, flags, size = segment
                require(src != dst, 'TCP endpoints are identical; direction is ambiguous')
                key = tuple(sorted((src, dst)))
                if selector is not None and key != tuple(sorted(selector)):
                    continue
                if key not in flows:
                    require(len(flows) < MAX_FLOWS, 'capture exceeds TCP conversation limit')
                    flows[key] = Conversation()
                flow = flows[key]
                direction = 0 if src == key[0] else 1
                flow.packets += 1
                if flags & 0x02:
                    flow.syn[direction].add(seq)
                    flow.initiators.add(1 - direction if flags & 0x10 else direction)
                if size:
                    flow.payload[direction].append(((seq + bool(flags & 0x02)) & MASK, size))
                if flags & 0x10:
                    flow.acks[1 - direction].append(ack)
    except OSError as exc:
        raise CaptureError(f'{path}: {exc.strerror or exc}') from exc
    except CaptureError as exc:
        raise CaptureError(f'{path}: {exc}') from exc
    require(flows, f'{path}: no matching TCP conversation')
    require(len(flows) == 1, f'{path}: multiple TCP conversations; select one with --flow or --left-flow/--right-flow')
    key, flow = next(iter(flows.items()))
    for seqs in flow.syn:
        require(len(seqs) <= 1, f'{path}: multiple SYN sequence numbers for one direction; tuple may be reused')
    require(selector is not None or len(flow.initiators) <= 1, f'{path}: conflicting SYN directions; provide an ordered flow selector')
    orientation = key.index(selector[0]) if selector is not None else next(iter(flow.initiators), None)
    return key, flow, orientation, {'packets': records, 'tcp_packets': flow.packets, 'first_timestamp_ns': first_ts, 'last_timestamp_ns': last_ts}


def signed_distance(value, base):
    delta = (value - base) & MASK
    require(delta != HALF, 'TCP sequence distance is exactly 2^31 and cannot be ordered')
    return delta if delta < HALF else delta - (1 << 32)


def merge_intervals(intervals):
    result = []
    for start, end in sorted(intervals):
        if result and start <= result[-1][1]:
            result[-1] = (result[-1][0], max(end, result[-1][1]))
        else:
            result.append((start, end))
    return result


def total_length(intervals):
    return sum(end - start for start, end in intervals)


def intersection_length(left, right):
    i = j = total = 0
    while i < len(left) and j < len(right):
        a, b = left[i]
        c, d = right[j]
        total += max(0, min(b, d) - max(a, c))
        if b < d:
            i += 1
        else:
            j += 1
    return total


def compare_direction(left, li, right, ri):
    syn = left.syn[li] | right.syn[ri]
    require(len(syn) <= 1, 'captures have different SYN sequence numbers; cannot compare this connection')
    sequences = left.payload[li] + right.payload[ri]
    base = (next(iter(syn)) + 1) & MASK if syn else (sequences[0][0] if sequences else None)
    if base is None:
        return {'sequence_base': None, 'both_bytes': 0, 'left_only_bytes': 0, 'right_only_bytes': 0,
                'left_repeated_payload_bytes': 0, 'right_repeated_payload_bytes': 0,
                'left_ack_observations': {'count': len(left.acks[li]), 'max_offset': None, 'observed_payload_bytes_covered': None},
                'right_ack_observations': {'count': len(right.acks[ri]), 'max_offset': None, 'observed_payload_bytes_covered': None}}
    converted = []
    for flow, direction in ((left, li), (right, ri)):
        raw = [(signed_distance(seq, base), size) for seq, size in flow.payload[direction]]
        converted.append(merge_intervals([(start, start + size) for start, size in raw]))
    all_intervals = converted[0] + converted[1]
    if all_intervals:
        first = min(start for start, _ in all_intervals)
        last = max(end for _, end in all_intervals)
        require(last - first < HALF, 'observed TCP sequence span is at least 2^31; wraparound is ambiguous')
        reference = (first + last) // 2
    else:
        first = last = reference = 0
    both = intersection_length(*converted)
    def ack_report(flow, direction, intervals):
        offsets = []
        for value in flow.acks[direction]:
            offset = reference + signed_distance(value, (base + reference) & MASK)
            require(abs(offset - first) < HALF and abs(offset - last) < HALF,
                    'ACK sequence is ambiguous relative to the observed payload span')
            offsets.append(offset)
        maximum = max(offsets) if offsets else None
        covered = sum(max(0, min(end, maximum) - start) for start, end in intervals if start < maximum) if maximum is not None else None
        return {'count': len(offsets), 'max_offset': maximum, 'observed_payload_bytes_covered': covered}
    ltotal, rtotal = map(total_length, converted)
    return {'sequence_base': base, 'both_bytes': both, 'left_only_bytes': ltotal - both, 'right_only_bytes': rtotal - both,
            'left_repeated_payload_bytes': sum(size for _, size in left.payload[li]) - ltotal,
            'right_repeated_payload_bytes': sum(size for _, size in right.payload[ri]) - rtotal,
            'left_ack_observations': ack_report(left, li, converted[0]),
            'right_ack_observations': ack_report(right, ri, converted[1])}


def parse_selector(text):
    parts = text.split(',')
    if len(parts) != 4:
        raise argparse.ArgumentTypeError('flow must be SRC_IP,SRC_PORT,DST_IP,DST_PORT (source is direction A)')
    try:
        a, b = str(ipaddress.ip_address(parts[0])), str(ipaddress.ip_address(parts[2]))
        ap, bp = int(parts[1]), int(parts[3])
        if not (0 <= ap <= 65535 and 0 <= bp <= 65535):
            raise ValueError('port out of range')
        if (a, ap) == (b, bp):
            raise ValueError('endpoints must differ')
        return (a, ap), (b, bp)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f'invalid flow: {exc}') from exc


def endpoint_text(endpoint):
    address, port = endpoint
    return f'[{address}]:{port}' if ':' in address else f'{address}:{port}'


def main(argv=None):
    parser = argparse.ArgumentParser(description='Compare TCP byte intervals in two offline captures; absence is not proof of loss. No clock synchronization or one-way latency is inferred.', epilog='Flow syntax: SRC_IP,SRC_PORT,DST_IP,DST_PORT. Source defines direction A; use separate selectors for NAT. Auto-selection requires one TCP conversation per capture and an unambiguous SYN orientation. Supported: classic pcap and pcapng SHB/IDB/EPB; Ethernet/VLAN, Linux cooked v1/v2, raw IPv4/IPv6. Fragmented, snaplen-truncated and unsupported packet/link formats are errors.')
    parser.add_argument('left', help='left pcap or pcapng file')
    parser.add_argument('right', help='right pcap or pcapng file')
    parser.add_argument('--flow', type=parse_selector, help='same ordered flow selector for both captures')
    parser.add_argument('--left-flow', type=parse_selector, help='ordered selector for the left capture')
    parser.add_argument('--right-flow', type=parse_selector, help='ordered selector for the right capture')
    parser.add_argument('--json', action='store_true', help='emit one JSON report')
    args = parser.parse_args(argv)
    if args.flow and (args.left_flow or args.right_flow):
        parser.error('--flow cannot be combined with --left-flow or --right-flow')
    if bool(args.left_flow) != bool(args.right_flow):
        parser.error('--left-flow and --right-flow must be supplied together')
    try:
        lk, left, lo, lm = load_capture(args.left, args.flow or args.left_flow)
        rk, right, ro, rm = load_capture(args.right, args.flow or args.right_flow)
        if lo is None and ro is not None and lk == rk:
            lo = lk.index(rk[ro])
        if ro is None and lo is not None and lk == rk:
            ro = rk.index(lk[lo])
        require(lo is not None and ro is not None, 'midstream direction is ambiguous; provide --flow or both --left-flow and --right-flow')
        if lk == rk and not (args.flow or args.left_flow):
            require(lk[lo] == rk[ro], 'captures have conflicting SYN orientations')
        directions = []
        for offset in (0, 1):
            li, ri = (lo + offset) % 2, (ro + offset) % 2
            result = compare_direction(left, li, right, ri)
            result.update({'direction': 'A to B' if offset == 0 else 'B to A',
                           'left_source': endpoint_text(lk[li]), 'left_destination': endpoint_text(lk[1-li]),
                           'right_source': endpoint_text(rk[ri]), 'right_destination': endpoint_text(rk[1-ri])})
            directions.append(result)
        report = {'left': lm, 'right': rm, 'directions': directions,
                  'caveats': ['Capture absence is not proof of network loss.', 'Matching bytes means sequence interval coverage, not a comparison of payload contents.', 'Timestamps are capture times, not one-way latency; clocks may be unsynchronized.', 'Sequence comparisons assume the same TCP sequence space and less than 2^31 bytes of observable span; tuple reuse and unseen full sequence wraps cannot always be detected.', 'ACK observations come from the reverse direction; coverage is cumulative and excludes selective ACK interpretation. ACK sequence positions are unwrapped relative to the observed payload span.']}
        if args.json:
            print(json.dumps(report, indent=2))
        else:
            for d in directions:
                print(f"{d['direction']}: {d['left_source']} -> {d['left_destination']} | {d['right_source']} -> {d['right_destination']}")
                print(f"  payload bytes: both={d['both_bytes']} left-only={d['left_only_bytes']} right-only={d['right_only_bytes']}")
                print(f"  repeated payload bytes: left={d['left_repeated_payload_bytes']} right={d['right_repeated_payload_bytes']}")
                for side in ('left', 'right'):
                    a = d[f'{side}_ack_observations']
                    print(f"  {side} cumulative ACKs: count={a['count']} max-offset={a['max_offset']} observed-payload-covered={a['observed_payload_bytes_covered']}")
            for caveat in report['caveats']:
                print(f'Note: {caveat}')
        return 0
    except CaptureError as exc:
        print(f'pcap-pair: {exc}', file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print('pcap-pair: interrupted', file=sys.stderr)
        return 130


if __name__ == '__main__':
    sys.exit(main())
