#!/usr/bin/env python3
import argparse
import collections
import ipaddress
import os
import struct
from dataclasses import dataclass, field


PCAPNG_SHB = 0x0A0D0D0A
PCAPNG_IDB = 0x00000001
PCAPNG_EPB = 0x00000006
PCAPNG_SPB = 0x00000003


@dataclass
class Interface:
    linktype: int
    snaplen: int
    tsresol: float = 1_000_000.0


@dataclass
class UdpFlow:
    packets: int = 0
    bytes: int = 0
    payload_bytes: int = 0
    first_ts: float | None = None
    last_ts: float | None = None
    src_ports: collections.Counter = field(default_factory=collections.Counter)
    src_ips: collections.Counter = field(default_factory=collections.Counter)
    payload_lengths: collections.Counter = field(default_factory=collections.Counter)
    ts_hits: int = 0
    rtp_ts_hits: int = 0


def ip4(n: int) -> str:
    return ".".join(str((n >> shift) & 0xFF) for shift in (24, 16, 8, 0))


def mac_is_multicast(addr: bytes) -> bool:
    return len(addr) >= 6 and bool(addr[0] & 1)


def is_ipv4_multicast(addr: str) -> bool:
    return ipaddress.ip_address(addr).is_multicast


def parse_options(data: bytes, endian: str) -> dict[int, list[bytes]]:
    out: dict[int, list[bytes]] = collections.defaultdict(list)
    pos = 0
    while pos + 4 <= len(data):
        code, length = struct.unpack_from(endian + "HH", data, pos)
        pos += 4
        if code == 0:
            break
        value = data[pos:pos + length]
        out[code].append(value)
        pos += (length + 3) & ~3
    return out


def option_tsresol(value: bytes) -> float:
    if not value:
        return 1_000_000.0
    raw = value[0]
    if raw & 0x80:
        return float(2 ** (raw & 0x7F))
    return float(10 ** raw)


def iter_pcapng_packets(path: str):
    with open(path, "rb") as f:
        data = f.read()

    pos = 0
    endian = "<"
    interfaces: list[Interface] = []
    block_counts = collections.Counter()
    while pos + 12 <= len(data):
        block_type = struct.unpack_from(endian + "I", data, pos)[0]
        total_length = struct.unpack_from(endian + "I", data, pos + 4)[0]
        if total_length < 12 or pos + total_length > len(data):
            break

        body = data[pos + 8:pos + total_length - 4]
        block_counts[block_type] += 1

        if block_type == PCAPNG_SHB:
            magic_le = struct.unpack_from("<I", body, 0)[0] if len(body) >= 4 else None
            magic_be = struct.unpack_from(">I", body, 0)[0] if len(body) >= 4 else None
            if magic_le == 0x1A2B3C4D:
                endian = "<"
            elif magic_be == 0x1A2B3C4D:
                endian = ">"
            interfaces = []
        elif block_type == PCAPNG_IDB and len(body) >= 8:
            linktype, _reserved, snaplen = struct.unpack_from(endian + "HHI", body, 0)
            opts = parse_options(body[8:], endian)
            tsresol = option_tsresol(opts.get(9, [b""])[0])
            interfaces.append(Interface(linktype=linktype, snaplen=snaplen, tsresol=tsresol))
        elif block_type == PCAPNG_EPB and len(body) >= 20:
            iface_id, ts_hi, ts_lo, cap_len, _orig_len = struct.unpack_from(endian + "IIIII", body, 0)
            if iface_id < len(interfaces) and 20 + cap_len <= len(body):
                iface = interfaces[iface_id]
                ts = ((ts_hi << 32) | ts_lo) / iface.tsresol
                pkt = body[20:20 + cap_len]
                yield iface.linktype, ts, pkt, block_counts
        elif block_type == PCAPNG_SPB and len(body) >= 4:
            orig_len = struct.unpack_from(endian + "I", body, 0)[0]
            pkt = body[4:4 + min(orig_len, len(body) - 4)]
            linktype = interfaces[0].linktype if interfaces else 1
            yield linktype, None, pkt, block_counts

        pos += total_length


def packet_network_offset(linktype: int, pkt: bytes):
    if linktype == 1:  # Ethernet
        if len(pkt) < 14:
            return None, None
        ethertype = struct.unpack_from("!H", pkt, 12)[0]
        offset = 14
        while ethertype in (0x8100, 0x88A8, 0x9100) and len(pkt) >= offset + 4:
            ethertype = struct.unpack_from("!H", pkt, offset + 2)[0]
            offset += 4
        return ethertype, offset
    if linktype == 101:  # Raw IP
        return 0x0800, 0
    if linktype == 113:  # Linux cooked capture v1
        if len(pkt) < 16:
            return None, None
        ethertype = struct.unpack_from("!H", pkt, 14)[0]
        return ethertype, 16
    if linktype == 276:  # Linux cooked capture v2
        if len(pkt) < 20:
            return None, None
        ethertype = struct.unpack_from("!H", pkt, 0)[0]
        return ethertype, 20
    return None, None


def looks_like_mpeg_ts(payload: bytes) -> bool:
    if len(payload) < 188:
        return False
    return any(
        start + 188 * 2 < len(payload)
        and payload[start] == 0x47
        and payload[start + 188] == 0x47
        and payload[start + 376] == 0x47
        for start in range(0, min(8, len(payload)))
    )


def looks_like_rtp_mpeg_ts(payload: bytes) -> bool:
    if len(payload) < 12:
        return False
    version = payload[0] >> 6
    cc = payload[0] & 0x0F
    extension = bool(payload[0] & 0x10)
    if version != 2:
        return False
    offset = 12 + cc * 4
    if len(payload) < offset:
        return False
    if extension:
        if len(payload) < offset + 4:
            return False
        ext_len = struct.unpack_from("!H", payload, offset + 2)[0] * 4
        offset += 4 + ext_len
    return looks_like_mpeg_ts(payload[offset:])


def parse_ipv4(pkt: bytes, offset: int):
    if len(pkt) < offset + 20:
        return None
    ver_ihl = pkt[offset]
    if ver_ihl >> 4 != 4:
        return None
    ihl = (ver_ihl & 0x0F) * 4
    if ihl < 20 or len(pkt) < offset + ihl:
        return None
    total_len = struct.unpack_from("!H", pkt, offset + 2)[0]
    proto = pkt[offset + 9]
    src = ".".join(map(str, pkt[offset + 12:offset + 16]))
    dst = ".".join(map(str, pkt[offset + 16:offset + 20]))
    payload_start = offset + ihl
    payload_end = min(len(pkt), offset + total_len) if total_len else len(pkt)
    return proto, src, dst, pkt[payload_start:payload_end]


def parse_igmp_groups(payload: bytes):
    groups = []
    if len(payload) < 8:
        return groups
    igmp_type = payload[0]
    if igmp_type in (0x12, 0x16, 0x17) and len(payload) >= 8:
        group = ".".join(map(str, payload[4:8]))
        if group != "0.0.0.0":
            groups.append(group)
    elif igmp_type == 0x22 and len(payload) >= 8:
        num_records = struct.unpack_from("!H", payload, 6)[0]
        pos = 8
        for _ in range(num_records):
            if len(payload) < pos + 8:
                break
            aux_len = payload[pos + 1] * 4
            num_sources = struct.unpack_from("!H", payload, pos + 2)[0]
            group = ".".join(map(str, payload[pos + 4:pos + 8]))
            if group != "0.0.0.0":
                groups.append(group)
            pos += 8 + num_sources * 4 + aux_len
    return groups


def analyze(path: str):
    flows: dict[tuple[str, int], UdpFlow] = collections.defaultdict(UdpFlow)
    igmp_groups = collections.Counter()
    linktypes = collections.Counter()
    packets = 0

    for linktype, ts, pkt, _block_counts in iter_pcapng_packets(path):
        packets += 1
        linktypes[linktype] += 1
        ethertype, offset = packet_network_offset(linktype, pkt)
        if ethertype != 0x0800 or offset is None:
            continue
        parsed = parse_ipv4(pkt, offset)
        if not parsed:
            continue
        proto, src, dst, ip_payload = parsed
        if proto == 17 and len(ip_payload) >= 8 and is_ipv4_multicast(dst):
            src_port, dst_port, udp_len = struct.unpack_from("!HHH", ip_payload, 0)
            payload = ip_payload[8:min(len(ip_payload), udp_len)]
            flow = flows[(dst, dst_port)]
            flow.packets += 1
            flow.bytes += len(ip_payload)
            flow.payload_bytes += len(payload)
            flow.first_ts = ts if flow.first_ts is None else min(flow.first_ts, ts or flow.first_ts)
            flow.last_ts = ts if flow.last_ts is None else max(flow.last_ts, ts or flow.last_ts)
            flow.src_ports[src_port] += 1
            flow.src_ips[src] += 1
            flow.payload_lengths[len(payload)] += 1
            if looks_like_mpeg_ts(payload):
                flow.ts_hits += 1
            if looks_like_rtp_mpeg_ts(payload):
                flow.rtp_ts_hits += 1
        elif proto == 2:
            for group in parse_igmp_groups(ip_payload):
                if is_ipv4_multicast(group):
                    igmp_groups[group] += 1

    return packets, linktypes, flows, igmp_groups


def duration(flow: UdpFlow) -> float:
    if flow.first_ts is None or flow.last_ts is None:
        return 0.0
    return max(0.0, flow.last_ts - flow.first_ts)


def flow_score(flow: UdpFlow) -> tuple[int, int, int]:
    return (flow.ts_hits + flow.rtp_ts_hits, flow.payload_bytes, flow.packets)


def is_probable_iptv(flow: UdpFlow, dst: str, port: int) -> bool:
    # Exclude common service discovery/control multicast.
    if dst.startswith("224.0.0."):
        return False
    if dst == "239.255.255.250" or port in (1900, 5353, 5355, 137, 138):
        return False
    if flow.ts_hits or flow.rtp_ts_hits:
        return True
    if flow.packets >= 20 and flow.payload_bytes >= 100_000:
        return True
    return False


def write_m3u(path: str, flows: dict[tuple[str, int], UdpFlow]):
    candidates = [
        (dst, port, flow)
        for (dst, port), flow in flows.items()
        if is_probable_iptv(flow, dst, port)
    ]
    candidates.sort(key=lambda item: tuple(reversed(flow_score(item[2]))), reverse=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write("#EXTM3U\n")
        for index, (dst, port, flow) in enumerate(candidates, start=1):
            src = flow.src_ips.most_common(1)[0][0] if flow.src_ips else ""
            hits = flow.ts_hits + flow.rtp_ts_hits
            name = f"IPTV {index:02d} {dst}:{port}"
            f.write(f'#EXTINF:-1 tvg-name="{name}" group-title="IPTV",{name}\n')
            f.write(f"#EXTVLCOPT:network-caching=1000\n")
            if src:
                f.write(f"# source={src} packets={flow.packets} bytes={flow.payload_bytes} ts_hits={hits}\n")
            f.write(f"udp://@{dst}:{port}\n")
    return candidates


def main():
    parser = argparse.ArgumentParser(description="Extract IPTV multicast UDP candidates from a pcapng file.")
    parser.add_argument("capture")
    parser.add_argument("--out", default="iptv_0610.m3u")
    args = parser.parse_args()

    packets, linktypes, flows, igmp_groups = analyze(args.capture)
    candidates = write_m3u(args.out, flows)

    print(f"capture={args.capture}")
    print(f"packets={packets}")
    print("linktypes=" + ", ".join(f"{k}:{v}" for k, v in linktypes.most_common()))
    print(f"udp_multicast_flows={len(flows)}")
    print(f"igmp_groups={len(igmp_groups)}")
    if igmp_groups:
        print("\nIGMP groups:")
        for group, count in igmp_groups.most_common(50):
            print(f"  {group:<15} reports={count}")
    print(f"\nProbable IPTV candidates written to {os.path.abspath(args.out)}: {len(candidates)}")
    for index, (dst, port, flow) in enumerate(candidates, start=1):
        dur = duration(flow)
        bitrate = (flow.payload_bytes * 8 / dur / 1_000_000) if dur > 0 else 0
        src = flow.src_ips.most_common(1)[0][0] if flow.src_ips else "-"
        common_len = flow.payload_lengths.most_common(1)[0][0] if flow.payload_lengths else 0
        print(
            f"{index:02d}. udp://@{dst}:{port} "
            f"src={src} packets={flow.packets} payload={flow.payload_bytes} "
            f"duration={dur:.1f}s bitrate={bitrate:.2f}Mbps "
            f"payload_len~{common_len} ts_hits={flow.ts_hits} rtp_ts_hits={flow.rtp_ts_hits}"
        )

    other = [
        (dst, port, flow)
        for (dst, port), flow in flows.items()
        if not is_probable_iptv(flow, dst, port)
    ]
    other.sort(key=lambda item: item[2].payload_bytes, reverse=True)
    if other:
        print("\nOther multicast UDP flows:")
        for dst, port, flow in other[:30]:
            print(f"  udp://@{dst}:{port:<5} packets={flow.packets:<6} payload={flow.payload_bytes}")


if __name__ == "__main__":
    main()
