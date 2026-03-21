"""
거래소 패킷 탐지용 간단 스니퍼
- 30초간 캡처
- 모든 포트 트래픽 수집
- opcode별 통계 + 큰 패킷(거래소 후보) 덤프
"""
import time
import sys
from collections import defaultdict
from scapy.all import sniff, TCP, IP, Raw

CAPTURE_DURATION = 30  # seconds
packets_data = []
start_time = None

def read_varint(data, offset=0):
    """Protobuf VarInt 디코딩"""
    result = 0
    shift = 0
    while offset < len(data):
        b = data[offset]
        result |= (b & 0x7F) << shift
        offset += 1
        if not (b & 0x80):
            return result, offset
        shift += 7
    return result, offset

def packet_callback(pkt):
    global start_time
    if start_time is None:
        start_time = time.time()

    if not pkt.haslayer(TCP) or not pkt.haslayer(Raw):
        return

    ip = pkt[IP]
    tcp = pkt[TCP]
    payload = bytes(pkt[Raw].load)

    if not payload:
        return

    elapsed = time.time() - start_time

    # 포트 태그
    if tcp.sport == 38600 or tcp.dport == 38600:
        tag = "LOCAL"
    elif tcp.sport == 13328 or tcp.dport == 13328:
        tag = "GAME"
    elif tcp.sport == 443 or tcp.dport == 443:
        tag = "TLS"
    else:
        tag = f"OTHER:{tcp.sport}/{tcp.dport}"

    direction = "S2C" if tcp.sport in (13328, 443, 38600) else "C2S"

    packets_data.append({
        'time': elapsed,
        'tag': tag,
        'direction': direction,
        'src': f"{ip.src}:{tcp.sport}",
        'dst': f"{ip.dst}:{tcp.dport}",
        'payload': payload,
        'size': len(payload),
    })

    count = len(packets_data)
    if count % 50 == 0:
        print(f"  ... {count} packets captured ({elapsed:.1f}s)", flush=True)

def analyze():
    print(f"\n{'='*60}")
    print(f"캡처 완료: 총 {len(packets_data)} 패킷")
    print(f"{'='*60}")

    # 포트별 통계
    port_stats = defaultdict(lambda: {'count': 0, 'bytes': 0, 'sizes': []})
    for p in packets_data:
        key = f"{p['tag']} {p['direction']}"
        port_stats[key]['count'] += 1
        port_stats[key]['bytes'] += p['size']
        port_stats[key]['sizes'].append(p['size'])

    print(f"\n[포트별 통계]")
    for key, stats in sorted(port_stats.items(), key=lambda x: -x[1]['bytes']):
        sizes = stats['sizes']
        avg = sum(sizes) / len(sizes)
        print(f"  {key:20s}: {stats['count']:5d} pkts, {stats['bytes']:8d} bytes, avg={avg:.0f}B, max={max(sizes)}B")

    # GAME 포트 (13328) 패킷 분석 - opcode 추출
    print(f"\n[GAME 포트 opcode 분석 (S2C)]")
    opcode_stats = defaultdict(lambda: {'count': 0, 'sizes': [], 'first_time': 999})

    for p in packets_data:
        if p['tag'] != 'GAME' or p['direction'] != 'S2C':
            continue
        payload = p['payload']
        if len(payload) < 3:
            continue

        # 매직 바이트 건너뛰기
        offset = 0
        while offset < len(payload):
            if payload[offset:offset+3] == b'\x06\x00\x36':
                offset += 3
                continue

            # VarInt length 읽기
            if offset >= len(payload):
                break
            try:
                frame_len, new_offset = read_varint(payload, offset)
                if frame_len <= 0 or frame_len > 10000:
                    break
                frame_start = new_offset
                frame_end = frame_start + frame_len
                if frame_end > len(payload):
                    # 프레임이 불완전 - 전체를 하나의 청크로
                    break

                frame_body = payload[frame_start:frame_end]
                if len(frame_body) >= 2:
                    opcode = int.from_bytes(frame_body[:2], 'little')
                    opcode_hex = f"0x{opcode:04X}"
                    body_len = len(frame_body) - 2
                    opcode_stats[opcode_hex]['count'] += 1
                    opcode_stats[opcode_hex]['sizes'].append(body_len)
                    opcode_stats[opcode_hex]['first_time'] = min(
                        opcode_stats[opcode_hex]['first_time'], p['time']
                    )

                offset = frame_end
            except:
                break

    print(f"  {'Opcode':10s} {'Count':6s} {'AvgBody':8s} {'MaxBody':8s} {'FirstSeen':10s}")
    print(f"  {'-'*48}")
    for op, stats in sorted(opcode_stats.items(), key=lambda x: -x[1]['count']):
        sizes = stats['sizes']
        avg = sum(sizes) / len(sizes)
        print(f"  {op:10s} {stats['count']:6d} {avg:8.0f}B {max(sizes):8d}B {stats['first_time']:10.1f}s")

    # 큰 패킷 (거래소 후보) 상세 덤프
    print(f"\n[큰 패킷 (>200B) - 거래소 후보]")
    big_packets = [p for p in packets_data if p['size'] > 200 and p['tag'] == 'GAME']
    if not big_packets:
        big_packets = [p for p in packets_data if p['size'] > 200]

    if not big_packets:
        print("  200B 이상 패킷 없음!")
        # 100B 이상으로 기준 낮춤
        big_packets = [p for p in packets_data if p['size'] > 100]
        if big_packets:
            print(f"  (100B 이상으로 기준 낮춤: {len(big_packets)}개)")

    for p in big_packets[:20]:
        payload = p['payload']
        hex_head = payload[:48].hex(' ')
        print(f"  [{p['time']:6.1f}s] {p['tag']:6s} {p['direction']} size={p['size']:5d} | {hex_head}")

    # TLS 트래픽 유무
    tls_count = sum(1 for p in packets_data if p['tag'] == 'TLS')
    local_count = sum(1 for p in packets_data if p['tag'] == 'LOCAL')
    print(f"\n[기타]")
    print(f"  TLS(443) 패킷: {tls_count}")
    print(f"  LOCAL(38600) 패킷: {local_count}")

def main():
    print(f"{'='*60}")
    print(f"거래소 패킷 탐지 스니퍼 시작 ({CAPTURE_DURATION}초간 캡처)")
    print(f">>> 지금 거래소를 열고 검색해보세요! <<<")
    print(f"{'='*60}", flush=True)

    bpf = (
        "tcp and ("
        "port 38600 or port 37300"
        " or net 206.127.156.0/24"
        " or net 216.107.0.0/16"
        ")"
    )

    try:
        sniff(
            filter=bpf,
            prn=packet_callback,
            store=False,
            timeout=CAPTURE_DURATION,
        )
    except KeyboardInterrupt:
        pass

    analyze()

if __name__ == "__main__":
    main()
