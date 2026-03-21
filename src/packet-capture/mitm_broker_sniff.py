"""
Aion2 MITM 거래소 패킷 스니퍼
- mitmproxy를 WireGuard/transparent 모드로 실행
- 게임 서버 트래픽만 필터링
- 복호화된 데이터를 분석
"""
import sys
import logging
from collections import defaultdict
from mitmproxy import ctx, tcp, connection
from mitmproxy.net.server_spec import ServerSpec

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("broker-sniff")

GAME_SUBNETS = ["216.107.", "206.127.156."]
packet_log = []
opcode_stats = defaultdict(lambda: {'count': 0, 'sizes': [], 'samples': []})


def read_varint(data, offset=0):
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


def is_game_traffic(address):
    for subnet in GAME_SUBNETS:
        if subnet in str(address):
            return True
    return False


class BrokerSniffAddon:
    def __init__(self):
        self.count = 0
        self.tcp_count = 0

    def request(self, flow):
        host = flow.request.host
        if not is_game_traffic(host):
            return
        self.count += 1
        body = flow.request.get_content()
        logger.info(
            f"[C2S HTTP] #{self.count} {flow.request.method} {flow.request.url} "
            f"body={len(body)}B | {body[:32].hex(' ') if body else 'empty'}"
        )

    def response(self, flow):
        host = flow.request.host
        if not is_game_traffic(host):
            return
        self.count += 1
        body = flow.response.get_content()
        logger.info(
            f"[S2C HTTP] #{self.count} {flow.response.status_code} {flow.request.url} "
            f"body={len(body)}B"
        )
        if body and len(body) > 0:
            head = body[:64].hex(' ')
            logger.info(f"  [{head}]")
            self._analyze_frame(body, "S2C")

    def tcp_message(self, flow: tcp.TCPFlow):
        msg = flow.messages[-1]
        server_addr = str(flow.server_conn.address) if flow.server_conn else ""
        if not is_game_traffic(server_addr):
            return

        self.tcp_count += 1
        direction = "S2C" if not msg.from_client else "C2S"
        data = msg.content
        if not data:
            return

        head = data[:64].hex(' ')
        logger.info(
            f"[{direction} TCP] #{self.tcp_count} {len(data)}B [{head}]"
        )
        self._analyze_frame(data, direction)

    def _analyze_frame(self, data, direction):
        """프레임 파싱 시도"""
        if direction != "S2C" or len(data) < 3:
            return

        offset = 0
        frames_found = 0
        while offset < len(data):
            # 매직 바이트 스킵
            if data[offset:offset+3] == b'\x06\x00\x36':
                offset += 3
                continue

            try:
                frame_len, new_offset = read_varint(data, offset)
                if frame_len <= 0 or frame_len > 100000:
                    break
                frame_start = new_offset
                frame_end = frame_start + frame_len
                if frame_end > len(data):
                    break

                frame_body = data[frame_start:frame_end]
                if len(frame_body) >= 2:
                    opcode = int.from_bytes(frame_body[:2], 'little')
                    opcode_hex = f"0x{opcode:04X}"
                    body_size = len(frame_body) - 2
                    opcode_stats[opcode_hex]['count'] += 1
                    opcode_stats[opcode_hex]['sizes'].append(body_size)
                    if len(opcode_stats[opcode_hex]['samples']) < 3:
                        opcode_stats[opcode_hex]['samples'].append(frame_body[:64].hex(' '))
                    frames_found += 1

                offset = frame_end
            except:
                break

        if frames_found > 0:
            logger.info(f"  -> {frames_found} frames parsed")

    def done(self):
        """종료 시 통계 출력"""
        logger.info(f"\n{'='*60}")
        logger.info(f"총 HTTP: {self.count}, TCP: {self.tcp_count}")
        logger.info(f"{'='*60}")
        if opcode_stats:
            logger.info(f"\n[Opcode 통계]")
            for op, stats in sorted(opcode_stats.items(), key=lambda x: -x[1]['count']):
                sizes = stats['sizes']
                avg = sum(sizes) / len(sizes) if sizes else 0
                mx = max(sizes) if sizes else 0
                logger.info(f"  {op}: count={stats['count']}, avg={avg:.0f}B, max={mx}B")
                for s in stats['samples'][:2]:
                    logger.info(f"    sample: [{s}]")


addons = [BrokerSniffAddon()]
