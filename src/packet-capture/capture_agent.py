"""
Aion 2 Packet Capture Agent (Windows)
- Npcap 기반 TCP 패킷 캡처
- 게임 트래픽 자동 감지 (매직 바이트 06 00 36)
- WebSocket으로 서버에 실시간 전송

사용법:
  pip install scapy websockets psutil
  python capture_agent.py --server ws://your-mac-server:8080/capture

외부 네트워크 (ngrok 터널):
  python capture_agent.py --server wss://xxxx.ngrok-free.app/capture
"""

import asyncio
import argparse
import logging
import struct
import time
from collections import defaultdict
from typing import Optional

try:
    from scapy.all import sniff, TCP, IP, Raw, get_if_list, conf
except ImportError:
    print("scapy 설치 필요: pip install scapy")
    raise

try:
    import websockets
except ImportError:
    print("websockets 설치 필요: pip install websockets")
    raise

try:
    import psutil
except ImportError:
    psutil = None

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger("aion2-capture")

MAGIC_BYTES = bytes([0x06, 0x00, 0x36])
GAME_PORT = 13328
GAME_SERVER_SUBNET = "206.127.156."
GAME_PROCESS_NAMES = {"Aion2.exe", "AION2.exe", "aion2.exe"}
TLS_CONTENT_TYPES = {0x14, 0x15, 0x16, 0x17}


class TrafficDetector:
    """게임 트래픽 자동 감지기"""

    def __init__(self):
        self.locked_port: Optional[int] = None
        self.locked_iface: Optional[str] = None
        self.candidates: dict[int, int] = defaultdict(int)  # port -> magic_count
        self.lock_threshold = 3

    def is_tls(self, payload: bytes) -> bool:
        if len(payload) < 5:
            return False
        content_type = payload[0]
        major = payload[1]
        minor = payload[2]
        return (
            content_type in TLS_CONTENT_TYPES
            and major == 0x03
            and minor in range(0x00, 0x05)
        )

    def check_magic(self, payload: bytes) -> bool:
        return MAGIC_BYTES in payload

    def register_candidate(self, port: int, iface: str) -> bool:
        self.candidates[port] += 1
        if self.candidates[port] >= self.lock_threshold:
            self.locked_port = port
            self.locked_iface = iface
            logger.info(f"트래픽 잠금: port={port}, iface={iface}")
            return True
        return False

    def is_locked(self) -> bool:
        return self.locked_port is not None

    def matches(self, src_port: int, dst_port: int) -> bool:
        if not self.is_locked():
            return True  # 잠금 전에는 모든 트래픽 검사
        return src_port == self.locked_port or dst_port == self.locked_port


class PacketBuffer:
    """TCP 스트림 버퍼 — 매직 바이트로 프레임 분리"""

    def __init__(self, max_size: int = 2 * 1024 * 1024):
        self.buffer = bytearray()
        self.max_size = max_size

    def append(self, data: bytes):
        self.buffer.extend(data)
        if len(self.buffer) > self.max_size:
            logger.warning("버퍼 오버플로 — 초기화")
            self.buffer.clear()

    def extract_frames(self) -> list[bytes]:
        frames = []
        data = bytes(self.buffer)
        parts = data.split(MAGIC_BYTES)

        if len(parts) <= 1:
            return frames

        # 마지막 부분은 불완전할 수 있으므로 버퍼에 유지
        for part in parts[:-1]:
            if len(part) > 2:  # 최소 opcode 2바이트
                frames.append(part)

        self.buffer = bytearray(parts[-1])
        return frames


class CaptureAgent:
    """메인 캡처 에이전트"""

    def __init__(self, server_url: str, dump_mode: bool = False):
        self.server_url = server_url
        self.dump_mode = dump_mode
        self.detector = TrafficDetector()
        self.buffers: dict[str, PacketBuffer] = defaultdict(PacketBuffer)
        self.ws: Optional[websockets.WebSocketClientProtocol] = None
        self.packet_queue: asyncio.Queue = asyncio.Queue(maxsize=10000)
        self.stats = {
            "captured": 0,
            "frames": 0,
            "sent": 0,
            "errors": 0,
        }
        self._running = False

    def _is_game_running(self) -> bool:
        if psutil is None:
            return True  # psutil 없으면 항상 실행 중으로 간주
        for proc in psutil.process_iter(["name"]):
            try:
                if proc.info["name"] in GAME_PROCESS_NAMES:
                    return True
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return False

    def _packet_callback(self, pkt):
        """scapy 패킷 콜백"""
        if not pkt.haslayer(TCP) or not pkt.haslayer(Raw):
            return

        ip = pkt[IP]
        tcp = pkt[TCP]
        payload = bytes(pkt[Raw].load)

        if not payload:
            return

        # 방향 확인 (S2C: 서버 → 클라이언트)
        is_s2c = ip.src.startswith(GAME_SERVER_SUBNET) or tcp.sport == GAME_PORT

        if not is_s2c:
            return

        # TLS 필터링
        if self.detector.is_tls(payload):
            return

        # 트래픽 감지
        if not self.detector.is_locked():
            if self.detector.check_magic(payload):
                self.detector.register_candidate(
                    tcp.sport, pkt.sniffed_on or "unknown"
                )
        elif not self.detector.matches(tcp.sport, tcp.dport):
            return

        self.stats["captured"] += 1

        # 버퍼에 추가
        stream_key = f"{ip.src}:{tcp.sport}->{ip.dst}:{tcp.dport}"
        self.buffers[stream_key].append(payload)

        # 프레임 추출
        frames = self.buffers[stream_key].extract_frames()
        for frame in frames:
            self.stats["frames"] += 1
            try:
                self.packet_queue.put_nowait(frame)
            except asyncio.QueueFull:
                self.stats["errors"] += 1

    async def _send_loop(self):
        """프레임을 WebSocket으로 전송"""
        while self._running:
            try:
                if self.ws is None or self.ws.closed:
                    await self._connect()

                frame = await asyncio.wait_for(
                    self.packet_queue.get(), timeout=1.0
                )

                if self.dump_mode:
                    self._dump_frame(frame)
                else:
                    # 타임스탬프 + 프레임 데이터 전송
                    header = struct.pack("<d", time.time())
                    await self.ws.send(header + frame)
                    self.stats["sent"] += 1

            except asyncio.TimeoutError:
                continue
            except websockets.exceptions.ConnectionClosed:
                logger.warning("WebSocket 연결 끊김 — 재접속 시도")
                self.ws = None
                await asyncio.sleep(2)
            except Exception as e:
                logger.error(f"전송 오류: {e}")
                self.stats["errors"] += 1
                await asyncio.sleep(1)

    async def _connect(self):
        """WebSocket 서버에 접속 (ws:// 또는 wss:// 자동 처리)"""
        try:
            extra = {}
            if "ngrok" in self.server_url or "wss://" in self.server_url:
                extra["additional_headers"] = {
                    "ngrok-skip-browser-warning": "true"
                }
            self.ws = await websockets.connect(
                self.server_url,
                max_size=4 * 1024 * 1024,
                **extra,
            )
            logger.info(f"서버 연결 성공: {self.server_url}")
        except Exception as e:
            logger.error(f"서버 연결 실패: {e}")
            await asyncio.sleep(5)

    def _dump_frame(self, frame: bytes):
        """덤프 모드 — 프레임을 콘솔에 출력"""
        hex_str = frame[:64].hex(" ")
        opcode = frame[:2].hex(" ") if len(frame) >= 2 else "??"
        logger.info(
            f"[FRAME] opcode={opcode} len={len(frame)} | {hex_str}..."
        )

    async def _stats_loop(self):
        """주기적 통계 출력"""
        while self._running:
            await asyncio.sleep(30)
            logger.info(
                f"[STATS] 캡처={self.stats['captured']} "
                f"프레임={self.stats['frames']} "
                f"전송={self.stats['sent']} "
                f"오류={self.stats['errors']} "
                f"잠금={'Y' if self.detector.is_locked() else 'N'}"
            )

    async def run(self):
        """캡처 시작"""
        self._running = True
        logger.info("Aion 2 패킷 캡처 에이전트 시작")

        if not self._is_game_running():
            logger.warning("Aion2.exe 프로세스를 찾을 수 없음 — 대기 중")

        # BPF 필터
        bpf = f"tcp and port {GAME_PORT}"
        logger.info(f"BPF 필터: {bpf}")

        # 비동기 전송/통계 루프 시작
        tasks = [
            asyncio.create_task(self._send_loop()),
            asyncio.create_task(self._stats_loop()),
        ]

        # 패킷 캡처 (블로킹 — 별도 스레드에서 실행)
        loop = asyncio.get_event_loop()
        try:
            await loop.run_in_executor(
                None,
                lambda: sniff(
                    filter=bpf,
                    prn=self._packet_callback,
                    store=False,
                    stop_filter=lambda _: not self._running,
                ),
            )
        except KeyboardInterrupt:
            logger.info("캡처 중지")
        finally:
            self._running = False
            for task in tasks:
                task.cancel()


def main():
    parser = argparse.ArgumentParser(description="Aion 2 Packet Capture Agent")
    parser.add_argument(
        "--server",
        default="ws://localhost:8080/capture",
        help="WebSocket 서버 URL (기본: ws://localhost:8080/capture)",
    )
    parser.add_argument(
        "--dump",
        action="store_true",
        help="덤프 모드 — 서버 전송 없이 콘솔 출력만",
    )
    args = parser.parse_args()

    agent = CaptureAgent(server_url=args.server, dump_mode=args.dump)
    asyncio.run(agent.run())


if __name__ == "__main__":
    main()
