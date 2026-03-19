"""
Aion 2 실시간 패킷 수신/분석 서버 (Mac)

Windows capture_agent.py → WebSocket → 이 서버 → 실시간 파싱 → 웹 대시보드

사용법:
  pip install websockets aiohttp lz4
  python realtime_server.py --port 8765 --web-port 8080
"""

import asyncio
import argparse
import json
import logging
import struct
import time
from collections import defaultdict
from datetime import datetime
from typing import Optional

import websockets
from aiohttp import web

from packet_parser import (
    PacketRouter,
    BrokerPacketAnalyzer,
    parse_frame,
    parse_compressed_packet,
    ParsedPacket,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("aion2-server")


class RealtimeAnalyzer:
    """실시간 패킷 분석 엔진"""

    def __init__(self):
        self.router = PacketRouter()
        self.broker_analyzer = BrokerPacketAnalyzer()
        self.stats = {
            "total_frames": 0,
            "total_packets": 0,
            "start_time": time.time(),
            "last_packet_time": 0,
            "opcode_freq": defaultdict(int),
        }
        self.recent_packets: list[dict] = []  # 최근 100개 패킷
        self.broker_candidates: dict = {}
        self.web_clients: set[web.WebSocketResponse] = set()

    def process_frame(self, timestamp: float, frame: bytes):
        self.stats["total_frames"] += 1
        self.stats["last_packet_time"] = timestamp

        parsed = parse_frame(frame)
        if parsed is None:
            return

        parsed.timestamp = timestamp

        if parsed.opcode == 0xFFFF:
            sub_packets = parse_compressed_packet(parsed.body)
            for sub in sub_packets:
                sub.timestamp = timestamp
                self._process_packet(timestamp, sub)
        else:
            self._process_packet(timestamp, parsed)

    def _process_packet(self, timestamp: float, packet: ParsedPacket):
        self.stats["total_packets"] += 1
        self.stats["opcode_freq"][packet.opcode] += 1

        self.broker_analyzer.feed(timestamp, packet)
        result = self.router.route(packet)

        packet_info = {
            "time": datetime.fromtimestamp(timestamp).strftime("%H:%M:%S.%f")[:-3],
            "opcode": packet.opcode_hex,
            "opcode_int": packet.opcode,
            "size": len(packet.body),
            "known": result is not None,
            "data": result,
        }

        self.recent_packets.append(packet_info)
        if len(self.recent_packets) > 200:
            self.recent_packets = self.recent_packets[-200:]

        # 웹 클라이언트에 실시간 브로드캐스트
        asyncio.create_task(self._broadcast(packet_info))

    async def _broadcast(self, packet_info: dict):
        if not self.web_clients:
            return
        msg = json.dumps(packet_info, ensure_ascii=False, default=str)
        closed = set()
        for ws in self.web_clients:
            try:
                await ws.send_str(msg)
            except Exception:
                closed.add(ws)
        self.web_clients -= closed

    def mark_event(self, event_type: str):
        now = time.time()
        self.broker_analyzer.mark_event(event_type, now)
        logger.info(f"이벤트 마킹: {event_type}")

    def get_status(self) -> dict:
        uptime = time.time() - self.stats["start_time"]
        unknown = self.router.get_unknown_opcode_stats()
        return {
            "uptime_sec": round(uptime, 1),
            "total_frames": self.stats["total_frames"],
            "total_packets": self.stats["total_packets"],
            "packets_per_sec": round(self.stats["total_packets"] / max(uptime, 1), 1),
            "unique_opcodes": len(self.stats["opcode_freq"]),
            "top_opcodes": [
                {"opcode": f"0x{op:04X}", "count": cnt}
                for op, cnt in sorted(
                    self.stats["opcode_freq"].items(), key=lambda x: -x[1]
                )[:15]
            ],
            "unknown_opcodes": [
                {"opcode": f"0x{op:04X}", "count": cnt}
                for op, cnt in unknown[:10]
            ],
            "web_clients": len(self.web_clients),
        }


class Server:
    """WebSocket 수신 + HTTP 대시보드 서버"""

    def __init__(self, ws_port: int, web_port: int):
        self.ws_port = ws_port
        self.web_port = web_port
        self.analyzer = RealtimeAnalyzer()
        self.capture_connected = False

    # ── WebSocket: 캡처 에이전트 연결 ──

    async def handle_capture(self, websocket):
        addr = websocket.remote_address
        logger.info(f"캡처 에이전트 연결: {addr}")
        self.capture_connected = True

        try:
            async for message in websocket:
                if isinstance(message, bytes) and len(message) > 8:
                    timestamp = struct.unpack("<d", message[:8])[0]
                    frame = message[8:]
                    self.analyzer.process_frame(timestamp, frame)
                elif isinstance(message, str):
                    try:
                        cmd = json.loads(message)
                        if cmd.get("type") == "event":
                            self.analyzer.mark_event(cmd["event"])
                    except json.JSONDecodeError:
                        pass
        except websockets.exceptions.ConnectionClosed:
            logger.warning(f"캡처 에이전트 연결 끊김: {addr}")
        finally:
            self.capture_connected = False

    async def start_ws_server(self):
        logger.info(f"캡처 수신 WebSocket: ws://0.0.0.0:{self.ws_port}")
        async with websockets.serve(self.handle_capture, "0.0.0.0", self.ws_port):
            await asyncio.Future()

    # ── HTTP: 웹 대시보드 ──

    async def handle_index(self, request):
        return web.Response(text=DASHBOARD_HTML, content_type="text/html")

    async def handle_status(self, request):
        status = self.analyzer.get_status()
        status["capture_connected"] = self.capture_connected
        return web.json_response(status)

    async def handle_packets(self, request):
        return web.json_response(self.analyzer.recent_packets[-50:])

    async def handle_event(self, request):
        data = await request.json()
        event_type = data.get("event", "unknown")
        self.analyzer.mark_event(event_type)
        candidates = self.analyzer.broker_analyzer.analyze_candidates(window_sec=3.0)
        return web.json_response({
            "ok": True,
            "broker_candidates": {
                f"0x{k:04X}": v for k, v in list(candidates.items())[:10]
            },
        })

    async def handle_ws_dashboard(self, request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        self.analyzer.web_clients.add(ws)
        logger.info(f"대시보드 클라이언트 연결 (총 {len(self.analyzer.web_clients)})")
        try:
            async for msg in ws:
                pass  # 대시보드는 수신만
        finally:
            self.analyzer.web_clients.discard(ws)
        return ws

    async def start_web_server(self):
        app = web.Application()
        app.router.add_get("/", self.handle_index)
        app.router.add_get("/api/status", self.handle_status)
        app.router.add_get("/api/packets", self.handle_packets)
        app.router.add_post("/api/event", self.handle_event)
        app.router.add_get("/ws", self.handle_ws_dashboard)

        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, "0.0.0.0", self.web_port)
        await site.start()
        logger.info(f"웹 대시보드: http://0.0.0.0:{self.web_port}")

    # ── 주기적 로그 ──

    async def stats_loop(self):
        while True:
            await asyncio.sleep(30)
            s = self.analyzer.get_status()
            logger.info(
                f"[STATS] 프레임={s['total_frames']} "
                f"패킷={s['total_packets']} "
                f"속도={s['packets_per_sec']}/s "
                f"opcode={s['unique_opcodes']}종 "
                f"캡처={'연결' if self.capture_connected else '대기'}"
            )

    async def run(self):
        await asyncio.gather(
            self.start_ws_server(),
            self.start_web_server(),
            self.stats_loop(),
        )


DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Aion2 Merchant - 실시간 패킷 모니터</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body { background: #0a0e17; color: #e0e0e0; font-family: 'Consolas', 'Monaco', monospace; font-size: 13px; }
.header { background: #111827; padding: 12px 20px; border-bottom: 1px solid #1e3a5f; display: flex; justify-content: space-between; align-items: center; }
.header h1 { font-size: 16px; color: #60a5fa; }
.status { display: flex; gap: 16px; }
.status-item { padding: 4px 10px; border-radius: 4px; font-size: 12px; }
.connected { background: #065f46; color: #6ee7b7; }
.disconnected { background: #7f1d1d; color: #fca5a5; }
.main { display: grid; grid-template-columns: 1fr 300px; height: calc(100vh - 48px); }
.packets { overflow-y: auto; padding: 8px; }
.sidebar { background: #111827; border-left: 1px solid #1e3a5f; padding: 12px; overflow-y: auto; }
.sidebar h3 { color: #60a5fa; margin: 12px 0 6px; font-size: 13px; }
.pkt { padding: 3px 8px; border-bottom: 1px solid #1a1a2e; display: flex; gap: 8px; font-size: 12px; }
.pkt:hover { background: #1a1a2e; }
.pkt .time { color: #6b7280; width: 80px; flex-shrink: 0; }
.pkt .opcode { color: #f59e0b; width: 60px; flex-shrink: 0; font-weight: bold; }
.pkt .size { color: #6b7280; width: 50px; flex-shrink: 0; text-align: right; }
.pkt .info { color: #9ca3af; flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.pkt.unknown .opcode { color: #ef4444; }
.pkt.broker-candidate .opcode { color: #10b981; background: #064e3b; padding: 0 4px; border-radius: 2px; }
.stat-row { display: flex; justify-content: space-between; padding: 3px 0; border-bottom: 1px solid #1a1a2e; }
.stat-val { color: #60a5fa; }
.btn-group { display: flex; flex-wrap: wrap; gap: 4px; margin: 8px 0; }
.btn { padding: 4px 8px; border: 1px solid #374151; background: #1f2937; color: #d1d5db; border-radius: 4px; cursor: pointer; font-size: 11px; }
.btn:hover { background: #374151; }
.btn:active { background: #4b5563; }
.opcode-list { max-height: 200px; overflow-y: auto; }
.opcode-item { display: flex; justify-content: space-between; padding: 2px 0; font-size: 11px; }
</style>
</head>
<body>

<div class="header">
  <h1>AION2 MERCHANT - Packet Monitor</h1>
  <div class="status">
    <span id="captureStatus" class="status-item disconnected">캡처 대기</span>
    <span id="pktCount" class="status-item" style="background:#1e3a5f">0 pkts</span>
    <span id="pps" class="status-item" style="background:#1e3a5f">0/s</span>
  </div>
</div>

<div class="main">
  <div class="packets" id="packetList"></div>
  <div class="sidebar">
    <h3>거래소 이벤트 마킹</h3>
    <p style="font-size:11px;color:#6b7280;margin-bottom:6px">게임에서 액션 수행 시 해당 버튼 클릭</p>
    <div class="btn-group">
      <button class="btn" onclick="markEvent('open')">거래소 열기</button>
      <button class="btn" onclick="markEvent('close')">거래소 닫기</button>
      <button class="btn" onclick="markEvent('search')">검색</button>
      <button class="btn" onclick="markEvent('page_next')">다음 페이지</button>
      <button class="btn" onclick="markEvent('buy')">구매</button>
      <button class="btn" onclick="markEvent('register')">등록</button>
      <button class="btn" onclick="markEvent('cancel')">취소</button>
    </div>
    <div id="candidateResult" style="font-size:11px;color:#10b981;margin:4px 0"></div>

    <h3>서버 상태</h3>
    <div id="serverStats"></div>

    <h3>Opcode 빈도 (상위 15)</h3>
    <div id="opcodeList" class="opcode-list"></div>

    <h3>미확인 Opcode (거래소 후보)</h3>
    <div id="unknownList" class="opcode-list"></div>
  </div>
</div>

<script>
const packetList = document.getElementById('packetList');
const captureStatus = document.getElementById('captureStatus');
const pktCount = document.getElementById('pktCount');
const ppsEl = document.getElementById('pps');
let totalPkts = 0;

// 실시간 WebSocket
const ws = new WebSocket(`ws://${location.host}/ws`);
ws.onmessage = (e) => {
  const pkt = JSON.parse(e.data);
  totalPkts++;
  addPacketRow(pkt);
  pktCount.textContent = totalPkts + ' pkts';
};

function addPacketRow(pkt) {
  const div = document.createElement('div');
  div.className = 'pkt' + (pkt.known ? '' : ' unknown');
  div.innerHTML = `
    <span class="time">${pkt.time}</span>
    <span class="opcode">${pkt.opcode}</span>
    <span class="size">${pkt.size}B</span>
    <span class="info">${pkt.data ? JSON.stringify(pkt.data) : ''}</span>
  `;
  packetList.appendChild(div);
  if (packetList.children.length > 500) packetList.removeChild(packetList.firstChild);
  packetList.scrollTop = packetList.scrollHeight;
}

// 이벤트 마킹
async function markEvent(type) {
  const res = await fetch('/api/event', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({event: type})
  });
  const data = await res.json();
  const el = document.getElementById('candidateResult');
  const candidates = data.broker_candidates || {};
  const keys = Object.keys(candidates);
  if (keys.length > 0) {
    el.innerHTML = '<b>후보:</b> ' + keys.map(k =>
      `${k}(${candidates[k].count}회, ${Math.round(candidates[k].avg_body_size)}B)`
    ).join(', ');
  } else {
    el.textContent = `이벤트 "${type}" 기록됨`;
  }
}

// 상태 폴링
async function pollStatus() {
  try {
    const res = await fetch('/api/status');
    const s = await res.json();
    captureStatus.textContent = s.capture_connected ? '캡처 연결됨' : '캡처 대기';
    captureStatus.className = 'status-item ' + (s.capture_connected ? 'connected' : 'disconnected');
    ppsEl.textContent = s.packets_per_sec + '/s';

    const statsEl = document.getElementById('serverStats');
    statsEl.innerHTML = `
      <div class="stat-row"><span>가동시간</span><span class="stat-val">${Math.round(s.uptime_sec)}s</span></div>
      <div class="stat-row"><span>총 프레임</span><span class="stat-val">${s.total_frames}</span></div>
      <div class="stat-row"><span>총 패킷</span><span class="stat-val">${s.total_packets}</span></div>
      <div class="stat-row"><span>고유 Opcode</span><span class="stat-val">${s.unique_opcodes}</span></div>
    `;

    const opcodeEl = document.getElementById('opcodeList');
    opcodeEl.innerHTML = (s.top_opcodes || []).map(o =>
      `<div class="opcode-item"><span>${o.opcode}</span><span class="stat-val">${o.count}</span></div>`
    ).join('');

    const unknownEl = document.getElementById('unknownList');
    unknownEl.innerHTML = (s.unknown_opcodes || []).map(o =>
      `<div class="opcode-item"><span style="color:#ef4444">${o.opcode}</span><span class="stat-val">${o.count}</span></div>`
    ).join('');
  } catch(e) {}
}
setInterval(pollStatus, 3000);
pollStatus();
</script>
</body>
</html>
"""


def main():
    parser = argparse.ArgumentParser(description="Aion 2 실시간 패킷 수신 서버")
    parser.add_argument("--port", type=int, default=8765, help="캡처 에이전트 수신 포트 (기본: 8765)")
    parser.add_argument("--web-port", type=int, default=8080, help="웹 대시보드 포트 (기본: 8080)")
    args = parser.parse_args()

    server = Server(ws_port=args.port, web_port=args.web_port)
    asyncio.run(server.run())


if __name__ == "__main__":
    main()
