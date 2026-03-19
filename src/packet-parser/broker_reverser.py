"""
거래소 패킷 리버싱 도구

이 도구는 패킷 캡처 에이전트와 함께 사용하여
거래소 관련 opcode를 식별하고 구조를 분석합니다.

사용 시나리오:
1. 게임에서 거래소를 열기 전에 캡처 시작
2. 거래소 열기/검색/페이지 넘기기/구매 등 액션 수행
3. 각 액션 시점을 기록
4. 패킷 타임라인과 이벤트를 매칭하여 거래소 opcode 후보 추출
"""

import json
import os
import struct
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

from packet_parser import (
    BrokerPacketAnalyzer,
    PacketRouter,
    parse_compressed_packet,
    parse_frame,
    read_varint,
    read_uint32le,
    read_int64le,
    read_utf8_string,
    ParsedPacket,
    MAGIC_BYTES,
)

DUMP_DIR = Path("../../data/captures")


class PacketDumper:
    """패킷을 파일로 덤프하여 오프라인 분석 지원"""

    def __init__(self, session_name: Optional[str] = None):
        self.session_name = session_name or datetime.now().strftime("%Y%m%d_%H%M%S")
        self.dump_path = DUMP_DIR / self.session_name
        self.dump_path.mkdir(parents=True, exist_ok=True)
        self.packet_count = 0
        self.events: list[dict] = []
        self.all_packets: list[dict] = []

    def dump_raw(self, timestamp: float, raw_data: bytes):
        """원시 패킷 저장"""
        filename = f"{self.packet_count:06d}.bin"
        filepath = self.dump_path / filename
        filepath.write_bytes(raw_data)
        self.all_packets.append({
            "index": self.packet_count,
            "timestamp": timestamp,
            "file": filename,
            "size": len(raw_data),
            "hex_preview": raw_data[:32].hex(" "),
        })
        self.packet_count += 1

    def mark_event(self, event_type: str, description: str = ""):
        """사용자 이벤트 마킹"""
        self.events.append({
            "timestamp": time.time(),
            "type": event_type,
            "description": description,
            "packet_index": self.packet_count,
        })
        print(f"[EVENT] {event_type}: {description} (패킷 #{self.packet_count})")

    def save_session(self):
        """세션 메타데이터 저장"""
        meta = {
            "session": self.session_name,
            "total_packets": self.packet_count,
            "events": self.events,
            "packets": self.all_packets,
        }
        meta_path = self.dump_path / "session.json"
        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2, ensure_ascii=False)
        print(f"세션 저장: {meta_path}")


class BrokerReverser:
    """
    거래소 패킷 리버스 엔지니어링 도구

    Aion 1 레퍼런스 기반으로 Aion 2 거래소 패킷 구조를 추정하고,
    실제 캡처 데이터와 매칭하여 opcode를 식별합니다.
    """

    def __init__(self):
        self.router = PacketRouter()
        self.analyzer = BrokerPacketAnalyzer()
        self.dumper = PacketDumper()
        self.opcode_timeline: list[tuple[float, int, int]] = []  # (time, opcode, size)

    def process_frame(self, timestamp: float, frame: bytes):
        """프레임 처리 — 파싱 + 분석"""
        self.dumper.dump_raw(timestamp, frame)

        parsed = parse_frame(frame)
        if parsed is None:
            return

        parsed.timestamp = timestamp

        # 압축 패킷 처리
        if parsed.opcode == 0xFFFF:
            sub_packets = parse_compressed_packet(parsed.body)
            for sub in sub_packets:
                sub.timestamp = timestamp
                self._analyze_packet(timestamp, sub)
        else:
            self._analyze_packet(timestamp, parsed)

    def _analyze_packet(self, timestamp: float, packet: ParsedPacket):
        """개별 패킷 분석"""
        self.analyzer.feed(timestamp, packet)
        self.opcode_timeline.append((timestamp, packet.opcode, len(packet.body)))

        # 알려진 opcode는 스킵
        result = self.router.route(packet)
        if result is None:
            # 미확인 opcode — 거래소 후보
            self._check_broker_heuristics(packet)

    def _check_broker_heuristics(self, packet: ParsedPacket):
        """
        휴리스틱으로 거래소 패킷인지 추정

        Aion 1 거래소 패킷 특징:
        1. 아이템 목록: 바디 크기가 큼 (아이템당 ~200바이트)
        2. 서브타입 바이트로 시작 (0~7)
        3. 아이템 수 필드가 있음
        4. 64-bit 가격 필드 패턴
        """
        body = packet.body
        if len(body) < 10:
            return

        # 서브타입 패턴 체크 (첫 바이트가 0~7)
        first_byte = body[0]
        if first_byte > 7:
            return

        # 바디 크기가 아이템 목록일 만한 크기인지
        # 아이템 1개 최소 ~50바이트 (VarInt 압축 감안)
        if len(body) > 100 and first_byte == 0:
            # 검색 결과 패킷 후보
            self._try_parse_search_result(packet)

    def _try_parse_search_result(self, packet: ParsedPacket):
        """
        거래소 검색 결과 패킷 파싱 시도

        Aion 1 기준:
        [1B: subType=0]
        [4B: totalCount]
        [1B: padding]
        [2B: page]
        [2B: itemCount]
        for each item: ...

        Aion 2 변환 추정 (VarInt 기반):
        [VarInt: subType=0]
        [VarInt: totalCount]
        [VarInt: page]
        [VarInt: itemCount]
        for each item: ...
        """
        body = packet.body
        try:
            offset = 0

            # 서브타입
            sub_vr = read_varint(body, offset)
            offset += sub_vr.byte_count
            sub_type = sub_vr.value

            if sub_type != 0:
                return

            # 총 아이템 수 (합리적 범위 체크)
            total_vr = read_varint(body, offset)
            offset += total_vr.byte_count
            if total_vr.value > 10000 or total_vr.value == 0:
                return

            # 페이지
            page_vr = read_varint(body, offset)
            offset += page_vr.byte_count

            # 이 패킷의 아이템 수
            count_vr = read_varint(body, offset)
            offset += count_vr.byte_count
            if count_vr.value > 50 or count_vr.value == 0:
                return

            print(
                f"[BROKER 후보!] opcode={packet.opcode_hex} "
                f"subType={sub_type} total={total_vr.value} "
                f"page={page_vr.value} count={count_vr.value} "
                f"bodySize={len(body)}"
            )

        except (ValueError, struct.error):
            pass

    def mark_event(self, event_type: str, description: str = ""):
        """사용자 이벤트 기록"""
        now = time.time()
        self.analyzer.mark_event(event_type, now)
        self.dumper.mark_event(event_type, description)

    def report(self) -> dict:
        """분석 리포트 생성"""
        # 거래소 후보 분석
        candidates = self.analyzer.analyze_candidates(window_sec=3.0)

        # 미확인 opcode 통계
        unknown_stats = self.router.get_unknown_opcode_stats()

        # Opcode 빈도
        opcode_freq: dict[int, int] = {}
        for _, opcode, _ in self.opcode_timeline:
            opcode_freq[opcode] = opcode_freq.get(opcode, 0) + 1

        return {
            "total_packets": len(self.opcode_timeline),
            "unique_opcodes": len(opcode_freq),
            "opcode_frequency": dict(
                sorted(opcode_freq.items(), key=lambda x: -x[1])
            ),
            "unknown_opcodes": unknown_stats[:20],
            "broker_candidates": candidates,
            "events": self.dumper.events,
        }

    def save_report(self):
        """리포트를 파일로 저장"""
        report = self.report()
        report_path = self.dumper.dump_path / "analysis_report.json"
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False, default=str)
        print(f"리포트 저장: {report_path}")

        # 콘솔 요약 출력
        print(f"\n{'='*60}")
        print(f"분석 리포트")
        print(f"{'='*60}")
        print(f"총 패킷: {report['total_packets']}")
        print(f"고유 Opcode: {report['unique_opcodes']}")
        print(f"\n상위 미확인 Opcode:")
        for opcode, count in report["unknown_opcodes"][:10]:
            print(f"  0x{opcode:04X} : {count}회")
        if report["broker_candidates"]:
            print(f"\n거래소 후보 Opcode:")
            for opcode, info in list(report["broker_candidates"].items())[:5]:
                print(
                    f"  0x{opcode:04X} ({info['opcode_hex']}): "
                    f"{info['count']}회, "
                    f"평균크기={info['avg_body_size']:.0f}B, "
                    f"이벤트={info['events']}"
                )
        self.dumper.save_session()


if __name__ == "__main__":
    print("거래소 패킷 리버싱 도구")
    print("=" * 40)
    print("이 도구는 캡처 에이전트와 함께 사용합니다.")
    print()
    print("사용 절차:")
    print("1. 캡처 에이전트를 --dump 모드로 실행")
    print("2. 게임에서 거래소 열기 전 시작")
    print("3. 거래소 열기 → 검색 → 페이지 넘기기 반복")
    print("4. 캡처 데이터로 오프라인 분석")
