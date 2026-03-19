"""
Aion 2 패킷 파서
- VarInt 디코딩
- LZ4 압축 해제
- Opcode 라우팅
- 거래소 패킷 분석 (리버싱 진행 중)
"""

import struct
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Optional

try:
    import lz4.block
except ImportError:
    lz4 = None


class Opcode(IntEnum):
    """알려진 Aion 2 opcode"""
    DAMAGE = 0x0438
    DOT_DAMAGE = 0x0538
    SUMMON_SPAWN = 0x4036
    OWN_NICKNAME = 0x3336
    OTHER_NICKNAME = 0x4436
    PLAYER_INFO = 0x048D
    COMPRESSED = 0xFFFF


# 거래소 관련 opcode (리버싱 필요 — 추정치)
# Aion 1에서는 S_VENDOR(146)가 서브타입으로 모든 거래소 응답을 처리
# Aion 2에서는 아직 미확인
BROKER_OPCODE_CANDIDATES = []


@dataclass
class VarIntResult:
    value: int
    byte_count: int


@dataclass
class ParsedPacket:
    opcode: int
    opcode_hex: str
    body: bytes
    timestamp: float = 0.0
    has_extra_flag: bool = False


@dataclass
class BrokerItem:
    """거래소 아이템 (Aion 1 레퍼런스 기반 구조)"""
    object_id: int = 0
    template_id: int = 0
    total_price: int = 0
    average_price: int = 0
    item_count: int = 0
    seller_name: str = ""
    creator_name: str = ""
    enchant_level: int = 0
    splitting_available: bool = False


@dataclass
class BrokerSearchResult:
    """거래소 검색 결과"""
    sub_type: int = 0
    total_count: int = 0
    page: int = 0
    items: list[BrokerItem] = field(default_factory=list)


def read_varint(data: bytes, offset: int = 0) -> VarIntResult:
    """Protobuf VarInt (LEB128) 디코딩"""
    value = 0
    shift = 0
    count = 0
    while offset + count < len(data):
        byte_val = data[offset + count]
        count += 1
        value |= (byte_val & 0x7F) << shift
        if (byte_val & 0x80) == 0:
            return VarIntResult(value, count)
        shift += 7
        if shift > 35:
            raise ValueError("VarInt too long")
    raise ValueError("Incomplete VarInt")


def read_uint16le(data: bytes, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def read_uint32le(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def read_int64le(data: bytes, offset: int) -> int:
    return struct.unpack_from("<q", data, offset)[0]


def read_utf8_string(data: bytes, offset: int) -> tuple[str, int]:
    """VarInt 길이 접두사 + UTF-8 문자열 읽기"""
    vr = read_varint(data, offset)
    str_len = vr.value
    str_start = offset + vr.byte_count
    str_end = str_start + str_len
    if str_end > len(data):
        return ("", vr.byte_count)
    text = data[str_start:str_end].decode("utf-8", errors="replace")
    return (text, vr.byte_count + str_len)


def decompress_lz4(data: bytes, offset: int) -> bytes:
    """LZ4 압축 해제"""
    if lz4 is None:
        raise ImportError("lz4 패키지 필요: pip install lz4")
    original_length = read_uint32le(data, offset)
    compressed_data = data[offset + 4:]
    return lz4.block.decompress(compressed_data, uncompressed_size=original_length)


def parse_frame(data: bytes) -> Optional[ParsedPacket]:
    """단일 프레임을 파싱하여 ParsedPacket 반환"""
    if len(data) < 2:
        return None

    offset = 0
    has_extra_flag = False

    # 추가 플래그 체크 (0xF0~0xFE)
    if 0xF0 <= data[0] <= 0xFE:
        has_extra_flag = True
        offset = 1

    if offset + 2 > len(data):
        return None

    # Opcode 추출 (2바이트)
    opcode = (data[offset] << 8) | data[offset + 1]
    body = data[offset + 2:]

    return ParsedPacket(
        opcode=opcode,
        opcode_hex=f"{data[offset]:02x} {data[offset+1]:02x}",
        body=body,
        has_extra_flag=has_extra_flag,
    )


def parse_compressed_packet(data: bytes) -> list[ParsedPacket]:
    """LZ4 압축 패킷 해제 후 서브패킷들 파싱"""
    try:
        decompressed = decompress_lz4(data, 0)
    except Exception:
        return []

    packets = []
    offset = 0
    while offset < len(decompressed):
        try:
            vr = read_varint(decompressed, offset)
            pkt_start = offset + vr.byte_count
            pkt_end = pkt_start + vr.value
            if pkt_end > len(decompressed):
                break
            pkt_data = decompressed[pkt_start:pkt_end]
            parsed = parse_frame(pkt_data)
            if parsed:
                packets.append(parsed)
            offset = pkt_end
        except (ValueError, struct.error):
            break

    return packets


class PacketRouter:
    """Opcode별 핸들러 라우터"""

    def __init__(self):
        self.handlers = {}
        self.unknown_opcodes: dict[int, int] = {}  # opcode -> count
        self._register_defaults()

    def _register_defaults(self):
        self.handlers[Opcode.DAMAGE] = self._handle_damage
        self.handlers[Opcode.DOT_DAMAGE] = self._handle_dot
        self.handlers[Opcode.OWN_NICKNAME] = self._handle_nickname
        self.handlers[Opcode.OTHER_NICKNAME] = self._handle_nickname
        self.handlers[Opcode.SUMMON_SPAWN] = self._handle_summon

    def route(self, packet: ParsedPacket):
        handler = self.handlers.get(packet.opcode)
        if handler:
            return handler(packet)
        else:
            # 미확인 opcode 추적 (거래소 opcode 발견용)
            self.unknown_opcodes[packet.opcode] = (
                self.unknown_opcodes.get(packet.opcode, 0) + 1
            )
            return None

    def get_unknown_opcode_stats(self) -> list[tuple[int, int]]:
        """미확인 opcode 빈도순 정렬 (거래소 opcode 식별용)"""
        return sorted(
            self.unknown_opcodes.items(), key=lambda x: -x[1]
        )

    def _handle_damage(self, pkt: ParsedPacket):
        """데미지 패킷 파싱 (DPS 미터 참조)"""
        body = pkt.body
        if len(body) < 10:
            return None
        try:
            offset = 0
            target_vr = read_varint(body, offset)
            offset += target_vr.byte_count
            switch_vr = read_varint(body, offset)
            offset += switch_vr.byte_count
            flag_vr = read_varint(body, offset)
            offset += flag_vr.byte_count
            actor_vr = read_varint(body, offset)
            offset += actor_vr.byte_count

            if offset + 4 > len(body):
                return None
            skill_code = read_uint32le(body, offset)

            return {
                "type": "damage",
                "target_id": target_vr.value,
                "actor_id": actor_vr.value,
                "skill_code": skill_code,
            }
        except (ValueError, struct.error):
            return None

    def _handle_dot(self, pkt: ParsedPacket):
        """DoT 데미지 패킷 파싱"""
        body = pkt.body
        try:
            offset = 0
            target_vr = read_varint(body, offset)
            offset += target_vr.byte_count
            offset += 1  # skip
            actor_vr = read_varint(body, offset)
            offset += actor_vr.byte_count
            unknown_vr = read_varint(body, offset)
            offset += unknown_vr.byte_count
            if offset + 4 > len(body):
                return None
            raw_skill = read_uint32le(body, offset)
            offset += 4
            damage_vr = read_varint(body, offset)

            return {
                "type": "dot_damage",
                "target_id": target_vr.value,
                "actor_id": actor_vr.value,
                "skill_code": raw_skill // 100,
                "damage": damage_vr.value,
            }
        except (ValueError, struct.error):
            return None

    def _handle_nickname(self, pkt: ParsedPacket):
        """닉네임 패킷 파싱"""
        return {"type": "nickname", "opcode": pkt.opcode_hex}

    def _handle_summon(self, pkt: ParsedPacket):
        """소환수 스폰 패킷"""
        return {"type": "summon_spawn", "opcode": pkt.opcode_hex}


class BrokerPacketAnalyzer:
    """
    거래소 패킷 분석기 (리버싱 도구)

    사용법:
    1. 캡처 에이전트에서 받은 모든 프레임을 feed()
    2. 거래소 UI 열기/닫기/검색 시점을 mark_event()로 기록
    3. analyze_candidates()로 거래소 opcode 후보 분석
    """

    def __init__(self):
        self.events: list[dict] = []
        self.packets_timeline: list[tuple[float, ParsedPacket]] = []

    def feed(self, timestamp: float, packet: ParsedPacket):
        self.packets_timeline.append((timestamp, packet))

    def mark_event(self, event_type: str, timestamp: float):
        """
        거래소 이벤트 기록
        event_type: "open", "close", "search", "page_next", "buy"
        """
        self.events.append({"type": event_type, "time": timestamp})

    def analyze_candidates(self, window_sec: float = 2.0) -> dict:
        """
        이벤트 전후 window_sec 초 내의 패킷에서
        거래소 opcode 후보를 추출
        """
        candidates = {}
        for event in self.events:
            event_time = event["time"]
            for ts, pkt in self.packets_timeline:
                if abs(ts - event_time) <= window_sec:
                    key = pkt.opcode
                    if key not in candidates:
                        candidates[key] = {
                            "opcode_hex": pkt.opcode_hex,
                            "count": 0,
                            "events": [],
                            "avg_body_size": 0,
                            "body_sizes": [],
                        }
                    candidates[key]["count"] += 1
                    candidates[key]["events"].append(event["type"])
                    candidates[key]["body_sizes"].append(len(pkt.body))

        # 평균 바디 크기 계산
        for info in candidates.values():
            sizes = info["body_sizes"]
            info["avg_body_size"] = sum(sizes) / len(sizes) if sizes else 0
            del info["body_sizes"]

        # 빈도순 정렬
        return dict(
            sorted(candidates.items(), key=lambda x: -x[1]["count"])
        )


if __name__ == "__main__":
    # 테스트
    test_varint = bytes([0xAC, 0x02])
    result = read_varint(test_varint)
    assert result.value == 300
    assert result.byte_count == 2
    print(f"VarInt 테스트 통과: {result.value} ({result.byte_count}바이트)")

    test_frame = bytes([0x04, 0x38, 0x01, 0x02, 0x03])
    parsed = parse_frame(test_frame)
    assert parsed is not None
    assert parsed.opcode == Opcode.DAMAGE
    print(f"프레임 파싱 테스트 통과: opcode={parsed.opcode_hex}")

    print("모든 테스트 통과")
