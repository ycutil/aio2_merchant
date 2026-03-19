# Aion 2 네트워크 프로토콜 명세서

> 종합 분석일: 2026-03-19
> 출처: TK-open-public/Aion2-Dps-Meter, taengu/Aion2-Dps-Meter, HappNJLand/Packet-Process, beyond-aion/aion-server

## 1. 프로토콜 개요

| 항목 | 값 |
|------|-----|
| 프로토콜 | TCP (평문, 암호화 없음!) |
| 서버 IP 대역 | `206.127.156.0/24` |
| 서버 포트 | `13328` |
| 방향 | S2C (Server-to-Client) 분석 완료 |
| 길이 인코딩 | Protobuf VarInt (LEB128) |
| 압축 | LZ4 (배치 패킷) |
| 암호화 | **없음** (평문 전송) |
| 프레임 구분자 | `06 00 36` (매직 바이트) |
| 문자열 인코딩 | UTF-8 + VarInt 길이 접두사 |

## 2. 패킷 프레임 구조

### 2.1 외부 프레임
```
[VarInt: packetLength] [optional: extraFlag (0xF0-0xFE)] [opcode byte1] [opcode byte2] [body...]
```

- **길이 접두사**: Protobuf VarInt (7비트/바이트, MSB 연속 비트)
- **추가 플래그**: 길이 뒤 첫 바이트가 0xF0~0xFE 범위면 추가 바이트 존재 → 이후 오프셋 +1
- **Opcode**: 2바이트 (길이 + 추가플래그 이후)
- **실제 길이 계산**: `realLength = varIntValue + varIntEncodedLength - 4`

### 2.2 스트림 분리 (taengu 방식)
TCP 스트림을 `06 00 36` 매직 바이트로 분리하여 개별 프레임 추출

### 2.3 VarInt 인코딩
```
표준 Protobuf/LEB128 unsigned VarInt:
- 각 바이트의 하위 7비트 = 데이터
- MSB(0x80) = 연속 플래그
- 리틀엔디안 순서
```

### 2.4 압축 패킷 (LZ4)
```
[VarInt: length] [extraFlag?] [0xFF 0xFF] [uint32le: originalLength] [LZ4 compressed data...]
```
- `0xFF 0xFF` 마커로 식별
- 압축 해제 후 내부에 다수의 서브패킷 포함 (각각 VarInt 길이 접두사)
- 재귀적으로 파싱

## 3. 알려진 Opcode 목록

### 3.1 Aion 2 확인된 Opcode
| Opcode | Hex | 타입 | 설명 |
|--------|-----|------|------|
| `04 38` | 0x0438 | 데미지 패킷 | 직접 타격 (스킬/기본공격) |
| `05 38` | 0x0538 | DoT 데미지 | 지속 피해 틱 |
| `40 36` | 0x4036 | 소환수 스폰 | 소환수/몹 출현 |
| `33 36` | 0x3336 | 자캐 닉네임 | 내 캐릭터 정보 (이름, 서버, 직업) |
| `44 36` | 0x4436 | 타캐 닉네임 | 다른 플레이어 정보 |
| `04 8D` | 0x048D | 닉네임/플레이어 | 플레이어 정보 (taengu 발견) |
| `FF FF` | 0xFFFF | 압축 마커 | LZ4 압축 멀티패킷 번들 |

### 3.2 서브 마커
| 마커 | 설명 |
|------|------|
| `07 02 06` | 소환수 주인 연결 (소환 패킷 내부) |
| `FF FF FF FF FF FF FF FF` | 소환 패킷 8바이트 앵커 |
| `03 00` | 힐량/멀티히트 종결자 |
| `06 00 36` | 프레임 종결/구분자 매직 바이트 |
| `F5 03` / `F5 A3` / `F8 03` / `F8 A3` | 루팅/액터-네임 마커 |

### 3.3 거래소 관련 Opcode → **미발견 (리버싱 필요)**
기존 DPS 미터 프로젝트에서는 거래소 패킷을 전혀 파싱하지 않음.
Aion 1 레퍼런스 기반 추정 필요.

## 4. 데미지 패킷 상세 (`04 38`)
```
[VarInt: packetLength]
[extraFlag?]
[04 38]                     -- opcode
[VarInt: targetId]          -- 대상 엔티티 ID
[VarInt: switchVariable]    -- 하위 4비트(AND 0x0F) → 패딩 크기 결정
[VarInt: flag]              -- 데미지 플래그
[VarInt: actorId]           -- 공격자 엔티티 ID
[uint32le: skillCode]       -- 스킬 코드 (4바이트 LE)
[1 byte skip]
[VarInt: type]              -- 타입 (3 = 크리티컬)
[1 byte: damageType]        -- 특수 데미지 비트필드
[N bytes: specialDamage]    -- switchVar & 0x0F에 따른 가변 길이:
                               4→8B, 5→12B, 6→10B, 7→14B
[VarInt: unknown]
[VarInt: damage]            -- 실제 데미지 값
[VarInt: loop]              -- 멀티히트 카운트
```

### 특수 데미지 플래그 비트필드
| 비트 | 마스크 | 플래그 |
|------|--------|--------|
| 0 | 0x01 | BACK (백어택) |
| 2 | 0x04 | PARRY (패리) |
| 3 | 0x08 | PERFECT (퍼펙트) |
| 4 | 0x10 | DOUBLE (더블) |
| 5 | 0x20 | ENDURE (인내) |
| 6 | 0x40 | SMITE (강타) |
| 7 | 0x80 | POWER_SHARD (마석) |

## 5. 서버 정보

### 서버 ID 범위
- `1001~1021`: 1리전 (한국 서버)
- `2001~2021`: 2리전

### 직업 코드
| 접두사 | 직업 |
|--------|------|
| 11xx | 검성 (Gladiator) |
| 12xx | 수호성 (Templar) |
| 13xx | 살성 (Assassin) |
| 14xx | 궁성 (Ranger) |
| 15xx | 마도성 (Sorcerer) |
| 16xx | 정령성 (Elementalist) |
| 17xx | 치유성 (Cleric) |
| 18xx | 호법성 (Chanter) |

## 6. 트래픽 자동 감지 방법 (패킷 미러링용)

### taengu 포크의 자동감지 파이프라인:
1. **멀티 인터페이스 캡처**: 모든 NIC에서 TCP 캡처
2. **가상 디바이스 우선**: 루프백/TAP/WireGuard 우선 시도
3. **TLS 필터링**: content_type 0x14-0x17, major=0x03이면 TLS → 무시
4. **매직 바이트 스캔**: `06 00 36` 패턴 탐색
5. **후보 등록**: 매직 발견 시 소스 포트를 후보로 등록
6. **확인 잠금**: 파싱 성공 시 포트/디바이스 잠금
7. **루프백 승격**: VPN 환경에서 물리→루프백 자동 전환

### 게임 프로세스 감지
- Win32 `EnumWindows` + 프로세스명 `Aion2.exe` 매칭
- 윈도우 타이틀 `AION2` 접두사 확인

## 7. 프로토콜 상수 및 센티넬 값 (HappNJLand 분석)

| 값 | Hex | 용도 |
|----|-----|------|
| 12,272,014 | 0xBAEBAE | 무적/흡수 센티넬 (데미지=0 처리) |
| 2,147,483,647 | 0x7FFFFFFF | INT_MAX — 미확인/미설정 HP |
| 999,999 | 0xF423F | 단일 히트 데미지 상한 |
| 8,999,999 | 0x89543F | 멀티히트 총 데미지 상한 |
| 2,000,000 | 0x1E8480 | 상한 체크 |
| 2,000 | 0x7D0 | 몹 코드 시작 임계값 |
| 71 | 0x47 | 서브타입 최대 ID |

### 엔티티 코드 범위
| 범위 | 타입 |
|------|------|
| 100,001 ~ 30,012,371 | 스킬 코드 |
| 2,000,000 ~ 2,980,259 | 몹 코드 |

### 캡처 방식 비교
| 프로젝트 | 캡처 라이브러리 | 모드 |
|----------|---------------|------|
| TK-open-public | Npcap (pcap4j) | Promiscuous |
| taengu | Npcap (pcap4j) | Multi-NIC 자동감지 |
| HappNJLand | WinDivert | SNIFF (커널 레벨, 비파괴) |

### WinDivert 방식 (HappNJLand)
- 커널 레벨 SNIFF|RecvOnly 모드 — 트래픽에 영향 없이 복사
- 멀티 스레드 캡처: CPU/2 스레드 (최소 2개)
- IPv4 → TCP → 페이로드 추출 파이프라인
- TCP 시퀀스 리오더링 지원 (128KB 버퍼)
- 디싱크 발생 시 `06 00 36` 매직으로 자동 재동기화

### 리소스 데이터
- **몹 DB**: 6,089개 정의 (코드 → 이름 + isBoss)
- **스킬 DB**: 7,062개 정의 (코드 → 한국어 이름)

## 8. 대체 프레임 마커

HappNJLand DLL 분석에서 추가 발견:
- `21 8D` (0x218D): 대체 동기화 패턴 — 프로토콜에 복수의 메시지 타입 존재 시사
- 서브타입 최대값 0x47(71): 내부 필드의 범위 체크에 사용
