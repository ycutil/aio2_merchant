# Aion 1 거래소(Broker) 패킷 레퍼런스

> 출처: beyond-aion/aion-server
> 용도: Aion 2 거래소 패킷 리버싱의 기준 참조 자료

## 1. 데이터 타입 와이어 포맷

| 메서드 | 타입 | 크기 | 설명 |
|--------|------|------|------|
| writeC/readC | byte | 1B | unsigned byte |
| writeH/readH | short | 2B | 16-bit int |
| writeD/readD | int | 4B | 32-bit int |
| writeQ/readQ | long | 8B | 64-bit int |
| writeS/readS | String | 가변 | null-terminated UTF-16LE |

**참고**: Aion 2는 UTF-16LE 대신 UTF-8 + VarInt 길이 사용 (프로토콜 진화)

## 2. Opcode 할당

### Client→Server (CM) 패킷
| Opcode | 패킷 | 리테일명 | 설명 |
|--------|------|----------|------|
| 117 | CM_BROKER_SELL_WINDOW | C_VENDOR_AVG_SOLDPRICE | 가격 범위 조회 |
| 123 | CM_BROKER_LIST | C_VENDOR_ITEMLIST_CATEGORY | 카테고리 브라우징 |
| 124 | CM_BROKER_SEARCH | C_VENDOR_ITEMLIST_NAME | 아이템 검색 |
| 125 | CM_BROKER_REGISTERED | C_VENDOR_MYLIST | 내 등록 목록 |
| 126 | CM_BUY_BROKER_ITEM | C_VENDOR_BUY | 구매 |
| 127 | CM_REGISTER_BROKER_ITEM | C_VENDOR_COMMIT | 등록 |
| 128 | CM_BROKER_CANCEL_REGISTERED | C_VENDOR_CANCEL | 등록 취소 |
| 129 | CM_BROKER_SETTLE_LIST | C_VENDOR_MYLOG | 정산 목록 |
| 130 | CM_BROKER_SETTLE_ACCOUNT | C_VENDOR_COLLECT | 정산 수령 |

### Server→Client (SM) 패킷
| Opcode | 패킷 | 설명 |
|--------|------|------|
| 146 | SM_BROKER_SERVICE (S_VENDOR) | 모든 거래소 응답 (서브타입으로 구분) |

**핵심**: 서버→클라이언트는 **단일 opcode + 서브타입** 패턴 사용

## 3. SM_BROKER_SERVICE 서브타입

| ID | 이름 | 용도 |
|----|------|------|
| 0 | SEARCHED_ITEMS | 검색/브라우징 결과 |
| 1 | REGISTERED_ITEMS | 내 등록 아이템 |
| 3 | REGISTER_ITEM | 등록 응답 |
| 4 | CANCEL_REGISTERED_ITEM | 취소 응답 |
| 5 | SETTLED_ITEMS | 판매/만료 아이템 목록 |
| 6 | REMOVE_SETTLED_ICON | 알림 아이콘 제거 |
| 7 | SHOW_SELL_WINDOW | 판매 창 + 가격 범위 |

## 4. 핵심 패킷 구조

### 검색 결과 (서브타입 0: SEARCHED_ITEMS)
```
[1B: subType=0]
[4B: totalCount]        -- 전체 매칭 아이템 수
[1B: padding]
[2B: startPage]         -- 현재 페이지
[2B: itemCount]         -- 이 패킷의 아이템 수 (최대 36)
for each item:
  [4B: objectId]        -- 아이템 고유 ID
  [4B: templateId]      -- 아이템 템플릿 ID
  [8B: totalPrice]      -- 총 가격 (단가 × 수량)
  [8B: averagePrice]    -- 최근 평균 가격
  [8B: itemCount]       -- 수량
  [138B: EnchantInfo]   -- 강화/마나석/스킨 데이터
  [var: sellerName]     -- 판매자 이름 (UTF-16LE null-term)
  [var: creatorName]    -- 제작자 이름
  [2B: unknown]
  [1B: unknown]
  [4B: polishCharge]    -- 이디안 충전값
  [1B: packCount]       -- 포장 횟수
  [1B: splitting]       -- 부분 구매 가능 여부
```

### 아이템 등록 (CM_REGISTER_BROKER_ITEM)
```
[4B: brokerNpcId]       -- 거래소 NPC 오브젝트 ID
[4B: itemUniqueId]      -- 인벤토리 아이템 고유 ID
[8B: price]             -- 단가 (Kinah)
[8B: itemCount]         -- 수량
[1B: splitting]         -- 부분 구매 허용 (0/1)
```
총 25바이트

### 아이템 구매 (CM_BUY_BROKER_ITEM)
```
[4B: brokerNpcId]       -- NPC 오브젝트 ID
[4B: itemUniqueId]      -- 거래소 아이템 고유 ID
[8B: itemCount]         -- 구매 수량
```
총 16바이트

### 카테고리 브라우징 (CM_BROKER_LIST)
```
[4B: brokerNpcId]
[1B: sortType]          -- 0=이름↑, 1=이름↓, 2=레벨↑, 3=레벨↓,
                           4=가격↑, 5=가격↓, 6=단가↑, 7=단가↓
[2B: page]              -- 페이지 번호
[2B: categoryMask]      -- 카테고리 필터
```
총 9바이트

### 아이템 검색 (CM_BROKER_SEARCH)
```
[4B: brokerNpcId]
[1B: sortType]
[2B: page]
[2B: categoryMask]
[2B: itemCount]         -- 검색할 아이템 ID 수
for each:
  [4B: itemId]          -- 아이템 템플릿 ID
```
총 11 + (itemCount × 4)바이트

### 가격 범위 조회 (서브타입 7: SHOW_SELL_WINDOW)
```
[1B: subType=7]
[1B: unknown]
[4B: itemId]
[4B: unknown]
[4B: unknown]
[1B: period=3]          -- 7일 평균 마커
[8B: currentLow]        -- 현재 최저가
[8B: currentHigh]       -- 현재 최고가
```
총 31바이트

## 5. EnchantInfoBlobEntry (138바이트 고정)

아이템 상세 상태 블록:
```
[1B: soulBound]         -- 귀속 여부
[1B: enchantLevel]      -- 강화 레벨
[4B: skinTemplateId]    -- 외형 스킨 ID
[1B: optionalSockets]   -- 마나석 슬롯 수
[1B: enchantBonus]      -- 강화 보너스
[24B: manastones]       -- 6개 마나석 ID (각 4B)
[4B: godStoneId]        -- 신석 ID
[4B: dyeInfo]           -- 염색 (상태+RGB)
[1B: unknown]
[4B: unknown]
[4B: dyeExpiration]     -- 염색 만료
[4B: idianStoneId]      -- 이디안 스톤 ID
[1B: polishNumber]      -- 연마 번호
[1B: temperingLevel]    -- 템퍼링 레벨
[48B: plumeStats]       -- 깃털 스탯 6쌍 (statId+value)
[나머지: 기타 플래그]
```

## 6. 카테고리 마스크 체계

| 마스크 ID | 카테고리 |
|-----------|----------|
| 9010 | 무기 (전체) |
| 9020 | 방어구 (전체) |
| 9030 | 악세서리 |
| 9040 | 스킬 관련 (스티그마 등) |
| 9050 | 제작 (재료, 도안) |
| 9060 | 소모품 (음식, 물약, 주문서, 강화석) |
| 9070 | 집 장식 |
| 9080 | 가구 |
| 7070 | 기타 |

## 7. 가격 시스템

- **형식**: 64-bit long (Kinah 단위)
- **와이어 전송**: `총가격 = 단가 × 수량`
- **등록 수수료**: 슬롯 1-10: 2%, 슬롯 11-15: 4%, 최소 10 Kinah
- **최대 등록**: 플레이어당 15개
- **페이지당 아이템**: 9개, 패킷당 최대 36개 (4페이지)
- **정렬**: 이름/레벨/총가격/단가 각 오름차순/내림차순

## 8. Aion 2 거래소 패킷 예측

### 유지될 것으로 예상:
- 단일 S2C opcode + 서브타입 패턴
- 아이템 템플릿 ID 기반 조회
- 가격 = 64-bit 정수
- 카테고리 필터 시스템
- 페이지네이션

### 변경될 것으로 예상:
- 리테일명이 "Vendor" 패턴 (C_VENDOR_*, S_VENDOR)
- UTF-16LE → UTF-8 + VarInt 길이
- 고정 크기 writeD/writeH → VarInt 인코딩 (프로토콜 진화)
- NPC 오브젝트 ID → 직접 UI 기반 (Aion 2는 NPC 없이 거래소 접근 가능할 수 있음)
- EnchantInfoBlob 크기 변경 (Aion 2 아이템 시스템에 맞게)
