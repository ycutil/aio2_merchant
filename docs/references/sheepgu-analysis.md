# sheepGu/aion2 분석 결과

## 개요
- **레포**: https://github.com/sheepGu/aion2
- **기술**: C# / .NET WinForms + MySQL (Entity Framework Core)
- **방식**: 화면 스크래핑 (OCR + 템플릿 매칭) — 패킷 캡처 아님!

## 핵심 발견
1. **패킷 미사용**: 네트워크 패킷을 전혀 사용하지 않음. Tesseract OCR로 게임 화면을 읽음.
2. **자동 구매 미구현**: TODO 상태
3. **원격 MySQL**: 112.111.39.216:3309 공유 서버 사용

## 참고할 데이터 모델

### AuctionItem (거래소 아이템)
| 필드 | 타입 | 설명 |
|------|------|------|
| name | string | 아이템명 |
| price | decimal(18,2) | 가격 |
| quantity | int | 수량 |
| seller_name | string | 판매자 |
| remaining_hours | int | 남은 시간 |
| position_x/y | int | UI 좌표 |
| is_abnormal_price | bool | 비정상 가격 여부 |
| price_deviation | decimal | 가격 편차 |

### MonitoredItem (감시 아이템)
| 필드 | 타입 | 설명 |
|------|------|------|
| item_name | string | 아이템명 |
| target_min/max_price | decimal | 목표 가격 범위 |
| priority | int(1-10) | 우선순위 |
| auto_purchase_enabled | bool | 자동 구매 |
| monitor_strategy | enum | 감시 전략 |

### 거래 전략
| 전략 | 조건 |
|------|------|
| Snipe | 가격 ≤ 목표최소의 80% |
| Arbitrage | 이익률 > 30% |
| Trend | 기타 |

### 아이템 카테고리
무기, 방어구, 악세서리, 재료, 강화석, 소모품, 보석, 특수 아이템, 코스튬, 탈것

## 우리 프로젝트에 적용할 점
- MonitoredItem의 가격 범위 + 우선순위 시스템
- 카테고리 분류 체계
- 가격 추이 분석 (시간대별 평균/최소/최대)
- AI 가중치 스코어링 (가격 30%, 시장 20%, 이익 30%, 타이밍 10%, 이력 10%)
