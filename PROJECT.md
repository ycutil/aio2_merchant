# AION2 Merchant - 아이온2 거래소 실시간 정보 사이트

## 프로젝트 개요
아이온2 게임 내 거래소(마켓플레이스)의 실시간 정보를 수집, 분석하여 웹사이트로 제공하는 시스템

## 아키텍처
```
[Windows PC: Aion2 게임 실행]
        │
        ▼ (패킷 캡처 - Npcap)
[Packet Capture Agent]
        │
        ▼ (TCP 전송)
[Mac Server: Packet Parser]
        │
        ▼ (디코딩/분석)
[Backend API Server]
        │
        ├──▶ [Database] (가격 히스토리, 아이템 DB)
        │
        ▼ (WebSocket / REST API)
[Frontend Web App]
```

## 디렉토리 구조
```
aion2_merchant/
├── docs/                    # 프로젝트 문서
│   ├── packet-analysis/     # 패킷 분석 결과
│   ├── references/          # 참조 자료
│   └── architecture/        # 아키텍처 문서
├── src/
│   ├── packet-capture/      # Windows 패킷 캡처 에이전트
│   ├── packet-parser/       # 패킷 파서/디코더
│   ├── backend/             # API 서버
│   └── frontend/            # 웹 프론트엔드
├── tools/                   # 분석/디버깅 도구
├── data/                    # 데이터 파일 (아이템 DB 등)
└── scripts/                 # 빌드/배포 스크립트
```

## 기술 스택 (예정)
- **패킷 캡처**: Python + Scapy / C# + Npcap (Windows)
- **패킷 파서**: Python / TypeScript
- **백엔드**: Node.js (Express/Fastify) + WebSocket
- **프론트엔드**: React / Next.js
- **데이터베이스**: PostgreSQL + Redis (캐시)
- **배포**: Docker

## 로드맵
1. [진행중] GitHub 자료 수집 및 패킷 구조 분석
2. [대기] 패킷 미러링 시스템 구현
3. [대기] 거래소 패킷 리버스 엔지니어링
4. [대기] 백엔드/프론트엔드 구현
5. [대기] 테스트 및 배포

## 참조 레포지토리
| 레포지토리 | 용도 | 중요도 |
|---|---|---|
| TK-open-public/Aion2-Dps-Meter | 핵심 패킷 파서 (Kotlin) | ★★★★★ |
| taengu/Aion2-Dps-Meter | 확장 포크, 전 리전 지원 | ★★★★★ |
| sheepGu/aion2 | 자동 거래 도구 | ★★★★★ |
| HappNJLand/Aion2-Dps-Meter-Packet-Process | C# 패킷 프로세서 | ★★★★☆ |
| p62003/aletheia_AION2_DPS_Meter | 순수 S2C 트래픽 모니터 | ★★★★☆ |
| ZDYoung0519/NOIA2 | TypeScript DPS 미터 | ★★★☆☆ |
| ImKK666/AION2-SDK | C++ SDK | ★★★☆☆ |
| beyond-aion/aion-server | Aion1 서버 에뮬 (거래소 레퍼런스) | ★★★★☆ |
| AionGermany/aion-germany | Aion1 에뮬 (프로토콜 참조) | ★★★☆☆ |
| acottis/aion | Rust Aion 서버 (pcap 처리) | ★★★☆☆ |
