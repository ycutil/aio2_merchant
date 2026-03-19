# AION2 Merchant

아이온2 거래소 실시간 정보 수집 및 분석 시스템

## 구조

```
[Windows PC]                              [Mac Server]
 Aion2.exe                                 realtime_server.py
   |                                         |  (port 8080)
   v                                         |
 capture_agent.py ---WebSocket(/capture)---> 패킷 파싱 + 분석
                     (ws:// or wss://)       |
                                             v
                                        웹 대시보드 (/)
                                        실시간 패킷 모니터
                                        거래소 opcode 분석
```

---

## Windows PC 설치 가이드

### 1. Python 설치

1. https://www.python.org/downloads/ 접속
2. "Download Python 3.x.x" 클릭
3. 설치 시 **"Add Python to PATH" 반드시 체크**
4. 설치 완료 후 CMD에서 확인:
```
python --version
```

### 2. Npcap 설치

1. https://npcap.com/#download 접속
2. "Npcap x.x.x installer" 다운로드
3. 설치 시 **"WinPcap API-compatible Mode" 체크**
4. 나머지 기본값으로 설치

### 3. 캡처 에이전트 설치

```
git clone https://github.com/ycutil/aio2_merchant.git
cd aio2_merchant\src\packet-capture
install_and_run.bat
```

또는 GitHub에서 ZIP 다운로드 후:
```
cd 다운로드경로\aio2_merchant-main\src\packet-capture
install_and_run.bat
```

패키지가 자동 설치됩니다 (scapy, websockets, psutil).

### 4. 캡처 실행

#### 같은 네트워크 (LAN)
```
run.bat ws://맥IP:8080/capture
```

#### 외부 네트워크 (ngrok)
```
run.bat wss://xxxx.ngrok-free.app/capture
```

ngrok URL은 Mac 서버 관리자에게 확인하세요.

#### 로컬 덤프만 (서버 연결 없이 테스트)
```
dump_only.bat
```

### 5. 주의사항

- Aion2가 실행 중인 상태에서 캡처 시작
- CMD를 **관리자 권한으로 실행** (패킷 캡처에 필요)
- 방화벽에서 Python 네트워크 접근 허용
- VPN 사용 시에도 자동 감지됨

---

## Mac 서버 실행

```bash
cd src/packet-parser
pip3 install aiohttp lz4
python3 realtime_server.py --port 8080
```

### 외부 네트워크 연결 (ngrok)

```bash
ngrok http 8080
```

표시되는 `https://xxxx.ngrok-free.app` URL을 Windows PC에 전달.
캡처 에이전트는 `wss://xxxx.ngrok-free.app/capture`로 연결.

### 웹 대시보드

브라우저에서 `http://localhost:8080` 접속.

- 실시간 패킷 스트리밍
- opcode 빈도 분석
- 거래소 이벤트 마킹 (열기/검색/구매 등)
- 이벤트 전후 패킷 상관분석으로 거래소 opcode 후보 자동 추출

---

## 파일 구조

```
src/
  packet-capture/          # Windows 캡처 에이전트
    capture_agent.py       # 메인 캡처 프로그램
    install_and_run.bat    # 최초 설치 + 실행
    run.bat                # 빠른 실행
    dump_only.bat          # 로컬 덤프 테스트
    requirements.txt

  packet-parser/           # Mac 서버
    realtime_server.py     # 수신 + 파싱 + 웹 대시보드
    packet_parser.py       # 패킷 파서 (VarInt, LZ4, opcode)
    broker_reverser.py     # 거래소 패킷 리버싱 도구
    requirements.txt

docs/
  packet-analysis/         # 프로토콜 분석 문서
  architecture/            # 시스템 설계 문서
  references/              # 참조 자료 분석
```

## 프로토콜 요약

| 항목 | 값 |
|------|-----|
| 전송 | TCP 평문 (암호화 없음) |
| 서버 | 206.127.156.0/24:13328 |
| 프레임 구분 | 매직 바이트 `06 00 36` |
| 길이 인코딩 | Protobuf VarInt (LEB128) |
| 압축 | LZ4 (마커: `FF FF`) |
| 문자열 | UTF-8 + VarInt 길이 |
