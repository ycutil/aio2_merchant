"""
Aion2 ETW TLS Capture
- Windows ETW (Event Tracing for Windows)로 Schannel 복호화 데이터 캡처
- 프로세스 인젝션 없음 → GameGuard 우회
- Microsoft-Windows-Schannel + NCRYPT 프로바이더 사용

Requirements:
  pip install pywintrace
  (관리자 권한 필요)
"""
import ctypes
import ctypes.wintypes
import struct
import sys
import time
import logging
import subprocess
import os
import tempfile
from collections import defaultdict

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("etw-capture")


def check_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False


def find_game_pid():
    """Aion2.exe PID 찾기"""
    import psutil
    for proc in psutil.process_iter(['name', 'pid']):
        if proc.info['name'] and proc.info['name'].lower() in ('aion2.exe',):
            return proc.info['pid']
    return None


def method1_netsh_trace():
    """
    Method 1: netsh trace - Windows 내장 패킷 캡처 + TLS 키 로깅
    """
    logger.info("=" * 60)
    logger.info("Method 1: netsh trace (TLS key capture)")
    logger.info("=" * 60)

    trace_file = r"C:\Users\Administrator\Documents\aion2\netsh_trace.etl"
    cab_file = trace_file.replace(".etl", ".cab")

    # 기존 트레이스 중지
    subprocess.run(["netsh", "trace", "stop"], capture_output=True)
    time.sleep(1)

    # 트레이스 시작 - Schannel + NCRYPT 프로바이더 포함
    cmd = [
        "netsh", "trace", "start",
        "capture=yes",
        f"tracefile={trace_file}",
        "provider=Microsoft-Windows-Schannel",
        "keywords=0xffffffffffffffff",
        "level=5",
        "provider={37D2C3CD-C5D4-4587-8531-4696C44244C8}",
        "keywords=0xffffffffffffffff",
        "level=5",
        "maxSize=100",
        "fileMode=circular",
    ]
    logger.info(f"Running: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    logger.info(f"stdout: {result.stdout}")
    if result.returncode != 0:
        logger.error(f"stderr: {result.stderr}")
        return False

    logger.info("netsh trace 시작됨. 30초간 캡처합니다.")
    logger.info(">>> 거래소를 열고 검색하세요! <<<")

    time.sleep(30)

    # 트레이스 중지
    logger.info("트레이스 중지 중...")
    result = subprocess.run(["netsh", "trace", "stop"], capture_output=True, text=True)
    logger.info(f"stdout: {result.stdout}")

    if os.path.exists(trace_file):
        size = os.path.getsize(trace_file)
        logger.info(f"트레이스 파일 생성됨: {trace_file} ({size} bytes)")
        return True
    else:
        logger.error("트레이스 파일이 생성되지 않음")
        return False


def method2_etw_schannel_direct():
    """
    Method 2: ETW 직접 세션 - Schannel SecretAgreement 이벤트 캡처
    logman으로 ETW 세션 시작
    """
    logger.info("=" * 60)
    logger.info("Method 2: ETW direct session (logman)")
    logger.info("=" * 60)

    etl_file = r"C:\Users\Administrator\Documents\aion2\schannel_etw.etl"

    # 기존 세션 정리
    subprocess.run(["logman", "stop", "aion2_tls", "-ets"], capture_output=True)
    time.sleep(1)

    # Schannel ETW 프로바이더들
    providers = [
        # Microsoft-Windows-Schannel
        "{37D2C3CD-C5D4-4587-8531-4696C44244C8}",
        # Microsoft-Windows-Schannel-Events
        "{91CC1150-71AA-47E2-AE18-C96E61736B6F}",
        # Microsoft-Windows-NCRYPT (crypto operations)
        "{A74EFE00-14BE-4EF9-9DA9-1484D5473301}",
        # Microsoft-Windows-Crypto-BCrypt
        "{C7E089AC-BA2A-11E0-9AF7-68384824019B}",
    ]

    # 첫 번째 프로바이더로 세션 생성
    cmd = [
        "logman", "create", "trace", "aion2_tls",
        "-p", providers[0], "0xffffffffffffffff", "0x5",
        "-o", etl_file,
        "-ets",
        "-bs", "1024",
        "-nb", "16", "256",
        "-mode", "Circular",
        "-max", "100",
    ]
    logger.info(f"Creating ETW session...")
    result = subprocess.run(cmd, capture_output=True, text=True)
    logger.info(f"Create result: {result.stdout.strip()} {result.stderr.strip()}")

    # 추가 프로바이더 등록
    for prov in providers[1:]:
        cmd = [
            "logman", "update", "trace", "aion2_tls",
            "-p", prov, "0xffffffffffffffff", "0x5",
            "-ets",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        logger.info(f"Added provider {prov[:20]}...: {result.stdout.strip()}")

    logger.info("ETW 세션 시작됨. 30초간 캡처합니다.")
    logger.info(">>> 거래소를 열고 검색하세요! <<<")

    time.sleep(30)

    # 세션 중지
    logger.info("ETW 세션 중지 중...")
    result = subprocess.run(["logman", "stop", "aion2_tls", "-ets"], capture_output=True, text=True)
    logger.info(f"Stop result: {result.stdout.strip()}")

    if os.path.exists(etl_file):
        size = os.path.getsize(etl_file)
        logger.info(f"ETL 파일 생성됨: {etl_file} ({size} bytes)")
        return True
    else:
        logger.error("ETL 파일이 생성되지 않음")
        return False


def method3_pktmon():
    """
    Method 3: pktmon (Windows 10+ 내장) - 패킷 모니터 + TLS 진단
    """
    logger.info("=" * 60)
    logger.info("Method 3: pktmon (built-in packet monitor)")
    logger.info("=" * 60)

    etl_file = r"C:\Users\Administrator\Documents\aion2\pktmon.etl"

    # 기존 캡처 중지
    subprocess.run(["pktmon", "stop"], capture_output=True)
    time.sleep(1)

    # 게임 서버 IP 필터 추가
    subprocess.run(["pktmon", "filter", "remove"], capture_output=True)

    filters = [
        ["pktmon", "filter", "add", "-i", "216.107.244.65", "-t", "TCP", "-p", "443"],
        ["pktmon", "filter", "add", "-i", "209.35.114.69", "-t", "TCP", "-p", "443"],
        ["pktmon", "filter", "add", "-i", "216.107.253.19", "-t", "TCP", "-p", "443"],
        ["pktmon", "filter", "add", "-i", "216.107.254.84", "-t", "TCP", "-p", "443"],
        ["pktmon", "filter", "add", "-i", "216.107.253.180", "-t", "TCP", "-p", "443"],
    ]
    for f in filters:
        result = subprocess.run(f, capture_output=True, text=True)
        logger.info(f"Filter: {result.stdout.strip()}")

    # 캡처 시작 (전체 패킷)
    cmd = [
        "pktmon", "start",
        "--capture",
        "--pkt-size", "0",  # full packet
        "-f", etl_file,
        "--comp", "all",
    ]
    logger.info(f"Starting pktmon...")
    result = subprocess.run(cmd, capture_output=True, text=True)
    logger.info(f"Start: {result.stdout.strip()}")

    if result.returncode != 0:
        logger.error(f"pktmon start failed: {result.stderr}")
        return False

    logger.info("pktmon 시작됨. 30초간 캡처합니다.")
    logger.info(">>> 거래소를 열고 검색하세요! <<<")

    time.sleep(30)

    # 중지
    logger.info("pktmon 중지 중...")
    result = subprocess.run(["pktmon", "stop"], capture_output=True, text=True)
    logger.info(f"Stop: {result.stdout.strip()}")

    if os.path.exists(etl_file):
        size = os.path.getsize(etl_file)
        logger.info(f"pktmon 파일: {etl_file} ({size} bytes)")

        # pcapng로 변환
        pcap_file = etl_file.replace(".etl", ".pcapng")
        result = subprocess.run(
            ["pktmon", "etl2pcap", etl_file, "-o", pcap_file],
            capture_output=True, text=True
        )
        if os.path.exists(pcap_file):
            pcap_size = os.path.getsize(pcap_file)
            logger.info(f"PCAP 변환됨: {pcap_file} ({pcap_size} bytes)")
        return True

    return False


def analyze_etl_events(etl_file):
    """ETL 파일에서 이벤트 분석 (wevtutil 사용)"""
    logger.info(f"\n{'='*60}")
    logger.info(f"ETL 파일 분석: {etl_file}")
    logger.info(f"{'='*60}")

    # tracerpt로 CSV 변환
    csv_file = etl_file.replace(".etl", "_report.csv")
    cmd = [
        "tracerpt", etl_file,
        "-o", csv_file,
        "-of", "CSV",
        "-summary", etl_file.replace(".etl", "_summary.txt"),
        "-y",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    logger.info(f"tracerpt: {result.stdout.strip()}")

    if os.path.exists(csv_file):
        size = os.path.getsize(csv_file)
        logger.info(f"CSV 생성됨: {csv_file} ({size} bytes)")

        # 첫 50줄 출력
        with open(csv_file, 'r', errors='replace') as f:
            for i, line in enumerate(f):
                if i >= 50:
                    break
                logger.info(f"  {line.rstrip()}")
        return True

    summary_file = etl_file.replace(".etl", "_summary.txt")
    if os.path.exists(summary_file):
        with open(summary_file, 'r', errors='replace') as f:
            logger.info(f"Summary:\n{f.read()}")

    return False


def main():
    if not check_admin():
        logger.error("관리자 권한이 필요합니다!")
        sys.exit(1)

    logger.info("Aion2 ETW TLS Capture")
    logger.info(f"Game PID: {find_game_pid()}")

    # Method 2: ETW direct (가장 유망)
    success = method2_etw_schannel_direct()
    if success:
        analyze_etl_events(r"C:\Users\Administrator\Documents\aion2\schannel_etw.etl")

    # Method 3: pktmon (패킷 크기/타이밍 분석용)
    # method3_pktmon()


if __name__ == "__main__":
    main()
