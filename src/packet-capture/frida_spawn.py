"""
Aion2 Frida Spawn Mode TLS Capture
- GameGuard 로드 전에 후킹하기 위해 spawn 모드 사용
- 게임 프로세스를 Frida가 직접 시작 → 즉시 후킹 → resume
"""
import frida
import sys
import time
import logging
import struct
from collections import defaultdict

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("frida-spawn")

GAME_EXE = r"D:\Program Files (x86)\plaync\AION2_KR\Aion2\Binaries\Win64\Aion2.exe"

# 간단한 Schannel 후킹 스크립트
HOOK_SCRIPT = r"""
'use strict';

let hookCount = 0;
let msgCount = 0;
const seen = {};

function hookModule(moduleName) {
    // DecryptMessage (S2C)
    let decrypt = Module.findExportByName(moduleName, 'DecryptMessage');
    if (decrypt && !seen['decrypt_' + moduleName]) {
        seen['decrypt_' + moduleName] = true;
        Interceptor.attach(decrypt, {
            onEnter: function(args) {
                this.pMessage = args[1];
            },
            onLeave: function(retval) {
                if (retval.toInt32() !== 0) return;
                try {
                    const pDesc = this.pMessage;
                    if (pDesc.isNull()) return;
                    const cBuffers = pDesc.add(4).readU32();
                    const pBuffers = pDesc.add(8).readPointer();
                    for (let i = 0; i < cBuffers; i++) {
                        const pBuf = pBuffers.add(i * 16);
                        const cb = pBuf.readU32();
                        const bufType = pBuf.add(4).readU32();
                        const pv = pBuf.add(8).readPointer();
                        if (bufType === 1 && cb > 0 && cb < 1048576) {
                            msgCount++;
                            send({ type: 'tls', dir: 'S2C', size: cb, seq: msgCount }, pv.readByteArray(cb));
                        }
                    }
                } catch(e) {}
            }
        });
        hookCount++;
        send({ type: 'log', msg: 'Hooked DecryptMessage in ' + moduleName });
    }

    // EncryptMessage (C2S)
    let encrypt = Module.findExportByName(moduleName, 'EncryptMessage');
    if (encrypt && !seen['encrypt_' + moduleName]) {
        seen['encrypt_' + moduleName] = true;
        Interceptor.attach(encrypt, {
            onEnter: function(args) {
                this.pMessage = args[1];
                // C2S: 읽기는 encrypt 전에 해야 함
                try {
                    const pDesc = this.pMessage;
                    if (pDesc.isNull()) return;
                    const cBuffers = pDesc.add(4).readU32();
                    const pBuffers = pDesc.add(8).readPointer();
                    for (let i = 0; i < cBuffers; i++) {
                        const pBuf = pBuffers.add(i * 16);
                        const cb = pBuf.readU32();
                        const bufType = pBuf.add(4).readU32();
                        const pv = pBuf.add(8).readPointer();
                        if (bufType === 1 && cb > 0 && cb < 1048576) {
                            msgCount++;
                            send({ type: 'tls', dir: 'C2S', size: cb, seq: msgCount }, pv.readByteArray(cb));
                        }
                    }
                } catch(e) {}
            }
        });
        hookCount++;
        send({ type: 'log', msg: 'Hooked EncryptMessage in ' + moduleName });
    }
}

// 즉시 후킹 시도
const modules = ['sspicli.dll', 'secur32.dll', 'schannel.dll', 'ncrypt.dll'];
for (const m of modules) {
    try { hookModule(m); } catch(e) {}
}

// 모듈 로드 시 후킹 (GameGuard 로드 전에 잡기 위해)
const observer = new ModuleLoadObserver({
    onAdded(module) {
        const name = module.name.toLowerCase();
        if (name === 'sspicli.dll' || name === 'secur32.dll' ||
            name === 'schannel.dll' || name === 'ncrypt.dll') {
            setTimeout(() => { hookModule(module.name); }, 100);
        }
    }
});

send({ type: 'log', msg: 'Hooks ready: ' + hookCount + ', waiting for TLS modules...' });
"""

# 통계
stats = defaultdict(int)
samples = []
MAX_SAMPLES = 50

def on_message(message, data):
    if message['type'] == 'send':
        payload = message['payload']

        if payload['type'] == 'log':
            logger.info(f"[FRIDA] {payload['msg']}")

        elif payload['type'] == 'tls' and data:
            d = payload['dir']
            size = payload['size']
            seq = payload['seq']
            stats[d] += 1
            stats[f'{d}_bytes'] += size

            head = data[:32].hex(' ') if data else ''

            if seq <= 30 or seq % 200 == 0:
                logger.info(f"[{d}] #{seq} {size}B [{head}]")

            if len(samples) < MAX_SAMPLES:
                samples.append({
                    'dir': d,
                    'size': size,
                    'seq': seq,
                    'time': time.time(),
                    'head': head,
                    'data': data[:256],
                })

    elif message['type'] == 'error':
        logger.error(f"[FRIDA ERROR] {message.get('description', str(message))}")


def main():
    logger.info(f"Game: {GAME_EXE}")
    logger.info("Spawn 모드로 게임 시작 중...")

    try:
        # spawn: 게임을 일시정지 상태로 시작
        pid = frida.spawn([GAME_EXE])
        logger.info(f"Game spawned with PID: {pid}")

        # attach & inject
        session = frida.attach(pid)
        logger.info("Attached to game process")

        script = session.create_script(HOOK_SCRIPT)
        script.on('message', on_message)
        script.load()
        logger.info("TLS hooks injected")

        # resume: 게임 실행 재개
        frida.resume(pid)
        logger.info("Game resumed. 로그인 후 거래소를 열어주세요!")
        logger.info("Ctrl+C로 종료")

        # 통계 출력 루프
        start = time.time()
        while True:
            time.sleep(10)
            elapsed = time.time() - start
            logger.info(
                f"[STATS {elapsed:.0f}s] "
                f"S2C={stats['S2C']} ({stats['S2C_bytes']}B) "
                f"C2S={stats['C2S']} ({stats['C2S_bytes']}B) "
                f"samples={len(samples)}"
            )

    except frida.ExecutableNotFoundError:
        logger.error(f"게임 실행파일을 찾을 수 없음: {GAME_EXE}")
    except frida.ProcessNotRespondingError as e:
        logger.error(f"GameGuard가 Frida를 차단했습니다: {e}")
        logger.info("=== 대안 방법 필요 ===")
    except KeyboardInterrupt:
        logger.info("\n캡처 종료")
        logger.info(f"총 S2C: {stats['S2C']} pkts ({stats['S2C_bytes']}B)")
        logger.info(f"총 C2S: {stats['C2S']} pkts ({stats['C2S_bytes']}B)")

        if samples:
            logger.info(f"\n[샘플 패킷 {len(samples)}개]")
            for s in samples[:20]:
                logger.info(f"  [{s['dir']}] {s['size']}B [{s['head']}]")
    except Exception as e:
        logger.error(f"오류: {type(e).__name__}: {e}")

    finally:
        try:
            script.unload()
            session.detach()
        except:
            pass


if __name__ == "__main__":
    main()
