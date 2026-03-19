"""
Aion 2 TLS Hooking via Frida
- Hooks Schannel (Windows TLS) DecryptMessage/EncryptMessage
- Captures decrypted game data before encryption / after decryption
- Sends to Mac server via WebSocket

Requirements (Windows):
  pip install frida frida-tools websockets

Usage:
  python frida_hook.py --server wss://xxxx.ngrok-free.app/capture
  python frida_hook.py --dump   (local dump only, no server)
"""

import argparse
import asyncio
import json
import logging
import struct
import sys
import time
import threading
from typing import Optional

try:
    import frida
except ImportError:
    print("Install frida: pip install frida frida-tools")
    sys.exit(1)

try:
    import websockets
except ImportError:
    print("Install websockets: pip install websockets")
    sys.exit(1)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("aion2-frida")

GAME_PROCESS = "Aion2.exe"

# Frida JavaScript injection script
# Hooks Windows Schannel SSPI functions for TLS interception
FRIDA_SCRIPT = r"""
'use strict';

const TARGETS = [
    // Schannel SSPI - Windows native TLS
    { module: 'sspicli.dll', fn: 'DecryptMessage', type: 'sspi_decrypt' },
    { module: 'sspicli.dll', fn: 'EncryptMessage', type: 'sspi_encrypt' },
    // Fallback: secur32.dll
    { module: 'secur32.dll', fn: 'DecryptMessage', type: 'sspi_decrypt' },
    { module: 'secur32.dll', fn: 'EncryptMessage', type: 'sspi_encrypt' },
];

let hookCount = 0;
let msgCount = 0;

function tryHook(moduleName, funcName, hookType) {
    let addr;
    try {
        addr = Module.findExportByName(moduleName, funcName);
    } catch (e) {
        return false;
    }
    if (!addr) return false;

    Interceptor.attach(addr, {
        onEnter: function (args) {
            // SecBufferDesc* pMessage is arg[1] for both Encrypt/Decrypt
            this.pMessage = args[1];
            this.direction = hookType === 'sspi_decrypt' ? 'S2C' : 'C2S';
        },
        onLeave: function (retval) {
            if (retval.toInt32() !== 0) return; // SEC_E_OK = 0

            try {
                const pSecBufferDesc = this.pMessage;
                if (pSecBufferDesc.isNull()) return;

                // SecBufferDesc layout:
                // ULONG ulVersion (4)
                // ULONG cBuffers  (4)
                // PSecBuffer pBuffers (8)
                const cBuffers = pSecBufferDesc.add(4).readU32();
                const pBuffers = pSecBufferDesc.add(8).readPointer();

                for (let i = 0; i < cBuffers; i++) {
                    // SecBuffer layout:
                    // ULONG cbBuffer (4)
                    // ULONG BufferType (4)
                    // PVOID pvBuffer (8)
                    const pBuf = pBuffers.add(i * 16);
                    const cbBuffer = pBuf.readU32();
                    const bufType = pBuf.add(4).readU32();
                    const pvBuffer = pBuf.add(8).readPointer();

                    // SECBUFFER_DATA = 1
                    if (bufType === 1 && cbBuffer > 0 && cbBuffer < 1048576) {
                        const data = pvBuffer.readByteArray(cbBuffer);
                        msgCount++;

                        send({
                            type: 'tls_data',
                            direction: this.direction,
                            size: cbBuffer,
                            seq: msgCount,
                        }, data);
                    }
                }
            } catch (e) {
                send({ type: 'error', msg: e.toString() });
            }
        }
    });

    hookCount++;
    send({ type: 'log', msg: 'Hooked ' + moduleName + '!' + funcName + ' (' + hookType + ')' });
    return true;
}

// Also try hooking WinHTTP/WinInet for HTTP-level interception
function tryHookWinHttp() {
    const targets = [
        { module: 'winhttp.dll', fn: 'WinHttpReadData' },
        { module: 'winhttp.dll', fn: 'WinHttpWriteData' },
    ];

    for (const t of targets) {
        let addr;
        try {
            addr = Module.findExportByName(t.module, t.fn);
        } catch (e) { continue; }
        if (!addr) continue;

        const isRead = t.fn.includes('Read');

        Interceptor.attach(addr, {
            onEnter: function (args) {
                this.hRequest = args[0];
                this.lpBuffer = args[1];
                this.dwRead = args[2].toInt32();
                if (!isRead) {
                    // WriteData: data available on enter
                    if (this.dwRead > 0 && this.dwRead < 1048576) {
                        const data = this.lpBuffer.readByteArray(this.dwRead);
                        msgCount++;
                        send({
                            type: 'tls_data',
                            direction: 'C2S',
                            size: this.dwRead,
                            seq: msgCount,
                        }, data);
                    }
                }
                this.lpdwBytesRead = args[3];
            },
            onLeave: function (retval) {
                if (!isRead) return;
                if (retval.toInt32() === 0) return; // FALSE = fail

                try {
                    let bytesRead = this.dwRead;
                    if (this.lpdwBytesRead && !this.lpdwBytesRead.isNull()) {
                        bytesRead = this.lpdwBytesRead.readU32();
                    }
                    if (bytesRead > 0 && bytesRead < 1048576) {
                        const data = this.lpBuffer.readByteArray(bytesRead);
                        msgCount++;
                        send({
                            type: 'tls_data',
                            direction: 'S2C',
                            size: bytesRead,
                            seq: msgCount,
                        }, data);
                    }
                } catch (e) {
                    send({ type: 'error', msg: e.toString() });
                }
            }
        });

        hookCount++;
        send({ type: 'log', msg: 'Hooked ' + t.module + '!' + t.fn });
    }
}

// Install hooks
for (const t of TARGETS) {
    tryHook(t.module, t.fn, t.type);
}
tryHookWinHttp();

send({ type: 'log', msg: 'Total hooks installed: ' + hookCount });
"""


class FridaCapture:
    """Frida-based TLS capture for Aion 2"""

    def __init__(self, server_url: str, dump_mode: bool = False):
        self.server_url = server_url
        self.dump_mode = dump_mode
        self.ws = None
        self._ws_connected = False
        self.session = None
        self.script = None
        self.queue = asyncio.Queue(maxsize=50000)
        self.stats = {"s2c": 0, "c2s": 0, "errors": 0, "sent": 0}
        self._running = False

    def _on_message(self, message, data):
        """Frida message callback (runs in Frida's thread)"""
        if message["type"] == "send":
            payload = message["payload"]

            if payload["type"] == "log":
                logger.info(f"[FRIDA] {payload['msg']}")

            elif payload["type"] == "error":
                logger.error(f"[FRIDA] {payload['msg']}")
                self.stats["errors"] += 1

            elif payload["type"] == "tls_data" and data:
                direction = payload["direction"]
                size = payload["size"]
                seq = payload["seq"]

                if direction == "S2C":
                    self.stats["s2c"] += 1
                else:
                    self.stats["c2s"] += 1

                if seq <= 20 or seq % 500 == 0:
                    head = data[:16].hex(" ") if data else ""
                    logger.info(
                        f"[{direction}] #{seq} {size}B [{head}]"
                    )

                try:
                    self.queue.put_nowait((direction, data))
                except asyncio.QueueFull:
                    self.stats["errors"] += 1

        elif message["type"] == "error":
            logger.error(f"[FRIDA ERROR] {message.get('description', message)}")

    def attach(self):
        """Attach to Aion2.exe and inject hooks"""
        logger.info(f"Attaching to {GAME_PROCESS}...")

        try:
            self.session = frida.attach(GAME_PROCESS)
        except frida.ProcessNotFoundError:
            logger.error(f"{GAME_PROCESS} not found. Is the game running?")
            sys.exit(1)
        except frida.PermissionError:
            logger.error("Permission denied. Run as Administrator!")
            sys.exit(1)

        logger.info("Injecting TLS hooks...")
        self.script = self.session.create_script(FRIDA_SCRIPT)
        self.script.on("message", self._on_message)
        self.script.load()
        logger.info("Hooks injected. Capturing TLS data...")

    async def _connect_ws(self):
        """Connect to Mac server"""
        try:
            kwargs = {}
            if "ngrok" in self.server_url:
                kwargs["additional_headers"] = {
                    "ngrok-skip-browser-warning": "true"
                }
            self.ws = await websockets.connect(self.server_url, **kwargs)
            self._ws_connected = True
            logger.info(f"Connected: {self.server_url}")
        except Exception as e:
            logger.error(f"WS connect failed: {e}")
            self._ws_connected = False
            await asyncio.sleep(5)

    async def _send_loop(self):
        """Send captured data to server"""
        while self._running:
            try:
                if not self.dump_mode and not self._ws_connected:
                    await self._connect_ws()

                direction, data = await asyncio.wait_for(
                    self.queue.get(), timeout=1.0
                )

                if self.dump_mode:
                    head = data[:32].hex(" ")
                    logger.info(f"[DUMP] {direction} {len(data)}B [{head}]")
                else:
                    # Header: 8B timestamp + 1B direction (0=S2C, 1=C2S)
                    header = struct.pack("<dB", time.time(), 0 if direction == "S2C" else 1)
                    await self.ws.send(header + data)
                    self.stats["sent"] += 1

            except asyncio.TimeoutError:
                continue
            except Exception as e:
                err_name = type(e).__name__
                if "Connection" in err_name:
                    self._ws_connected = False
                    self.ws = None
                    await asyncio.sleep(2)
                else:
                    logger.error(f"Send error: {err_name}: {e}")
                    self.stats["errors"] += 1
                    await asyncio.sleep(1)

    async def _stats_loop(self):
        """Print stats periodically"""
        while self._running:
            await asyncio.sleep(30)
            logger.info(
                f"[STATS] S2C={self.stats['s2c']} C2S={self.stats['c2s']} "
                f"sent={self.stats['sent']} errors={self.stats['errors']} "
                f"queue={self.queue.qsize()}"
            )

    async def run(self):
        self._running = True
        self.attach()

        tasks = [
            asyncio.create_task(self._send_loop()),
            asyncio.create_task(self._stats_loop()),
        ]

        try:
            # Keep running until interrupted
            while self._running:
                await asyncio.sleep(1)
        except KeyboardInterrupt:
            logger.info("Stopping...")
        finally:
            self._running = False
            if self.script:
                self.script.unload()
            if self.session:
                self.session.detach()
            for t in tasks:
                t.cancel()


def main():
    parser = argparse.ArgumentParser(description="Aion 2 TLS Hook (Frida)")
    parser.add_argument(
        "--server",
        default="ws://localhost:8080/capture",
        help="WebSocket server URL",
    )
    parser.add_argument(
        "--dump", action="store_true",
        help="Dump mode - no server, console output only",
    )
    args = parser.parse_args()

    capture = FridaCapture(server_url=args.server, dump_mode=args.dump)
    asyncio.run(capture.run())


if __name__ == "__main__":
    main()
