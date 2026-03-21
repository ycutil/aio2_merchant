/*
 * WinHTTP Proxy DLL + Proper Inline Hook for Aion2
 * - DecryptMessage/EncryptMessage 인라인 후킹
 * - 정확한 16바이트 트램폴린 + RIP-relative 보정
 * - 함수 프롤로그: push rbx; push rbp; push rsi; push rdi; sub rsp,0x58; mov rax,[rip+X]
 *
 * Build:
 *   gcc -shared -o winhttp.dll winhttp_proxy.c winhttp.def -O2
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <string.h>

/* ===== Logging ===== */
static FILE *g_log = NULL;
static CRITICAL_SECTION g_cs;
static HMODULE g_real_winhttp = NULL;
static volatile long g_msg_count = 0;

static void log_msg(const char *fmt, ...) {
    if (!g_log) return;
    EnterCriticalSection(&g_cs);
    SYSTEMTIME st;
    GetLocalTime(&st);
    fprintf(g_log, "[%02d:%02d:%02d.%03d] ",
            st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    va_list a;
    va_start(a, fmt);
    vfprintf(g_log, fmt, a);
    va_end(a);
    fprintf(g_log, "\n");
    fflush(g_log);
    LeaveCriticalSection(&g_cs);
}

static void log_data(const char *label, const unsigned char *data, DWORD len) {
    if (!g_log || !data || len == 0) return;
    EnterCriticalSection(&g_cs);

    int is_text = 1;
    DWORD check = len > 200 ? 200 : len;
    for (DWORD i = 0; i < check; i++) {
        if (data[i] < 0x09 || (data[i] > 0x0d && data[i] < 0x20 && data[i] != 0x1b)) {
            is_text = 0;
            break;
        }
    }

    DWORD show = len > 4096 ? 4096 : len;
    if (is_text) {
        fprintf(g_log, "  %s TEXT (%lu B):\n", label, (unsigned long)len);
        fwrite(data, 1, show, g_log);
        if (len > show) fprintf(g_log, "\n  ... +%lu B", (unsigned long)(len - show));
        fprintf(g_log, "\n");
    } else {
        DWORD hexshow = len > 256 ? 256 : len;
        fprintf(g_log, "  %s HEX (%lu B): ", label, (unsigned long)len);
        for (DWORD i = 0; i < hexshow; i++) fprintf(g_log, "%02x ", data[i]);
        if (len > hexshow) fprintf(g_log, "...");
        fprintf(g_log, "\n");
    }
    fflush(g_log);
    LeaveCriticalSection(&g_cs);
}

/* ===== SSPI types ===== */
typedef struct {
    unsigned long cbBuffer;
    unsigned long BufferType;
    void *pvBuffer;
} SecBuffer;

typedef struct {
    unsigned long ulVersion;
    unsigned long cBuffers;
    SecBuffer *pBuffers;
} SecBufferDesc;

#define SECBUFFER_DATA 1

typedef long SECURITY_STATUS;
typedef SECURITY_STATUS (WINAPI *DecryptMessage_t)(
    void*, SecBufferDesc*, unsigned long, unsigned long*);
typedef SECURITY_STATUS (WINAPI *EncryptMessage_t)(
    void*, unsigned long, SecBufferDesc*, unsigned long);


/* ===== Trampoline structure ===== */
/*
 * 원본 함수 프롤로그 (16 bytes):
 *   +00: 40 53           push rbx
 *   +02: 55              push rbp
 *   +03: 56              push rsi
 *   +04: 57              push rdi
 *   +05: 48 83 ec 58     sub rsp, 0x58
 *   +09: 48 8b 05 XX XX XX XX   mov rax, [rip + offset]
 *
 * 트램폴린 레이아웃 (48 bytes):
 *   [0..4]   push rbx; push rbp; push rsi; push rdi
 *   [5..8]   sub rsp, 0x58
 *   [9..15]  mov rax, [rip + ADJUSTED_OFFSET]  ← RIP 보정됨
 *   [16..29] jmp back to original+16 (ff 25 00 00 00 00 + 8-byte addr)
 */

typedef struct {
    unsigned char *target;       /* original function address */
    unsigned char *trampoline;   /* executable trampoline */
    int installed;
} Hook;

static Hook g_decrypt_hook = {0};
static Hook g_encrypt_hook = {0};

static int install_hook(Hook *hook, void *target, void *detour) {
    unsigned char *func = (unsigned char*)target;
    hook->target = func;
    hook->installed = 0;

    /* Verify expected prologue pattern */
    if (func[0] != 0x40 || func[1] != 0x53 ||  /* push rbx */
        func[2] != 0x55 ||                       /* push rbp */
        func[3] != 0x56 ||                       /* push rsi */
        func[4] != 0x57 ||                       /* push rdi */
        func[5] != 0x48 || func[6] != 0x83 || func[7] != 0xEC || /* sub rsp, */
        func[9] != 0x48 || func[10] != 0x8B || func[11] != 0x05) { /* mov rax, [rip+] */
        log_msg("ERROR: Unexpected prologue at %p: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x",
                func, func[0], func[1], func[2], func[3], func[4], func[5],
                func[6], func[7], func[8], func[9], func[10], func[11]);
        return 0;
    }

    /* Allocate executable memory for trampoline */
    hook->trampoline = (unsigned char*)VirtualAlloc(
        NULL, 64, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!hook->trampoline) return 0;

    /*
     * 트램폴린 구성:
     * [0..4]   push rbx; push rbp; push rsi; push rdi  (원본 그대로)
     * [5..8]   sub rsp, 0x58                            (원본 그대로)
     * [9..18]  mov rax, imm64    (절대 주소 로드, 10 bytes)
     * [19..21] mov rax, [rax]    (간접 참조, 3 bytes)
     * [22..35] jmp func+16       (14 bytes)
     *
     * 원본의 mov rax,[rip+X]를 절대 주소 2-명령어로 대체
     */

    /* Copy first 9 bytes as-is (push rbx/rbp/rsi/rdi + sub rsp,0x58) */
    memcpy(hook->trampoline, func, 9);

    /* Calculate absolute address that original [rip+X] references */
    /* Original instruction at func+9, 7 bytes long, RIP = func+16 */
    int original_offset = *(int*)(func + 12);
    UINT64 absolute_addr = (UINT64)(func + 16 + original_offset);

    /* mov rax, imm64: 48 B8 + 8-byte immediate */
    hook->trampoline[9]  = 0x48;
    hook->trampoline[10] = 0xB8;
    *(UINT64*)(hook->trampoline + 11) = absolute_addr;

    /* mov rax, [rax]: 48 8B 00 */
    hook->trampoline[19] = 0x48;
    hook->trampoline[20] = 0x8B;
    hook->trampoline[21] = 0x00;

    /* jmp to func+16: ff 25 00 00 00 00 + 8-byte addr */
    hook->trampoline[22] = 0xFF;
    hook->trampoline[23] = 0x25;
    *(int*)(hook->trampoline + 24) = 0;
    *(UINT64*)(hook->trampoline + 28) = (UINT64)(func + 16);

    /* Now patch the original function: 14-byte jmp to detour */
    DWORD old_protect;
    VirtualProtect(func, 16, PAGE_EXECUTE_READWRITE, &old_protect);

    /* ff 25 00 00 00 00 [8-byte address] + 2 nops */
    func[0] = 0xFF;
    func[1] = 0x25;
    *(int*)(func + 2) = 0;
    *(UINT64*)(func + 6) = (UINT64)detour;
    func[14] = 0x90; /* nop */
    func[15] = 0x90; /* nop */

    DWORD dummy;
    VirtualProtect(func, 16, old_protect, &dummy);
    FlushInstructionCache(GetCurrentProcess(), func, 16);

    hook->installed = 1;
    return 1;
}


/* ===== Hooked functions ===== */

static SECURITY_STATUS WINAPI my_DecryptMessage(
    void *phContext, SecBufferDesc *pMessage,
    unsigned long MessageSeqNo, unsigned long *pfQOP)
{
    /* Call original via trampoline */
    DecryptMessage_t orig = (DecryptMessage_t)g_decrypt_hook.trampoline;
    SECURITY_STATUS status = orig(phContext, pMessage, MessageSeqNo, pfQOP);

    /* Capture AFTER decryption (status == 0 = SEC_E_OK) */
    if (status == 0 && pMessage &&
        !IsBadReadPtr(pMessage, sizeof(*pMessage)) &&
        pMessage->cBuffers <= 16 &&
        !IsBadReadPtr(pMessage->pBuffers, pMessage->cBuffers * sizeof(SecBuffer))) {
        for (unsigned long i = 0; i < pMessage->cBuffers; i++) {
            SecBuffer *buf = &pMessage->pBuffers[i];
            if (buf->BufferType == SECBUFFER_DATA &&
                buf->cbBuffer > 0 && buf->cbBuffer < 1048576 &&
                buf->pvBuffer &&
                !IsBadReadPtr(buf->pvBuffer, buf->cbBuffer)) {
                long seq = InterlockedIncrement(&g_msg_count);
                log_msg("[S2C] #%ld %lu bytes", seq, (unsigned long)buf->cbBuffer);
                log_data("S2C", (unsigned char*)buf->pvBuffer, buf->cbBuffer);
            }
        }
    }
    return status;
}

static SECURITY_STATUS WINAPI my_EncryptMessage(
    void *phContext, unsigned long fQOP,
    SecBufferDesc *pMessage, unsigned long MessageSeqNo)
{
    /* Capture BEFORE encryption */
    if (pMessage &&
        !IsBadReadPtr(pMessage, sizeof(*pMessage)) &&
        pMessage->cBuffers <= 16 &&
        !IsBadReadPtr(pMessage->pBuffers, pMessage->cBuffers * sizeof(SecBuffer))) {
        for (unsigned long i = 0; i < pMessage->cBuffers; i++) {
            SecBuffer *buf = &pMessage->pBuffers[i];
            if (buf->BufferType == SECBUFFER_DATA &&
                buf->cbBuffer > 0 && buf->cbBuffer < 1048576 &&
                buf->pvBuffer &&
                !IsBadReadPtr(buf->pvBuffer, buf->cbBuffer)) {
                long seq = InterlockedIncrement(&g_msg_count);
                log_msg("[C2S] #%ld %lu bytes", seq, (unsigned long)buf->cbBuffer);
                log_data("C2S", (unsigned char*)buf->pvBuffer, buf->cbBuffer);
            }
        }
    }

    EncryptMessage_t orig = (EncryptMessage_t)g_encrypt_hook.trampoline;
    return orig(phContext, fQOP, pMessage, MessageSeqNo);
}


/* ===== Delayed hook installation ===== */

static DWORD WINAPI hook_thread(LPVOID param) {
    Sleep(3000);
    log_msg("Hook thread starting...");

    void *decrypt_addr = NULL;
    void *encrypt_addr = NULL;

    const char *mods[] = {"sspicli.dll", "secur32.dll", NULL};
    for (int i = 0; mods[i]; i++) {
        HMODULE m = GetModuleHandleA(mods[i]);
        if (!m) m = LoadLibraryA(mods[i]);
        if (!m) continue;
        if (!decrypt_addr) decrypt_addr = GetProcAddress(m, "DecryptMessage");
        if (!encrypt_addr) encrypt_addr = GetProcAddress(m, "EncryptMessage");
        if (decrypt_addr && encrypt_addr) break;
    }

    log_msg("Targets: Decrypt=%p Encrypt=%p", decrypt_addr, encrypt_addr);

    if (!decrypt_addr || !encrypt_addr) {
        log_msg("FATAL: Cannot find functions!");
        return 1;
    }

    /* Show actual bytes for verification */
    unsigned char *d = (unsigned char*)decrypt_addr;
    unsigned char *e = (unsigned char*)encrypt_addr;
    log_msg("Decrypt bytes: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x",
            d[0],d[1],d[2],d[3],d[4],d[5],d[6],d[7],d[8],d[9],d[10],d[11],d[12],d[13],d[14],d[15]);
    log_msg("Encrypt bytes: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x",
            e[0],e[1],e[2],e[3],e[4],e[5],e[6],e[7],e[8],e[9],e[10],e[11],e[12],e[13],e[14],e[15]);

    if (install_hook(&g_decrypt_hook, decrypt_addr, my_DecryptMessage)) {
        log_msg("DecryptMessage hooked! trampoline=%p", g_decrypt_hook.trampoline);
    }
    if (install_hook(&g_encrypt_hook, encrypt_addr, my_EncryptMessage)) {
        log_msg("EncryptMessage hooked! trampoline=%p", g_encrypt_hook.trampoline);
    }

    log_msg("=== Hooks active, waiting for traffic ===");

    /* Stats loop */
    for (int i = 1; i <= 600; i++) {
        Sleep(30000);
        log_msg("[STATS] messages=%ld", g_msg_count);
    }
    return 0;
}


/* ===== DLL Entry ===== */

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hinstDLL);
        InitializeCriticalSection(&g_cs);

        g_log = fopen("C:\\Users\\Administrator\\Documents\\aion2\\winhttp_capture.log", "w");
        log_msg("=== Inline hook v4 (proper trampoline) ===");

        char sys[MAX_PATH];
        GetSystemDirectoryA(sys, MAX_PATH);
        strcat(sys, "\\winhttp.dll");
        g_real_winhttp = LoadLibraryA(sys);
        log_msg("Real winhttp: %p", g_real_winhttp);

        CreateThread(NULL, 0, hook_thread, NULL, 0, NULL);
        log_msg("Hook thread created (3s delay)");
    }
    else if (fdwReason == DLL_PROCESS_DETACH) {
        if (g_log) {
            log_msg("=== Total: %ld messages ===", g_msg_count);
            fclose(g_log);
        }
        if (g_real_winhttp) FreeLibrary(g_real_winhttp);
        DeleteCriticalSection(&g_cs);
    }
    return TRUE;
}
