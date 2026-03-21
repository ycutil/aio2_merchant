/*
 * version.dll proxy - Loads alongside game, hooks libcurl's curl_easy_setopt
 * to capture all HTTP traffic via CURLOPT_DEBUGFUNCTION.
 *
 * Does NOT touch libcurl.dll file - hooks in memory at runtime.
 * All 17 version.dll exports forwarded via .def to system version.dll.
 *
 * Compile: gcc -shared -o version.dll version_hook.c version_hook.def -static-libgcc
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

/* ------------------------------------------------------------------ */
/* Logging                                                             */
/* ------------------------------------------------------------------ */
static FILE *g_logfile = NULL;
static CRITICAL_SECTION g_logcs;
static int g_msg_count = 0;

static void log_write(const char *fmt, ...) {
    if (!g_logfile) return;
    EnterCriticalSection(&g_logcs);
    SYSTEMTIME st;
    GetLocalTime(&st);
    fprintf(g_logfile, "[%02d:%02d:%02d.%03d] ",
            st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    va_list args;
    va_start(args, fmt);
    vfprintf(g_logfile, fmt, args);
    va_end(args);
    fprintf(g_logfile, "\n");
    fflush(g_logfile);
    LeaveCriticalSection(&g_logcs);
}

/* ------------------------------------------------------------------ */
/* curl constants                                                      */
/* ------------------------------------------------------------------ */
#define CURLOPT_VERBOSE       41L
#define CURLOPT_URL           10002L
#define CURLOPT_WRITEFUNCTION 20011L
#define CURLOPT_WRITEDATA     10001L
#define CURLOPT_DEBUGFUNCTION 20094L
#define CURLOPT_DEBUGDATA     10095L
#define CURLOPT_HTTPHEADER    10023L
#define CURLOPT_POSTFIELDS    10015L
#define CURLOPT_POSTFIELDSIZE 60L
#define CURLOPT_COPYPOSTFIELDS 10165L

#define CURLINFO_TEXT       0
#define CURLINFO_HEADER_IN  1
#define CURLINFO_HEADER_OUT 2
#define CURLINFO_DATA_IN    3
#define CURLINFO_DATA_OUT   4

/* ------------------------------------------------------------------ */
/* curl function types                                                 */
/* ------------------------------------------------------------------ */
typedef void CURL;
typedef int CURLcode;
typedef long CURLoption;

typedef CURLcode (*fn_curl_easy_setopt_t)(CURL *handle, CURLoption option, ...);
typedef int (*curl_debug_callback)(CURL *handle, int type, char *data, size_t size, void *userptr);

/* ------------------------------------------------------------------ */
/* Original function pointer & trampoline                              */
/* ------------------------------------------------------------------ */
static fn_curl_easy_setopt_t real_curl_easy_setopt = NULL;
static BYTE original_bytes[16];
static BYTE *trampoline = NULL;

/* ------------------------------------------------------------------ */
/* Debug callback - captures ALL HTTP data                             */
/* ------------------------------------------------------------------ */
static int our_debug_callback(CURL *handle, int type, char *data, size_t size, void *userptr) {
    (void)handle; (void)userptr;

    const char *prefix;
    switch (type) {
        case CURLINFO_TEXT:       prefix = "INFO"; break;
        case CURLINFO_HEADER_IN:  prefix = "S2C HDR"; break;
        case CURLINFO_HEADER_OUT: prefix = "C2S HDR"; break;
        case CURLINFO_DATA_IN:   prefix = "S2C DATA"; break;
        case CURLINFO_DATA_OUT:  prefix = "C2S DATA"; break;
        default: prefix = "OTHER"; break;
    }

    int msg_id = InterlockedIncrement((volatile LONG*)&g_msg_count);

    if (!g_logfile) return 0;
    EnterCriticalSection(&g_logcs);

    SYSTEMTIME st;
    GetLocalTime(&st);
    fprintf(g_logfile, "[%02d:%02d:%02d.%03d] [%s] #%d %zu bytes\n",
            st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
            prefix, msg_id, size);

    /* Print as text if printable, hex otherwise */
    int is_text = 1;
    for (size_t i = 0; i < size && i < 256; i++) {
        unsigned char c = (unsigned char)data[i];
        if (c < 0x20 && c != '\r' && c != '\n' && c != '\t') {
            is_text = 0;
            break;
        }
    }

    if (is_text && size > 0) {
        /* Print text, limit to 4KB */
        size_t print_len = size < 4096 ? size : 4096;
        fprintf(g_logfile, "  ");
        fwrite(data, 1, print_len, g_logfile);
        if (print_len < size)
            fprintf(g_logfile, "\n  ... (%zu more bytes)", size - print_len);
        fprintf(g_logfile, "\n");
    } else if (size > 0) {
        /* Print hex, first 256 bytes */
        size_t print_len = size < 256 ? size : 256;
        fprintf(g_logfile, "  HEX: ");
        for (size_t i = 0; i < print_len; i++) {
            fprintf(g_logfile, "%02x ", (unsigned char)data[i]);
            if ((i + 1) % 32 == 0) fprintf(g_logfile, "\n       ");
        }
        if (print_len < size)
            fprintf(g_logfile, "... (+%zu bytes)", size - print_len);
        fprintf(g_logfile, "\n");
    }

    fflush(g_logfile);
    LeaveCriticalSection(&g_logcs);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Hooked curl_easy_setopt                                             */
/* ------------------------------------------------------------------ */
/*
 * curl_easy_setopt prologue (14 bytes, no RIP-relative):
 *   +00: 89 54 24 10           mov [rsp+0x10], edx
 *   +04: 4c 89 44 24 18        mov [rsp+0x18], r8
 *   +09: 4c 89 4c 24 20        mov [rsp+0x20], r9
 *   +0e: 48 83 ec 28           sub rsp, 0x28
 *
 * We copy 14 bytes to trampoline + jmp back.
 * Our hook receives (rcx=handle, rdx=option, r8=value).
 */

static CURLcode hooked_curl_easy_setopt(CURL *handle, CURLoption option, void *value) {
    /* Call original via trampoline */
    fn_curl_easy_setopt_t tramp = (fn_curl_easy_setopt_t)trampoline;
    CURLcode ret = tramp(handle, option, value);

    /* Log URL setting */
    if (option == CURLOPT_URL && value) {
        log_write("curl_easy_setopt URL: %s (handle=%p)", (char*)value, handle);

        /* Force debug callback on this handle */
        tramp(handle, CURLOPT_VERBOSE, (void*)1L);
        tramp(handle, CURLOPT_DEBUGFUNCTION, (void*)our_debug_callback);
        tramp(handle, CURLOPT_DEBUGDATA, NULL);
        log_write("  -> Debug callback installed on handle %p", handle);
    }

    /* Block game from overriding our debug callback */
    if (option == CURLOPT_DEBUGFUNCTION && value != (void*)our_debug_callback) {
        log_write("  -> Blocked game's DEBUGFUNCTION override");
        return ret;  /* Don't actually set it - keep ours */
    }
    if (option == CURLOPT_VERBOSE && value == 0) {
        log_write("  -> Blocked VERBOSE=0");
        return ret;
    }

    return ret;
}

/* ------------------------------------------------------------------ */
/* Inline hook installer                                               */
/* ------------------------------------------------------------------ */
static int install_inline_hook(void *target, void *hook, BYTE *saved, BYTE **out_trampoline) {
    /* Allocate trampoline near target (within 2GB for safety, though not needed for abs jmp) */
    BYTE *tramp = (BYTE*)VirtualAlloc(NULL, 64, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!tramp) return 0;

    /* Copy original 14 bytes to trampoline */
    memcpy(saved, target, 14);
    memcpy(tramp, target, 14);

    /* Add absolute JMP back to target+14:  FF 25 00 00 00 00 [8-byte addr] */
    tramp[14] = 0xFF;
    tramp[15] = 0x25;
    *(DWORD*)(tramp + 16) = 0;
    *(UINT64*)(tramp + 20) = (UINT64)((BYTE*)target + 14);

    /* Patch target: absolute JMP to hook:  FF 25 00 00 00 00 [8-byte addr] */
    DWORD oldprot;
    VirtualProtect(target, 14, PAGE_EXECUTE_READWRITE, &oldprot);
    BYTE patch[14];
    patch[0] = 0xFF;
    patch[1] = 0x25;
    *(DWORD*)(patch + 2) = 0;
    *(UINT64*)(patch + 6) = (UINT64)hook;
    memcpy(target, patch, 14);
    VirtualProtect(target, 14, oldprot, &oldprot);
    FlushInstructionCache(GetCurrentProcess(), target, 14);

    *out_trampoline = tramp;
    return 1;
}

/* ------------------------------------------------------------------ */
/* Hook thread - waits for libcurl.dll then hooks                      */
/* ------------------------------------------------------------------ */
static DWORD WINAPI hook_thread(LPVOID param) {
    (void)param;

    log_write("Hook thread started, waiting for libcurl.dll...");

    HMODULE hcurl = NULL;
    for (int i = 0; i < 120; i++) {  /* Wait up to 60 seconds */
        hcurl = GetModuleHandleA("libcurl.dll");
        if (hcurl) break;
        Sleep(500);
    }

    if (!hcurl) {
        log_write("libcurl.dll not found after 60s, giving up");
        return 1;
    }

    log_write("libcurl.dll found at %p", hcurl);

    /* Wait a bit for libcurl to fully initialize */
    Sleep(3000);

    /* Find curl_easy_setopt */
    real_curl_easy_setopt = (fn_curl_easy_setopt_t)GetProcAddress(hcurl, "curl_easy_setopt");
    if (!real_curl_easy_setopt) {
        log_write("curl_easy_setopt not found!");
        return 1;
    }

    log_write("curl_easy_setopt at %p", real_curl_easy_setopt);
    log_write("Bytes: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x",
              ((BYTE*)real_curl_easy_setopt)[0], ((BYTE*)real_curl_easy_setopt)[1],
              ((BYTE*)real_curl_easy_setopt)[2], ((BYTE*)real_curl_easy_setopt)[3],
              ((BYTE*)real_curl_easy_setopt)[4], ((BYTE*)real_curl_easy_setopt)[5],
              ((BYTE*)real_curl_easy_setopt)[6], ((BYTE*)real_curl_easy_setopt)[7],
              ((BYTE*)real_curl_easy_setopt)[8], ((BYTE*)real_curl_easy_setopt)[9],
              ((BYTE*)real_curl_easy_setopt)[10], ((BYTE*)real_curl_easy_setopt)[11],
              ((BYTE*)real_curl_easy_setopt)[12], ((BYTE*)real_curl_easy_setopt)[13]);

    /* Install inline hook */
    if (install_inline_hook((void*)real_curl_easy_setopt, (void*)hooked_curl_easy_setopt,
                           original_bytes, &trampoline)) {
        log_write("curl_easy_setopt HOOKED! trampoline=%p", trampoline);
    } else {
        log_write("FAILED to hook curl_easy_setopt");
        return 1;
    }

    log_write("=== Hook active, waiting for HTTP traffic ===");

    /* Stats loop */
    while (1) {
        Sleep(30000);
        log_write("[STATS] messages=%d", g_msg_count);
    }

    return 0;
}

/* ------------------------------------------------------------------ */
/* DllMain                                                             */
/* ------------------------------------------------------------------ */
/* ------------------------------------------------------------------ */
/* version.dll forwarding - load system version.dll and forward calls   */
/* ------------------------------------------------------------------ */
static HMODULE g_real_version = NULL;
typedef BOOL (WINAPI *pfn_generic)();  /* generic function pointer */
static pfn_generic pfn[17] = {0};

static void load_real_version(void) {
    char syspath[MAX_PATH];
    GetSystemDirectoryA(syspath, MAX_PATH);
    strcat(syspath, "\\version.dll");
    g_real_version = LoadLibraryA(syspath);
}

#define VER_FWD(idx, name) \
    __declspec(dllexport) void* __cdecl ver_##name() { \
        if (!pfn[idx]) pfn[idx] = (pfn_generic)GetProcAddress(g_real_version, #name); \
        /* naked asm to forward all args */ \
        return ((void*(*)(void))pfn[idx])(); \
    }

/* Actually, we need proper forwarding. Use naked asm thunks. */
#undef VER_FWD

static FARPROC resolve_ver(int idx, const char *name) {
    if (!pfn[idx]) pfn[idx] = (pfn_generic)GetProcAddress(g_real_version, name);
    return (FARPROC)pfn[idx];
}

#define MAKE_VER_THUNK(idx, name) \
    void __attribute__((naked)) ver_##name(void) { \
        __asm__ __volatile__ ( \
            "sub $40, %%rsp\n\t" \
            "mov %0, %%rcx\n\t" \
            "lea %1, %%rdx\n\t" \
            "call resolve_ver\n\t" \
            "add $40, %%rsp\n\t" \
            "jmp *%%rax\n\t" \
            : : "i"(idx), "m"(#name) \
        ); \
    }

/* Simpler approach: just use regular C functions */
/* Since version.dll functions have known signatures, forward properly */

/* GetFileVersionInfoA(LPCSTR, DWORD, DWORD, LPVOID) */
__declspec(dllexport) BOOL WINAPI ver_GetFileVersionInfoA(LPCSTR a, DWORD b, DWORD c, LPVOID d) {
    if (!pfn[0]) pfn[0]=(pfn_generic)GetProcAddress(g_real_version,"GetFileVersionInfoA");
    return ((BOOL(WINAPI*)(LPCSTR,DWORD,DWORD,LPVOID))pfn[0])(a,b,c,d);
}
__declspec(dllexport) int WINAPI ver_GetFileVersionInfoByHandle(int a, void* b) {
    if (!pfn[1]) pfn[1]=(pfn_generic)GetProcAddress(g_real_version,"GetFileVersionInfoByHandle");
    return ((int(WINAPI*)(int,void*))pfn[1])(a,b);
}
__declspec(dllexport) BOOL WINAPI ver_GetFileVersionInfoExA(DWORD a, LPCSTR b, DWORD c, DWORD d, LPVOID e) {
    if (!pfn[2]) pfn[2]=(pfn_generic)GetProcAddress(g_real_version,"GetFileVersionInfoExA");
    return ((BOOL(WINAPI*)(DWORD,LPCSTR,DWORD,DWORD,LPVOID))pfn[2])(a,b,c,d,e);
}
__declspec(dllexport) BOOL WINAPI ver_GetFileVersionInfoExW(DWORD a, LPCWSTR b, DWORD c, DWORD d, LPVOID e) {
    if (!pfn[3]) pfn[3]=(pfn_generic)GetProcAddress(g_real_version,"GetFileVersionInfoExW");
    return ((BOOL(WINAPI*)(DWORD,LPCWSTR,DWORD,DWORD,LPVOID))pfn[3])(a,b,c,d,e);
}
__declspec(dllexport) DWORD WINAPI ver_GetFileVersionInfoSizeA(LPCSTR a, LPDWORD b) {
    if (!pfn[4]) pfn[4]=(pfn_generic)GetProcAddress(g_real_version,"GetFileVersionInfoSizeA");
    return ((DWORD(WINAPI*)(LPCSTR,LPDWORD))pfn[4])(a,b);
}
__declspec(dllexport) DWORD WINAPI ver_GetFileVersionInfoSizeExA(DWORD a, LPCSTR b, LPDWORD c) {
    if (!pfn[5]) pfn[5]=(pfn_generic)GetProcAddress(g_real_version,"GetFileVersionInfoSizeExA");
    return ((DWORD(WINAPI*)(DWORD,LPCSTR,LPDWORD))pfn[5])(a,b,c);
}
__declspec(dllexport) DWORD WINAPI ver_GetFileVersionInfoSizeExW(DWORD a, LPCWSTR b, LPDWORD c) {
    if (!pfn[6]) pfn[6]=(pfn_generic)GetProcAddress(g_real_version,"GetFileVersionInfoSizeExW");
    return ((DWORD(WINAPI*)(DWORD,LPCWSTR,LPDWORD))pfn[6])(a,b,c);
}
__declspec(dllexport) DWORD WINAPI ver_GetFileVersionInfoSizeW(LPCWSTR a, LPDWORD b) {
    if (!pfn[7]) pfn[7]=(pfn_generic)GetProcAddress(g_real_version,"GetFileVersionInfoSizeW");
    return ((DWORD(WINAPI*)(LPCWSTR,LPDWORD))pfn[7])(a,b);
}
__declspec(dllexport) BOOL WINAPI ver_GetFileVersionInfoW(LPCWSTR a, DWORD b, DWORD c, LPVOID d) {
    if (!pfn[8]) pfn[8]=(pfn_generic)GetProcAddress(g_real_version,"GetFileVersionInfoW");
    return ((BOOL(WINAPI*)(LPCWSTR,DWORD,DWORD,LPVOID))pfn[8])(a,b,c,d);
}
__declspec(dllexport) DWORD WINAPI ver_VerFindFileA(DWORD a, LPCSTR b, LPCSTR c, LPCSTR d, LPSTR e, PUINT f, LPSTR g, PUINT h) {
    if (!pfn[9]) pfn[9]=(pfn_generic)GetProcAddress(g_real_version,"VerFindFileA");
    return ((DWORD(WINAPI*)(DWORD,LPCSTR,LPCSTR,LPCSTR,LPSTR,PUINT,LPSTR,PUINT))pfn[9])(a,b,c,d,e,f,g,h);
}
__declspec(dllexport) DWORD WINAPI ver_VerFindFileW(DWORD a, LPCWSTR b, LPCWSTR c, LPCWSTR d, LPWSTR e, PUINT f, LPWSTR g, PUINT h) {
    if (!pfn[10]) pfn[10]=(pfn_generic)GetProcAddress(g_real_version,"VerFindFileW");
    return ((DWORD(WINAPI*)(DWORD,LPCWSTR,LPCWSTR,LPCWSTR,LPWSTR,PUINT,LPWSTR,PUINT))pfn[10])(a,b,c,d,e,f,g,h);
}
__declspec(dllexport) DWORD WINAPI ver_VerInstallFileA(DWORD a, LPCSTR b, LPCSTR c, LPCSTR d, LPCSTR e, LPCSTR f, LPSTR g, PUINT h) {
    if (!pfn[11]) pfn[11]=(pfn_generic)GetProcAddress(g_real_version,"VerInstallFileA");
    return ((DWORD(WINAPI*)(DWORD,LPCSTR,LPCSTR,LPCSTR,LPCSTR,LPCSTR,LPSTR,PUINT))pfn[11])(a,b,c,d,e,f,g,h);
}
__declspec(dllexport) DWORD WINAPI ver_VerInstallFileW(DWORD a, LPCWSTR b, LPCWSTR c, LPCWSTR d, LPCWSTR e, LPCWSTR f, LPWSTR g, PUINT h) {
    if (!pfn[12]) pfn[12]=(pfn_generic)GetProcAddress(g_real_version,"VerInstallFileW");
    return ((DWORD(WINAPI*)(DWORD,LPCWSTR,LPCWSTR,LPCWSTR,LPCWSTR,LPCWSTR,LPWSTR,PUINT))pfn[12])(a,b,c,d,e,f,g,h);
}
__declspec(dllexport) DWORD WINAPI ver_VerLanguageNameA(DWORD a, LPSTR b, DWORD c) {
    if (!pfn[13]) pfn[13]=(pfn_generic)GetProcAddress(g_real_version,"VerLanguageNameA");
    return ((DWORD(WINAPI*)(DWORD,LPSTR,DWORD))pfn[13])(a,b,c);
}
__declspec(dllexport) DWORD WINAPI ver_VerLanguageNameW(DWORD a, LPWSTR b, DWORD c) {
    if (!pfn[14]) pfn[14]=(pfn_generic)GetProcAddress(g_real_version,"VerLanguageNameW");
    return ((DWORD(WINAPI*)(DWORD,LPWSTR,DWORD))pfn[14])(a,b,c);
}
__declspec(dllexport) BOOL WINAPI ver_VerQueryValueA(LPCVOID a, LPCSTR b, LPVOID *c, PUINT d) {
    if (!pfn[15]) pfn[15]=(pfn_generic)GetProcAddress(g_real_version,"VerQueryValueA");
    return ((BOOL(WINAPI*)(LPCVOID,LPCSTR,LPVOID*,PUINT))pfn[15])(a,b,c,d);
}
__declspec(dllexport) BOOL WINAPI ver_VerQueryValueW(LPCVOID a, LPCWSTR b, LPVOID *c, PUINT d) {
    if (!pfn[16]) pfn[16]=(pfn_generic)GetProcAddress(g_real_version,"VerQueryValueW");
    return ((BOOL(WINAPI*)(LPCVOID,LPCWSTR,LPVOID*,PUINT))pfn[16])(a,b,c,d);
}

/* ------------------------------------------------------------------ */
/* DllMain                                                             */
/* ------------------------------------------------------------------ */
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
    (void)lpReserved; (void)hinstDLL;
    if (fdwReason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hinstDLL);
        load_real_version();
        InitializeCriticalSection(&g_logcs);
        g_logfile = fopen("C:/Users/Administrator/Documents/aion2/curl_capture.log", "w");
        log_write("=== version.dll hook proxy loaded (PID=%lu) ===", GetCurrentProcessId());
        CreateThread(NULL, 0, hook_thread, NULL, 0, NULL);
    }
    else if (fdwReason == DLL_PROCESS_DETACH) {
        log_write("=== Unloading, total messages: %d ===", g_msg_count);
        if (g_logfile) { fclose(g_logfile); g_logfile = NULL; }
        if (trampoline) { VirtualFree(trampoline, 0, MEM_RELEASE); trampoline = NULL; }
        DeleteCriticalSection(&g_logcs);
    }
    return TRUE;
}
