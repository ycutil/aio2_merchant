/*
 * libcurl proxy DLL - Intercepts Aion2 game HTTP traffic
 *
 * All 86 exports are REAL functions (not .def forwarders) that resolve
 * the original function via GetProcAddress at runtime.
 *
 * Hooked functions: curl_easy_init, curl_easy_setopt, curl_easy_perform,
 *                   curl_easy_cleanup
 * All others: naked JMP thunks that forward all args transparently.
 *
 * Compile: gcc -shared -o libcurl.dll libcurl_proxy.c libcurl_proxy.def
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>

/* ------------------------------------------------------------------ */
/* CURLoption constants                                                */
/* ------------------------------------------------------------------ */
/* Forward declarations */
static void lazy_init(void);
static void log_init(void);
static void log_write(const char *fmt, ...);

#define CURLOPT_VERBOSE         41L
#define CURLOPT_URL             10002L
#define CURLOPT_WRITEFUNCTION   20011L
#define CURLOPT_DEBUGFUNCTION   20094L
#define CURLOPT_DEBUGDATA       10095L

/* curl_infotype values */
#define CURLINFO_TEXT       0
#define CURLINFO_HEADER_IN  1
#define CURLINFO_HEADER_OUT 2
#define CURLINFO_DATA_IN    3
#define CURLINFO_DATA_OUT   4

/* ------------------------------------------------------------------ */
/* Logging                                                             */
/* ------------------------------------------------------------------ */
static CRITICAL_SECTION g_log_cs;
static FILE *g_logfile = NULL;
static const char *LOG_PATH = "C:/Users/Administrator/Documents/aion2/curl_capture.log";

static void log_init(void) {
    InitializeCriticalSection(&g_log_cs);
    g_logfile = fopen(LOG_PATH, "a");
    if (g_logfile) {
        setvbuf(g_logfile, NULL, _IOLBF, 0);  /* line-buffered */
    }
}

static void log_write(const char *fmt, ...) {
    if (!g_logfile) return;
    EnterCriticalSection(&g_log_cs);

    SYSTEMTIME st;
    GetLocalTime(&st);
    fprintf(g_logfile, "[%04d-%02d-%02d %02d:%02d:%02d.%03d] ",
            st.wYear, st.wMonth, st.wDay,
            st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);

    va_list ap;
    va_start(ap, fmt);
    vfprintf(g_logfile, fmt, ap);
    va_end(ap);

    fprintf(g_logfile, "\n");
    fflush(g_logfile);
    LeaveCriticalSection(&g_log_cs);
}

static void log_hex_dump(const char *prefix, const void *handle, const char *data, size_t size) {
    if (!g_logfile || size == 0) return;
    EnterCriticalSection(&g_log_cs);

    SYSTEMTIME st;
    GetLocalTime(&st);
    fprintf(g_logfile, "[%04d-%02d-%02d %02d:%02d:%02d.%03d] %s (handle=%p, %zu bytes):\n",
            st.wYear, st.wMonth, st.wDay,
            st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
            prefix, handle, size);

    /* Print as text (truncate at 4KB for text view) */
    size_t text_len = size < 4096 ? size : 4096;
    fprintf(g_logfile, "--- TEXT ---\n");
    fwrite(data, 1, text_len, g_logfile);
    if (text_len < size)
        fprintf(g_logfile, "\n... (truncated, %zu more bytes)", size - text_len);
    fprintf(g_logfile, "\n--- HEX ---\n");

    /* Hex dump (limit to first 2KB) */
    size_t hex_len = size < 2048 ? size : 2048;
    for (size_t i = 0; i < hex_len; i += 16) {
        fprintf(g_logfile, "  %04zx: ", i);
        for (size_t j = 0; j < 16; j++) {
            if (i + j < hex_len)
                fprintf(g_logfile, "%02x ", (unsigned char)data[i + j]);
            else
                fprintf(g_logfile, "   ");
        }
        fprintf(g_logfile, " |");
        for (size_t j = 0; j < 16 && (i + j) < hex_len; j++) {
            unsigned char c = (unsigned char)data[i + j];
            fprintf(g_logfile, "%c", (c >= 32 && c < 127) ? c : '.');
        }
        fprintf(g_logfile, "|\n");
    }
    if (hex_len < size)
        fprintf(g_logfile, "  ... (%zu more bytes)\n", size - hex_len);
    fprintf(g_logfile, "--- END ---\n");
    fflush(g_logfile);

    LeaveCriticalSection(&g_log_cs);
}

/* ------------------------------------------------------------------ */
/* Real DLL handle and function pointers                               */
/* ------------------------------------------------------------------ */
static HMODULE g_real_dll = NULL;

/* Typedefs for hooked functions */
typedef void* (*fn_curl_easy_init_t)(void);
typedef int   (*fn_curl_easy_setopt_t)(void *handle, long option, ...);
typedef int   (*fn_curl_easy_perform_t)(void *handle);
typedef void  (*fn_curl_easy_cleanup_t)(void *handle);

static fn_curl_easy_init_t    real_curl_easy_init    = NULL;
static fn_curl_easy_setopt_t  real_curl_easy_setopt  = NULL;
static fn_curl_easy_perform_t real_curl_easy_perform = NULL;
static fn_curl_easy_cleanup_t real_curl_easy_cleanup = NULL;

/* Generic function pointers for all other 82 pass-through functions */
typedef void (*fn_generic_t)(void);

static fn_generic_t real_curl_easy_duphandle = NULL;
static fn_generic_t real_curl_easy_escape = NULL;
static fn_generic_t real_curl_easy_getinfo = NULL;
static fn_generic_t real_curl_easy_option_by_id = NULL;
static fn_generic_t real_curl_easy_option_by_name = NULL;
static fn_generic_t real_curl_easy_option_next = NULL;
static fn_generic_t real_curl_easy_pause = NULL;
static fn_generic_t real_curl_easy_recv = NULL;
static fn_generic_t real_curl_easy_reset = NULL;
static fn_generic_t real_curl_easy_send = NULL;
static fn_generic_t real_curl_easy_strerror = NULL;
static fn_generic_t real_curl_easy_unescape = NULL;
static fn_generic_t real_curl_easy_upkeep = NULL;
static fn_generic_t real_curl_escape = NULL;
static fn_generic_t real_curl_formadd = NULL;
static fn_generic_t real_curl_formfree = NULL;
static fn_generic_t real_curl_formget = NULL;
static fn_generic_t real_curl_free = NULL;
static fn_generic_t real_curl_getdate = NULL;
static fn_generic_t real_curl_getenv = NULL;
static fn_generic_t real_curl_global_cleanup = NULL;
static fn_generic_t real_curl_global_init = NULL;
static fn_generic_t real_curl_global_init_mem = NULL;
static fn_generic_t real_curl_global_sslset = NULL;
static fn_generic_t real_curl_maprintf = NULL;
static fn_generic_t real_curl_mfprintf = NULL;
static fn_generic_t real_curl_mime_addpart = NULL;
static fn_generic_t real_curl_mime_data = NULL;
static fn_generic_t real_curl_mime_data_cb = NULL;
static fn_generic_t real_curl_mime_encoder = NULL;
static fn_generic_t real_curl_mime_filedata = NULL;
static fn_generic_t real_curl_mime_filename = NULL;
static fn_generic_t real_curl_mime_free = NULL;
static fn_generic_t real_curl_mime_headers = NULL;
static fn_generic_t real_curl_mime_init = NULL;
static fn_generic_t real_curl_mime_name = NULL;
static fn_generic_t real_curl_mime_subparts = NULL;
static fn_generic_t real_curl_mime_type = NULL;
static fn_generic_t real_curl_mprintf = NULL;
static fn_generic_t real_curl_msnprintf = NULL;
static fn_generic_t real_curl_msprintf = NULL;
static fn_generic_t real_curl_multi_add_handle = NULL;
static fn_generic_t real_curl_multi_assign = NULL;
static fn_generic_t real_curl_multi_cleanup = NULL;
static fn_generic_t real_curl_multi_fdset = NULL;
static fn_generic_t real_curl_multi_info_read = NULL;
static fn_generic_t real_curl_multi_init = NULL;
static fn_generic_t real_curl_multi_perform = NULL;
static fn_generic_t real_curl_multi_poll = NULL;
static fn_generic_t real_curl_multi_remove_handle = NULL;
static fn_generic_t real_curl_multi_setopt = NULL;
static fn_generic_t real_curl_multi_socket = NULL;
static fn_generic_t real_curl_multi_socket_action = NULL;
static fn_generic_t real_curl_multi_socket_all = NULL;
static fn_generic_t real_curl_multi_strerror = NULL;
static fn_generic_t real_curl_multi_timeout = NULL;
static fn_generic_t real_curl_multi_wait = NULL;
static fn_generic_t real_curl_multi_wakeup = NULL;
static fn_generic_t real_curl_mvaprintf = NULL;
static fn_generic_t real_curl_mvfprintf = NULL;
static fn_generic_t real_curl_mvprintf = NULL;
static fn_generic_t real_curl_mvsnprintf = NULL;
static fn_generic_t real_curl_mvsprintf = NULL;
static fn_generic_t real_curl_pushheader_byname = NULL;
static fn_generic_t real_curl_pushheader_bynum = NULL;
static fn_generic_t real_curl_share_cleanup = NULL;
static fn_generic_t real_curl_share_init = NULL;
static fn_generic_t real_curl_share_setopt = NULL;
static fn_generic_t real_curl_share_strerror = NULL;
static fn_generic_t real_curl_slist_append = NULL;
static fn_generic_t real_curl_slist_free_all = NULL;
static fn_generic_t real_curl_strequal = NULL;
static fn_generic_t real_curl_strnequal = NULL;
static fn_generic_t real_curl_unescape = NULL;
static fn_generic_t real_curl_url = NULL;
static fn_generic_t real_curl_url_cleanup = NULL;
static fn_generic_t real_curl_url_dup = NULL;
static fn_generic_t real_curl_url_get = NULL;
static fn_generic_t real_curl_url_set = NULL;
static fn_generic_t real_curl_url_strerror = NULL;
static fn_generic_t real_curl_version = NULL;
static fn_generic_t real_curl_version_info = NULL;

/* ------------------------------------------------------------------ */
/* Resolve all function pointers                                       */
/* ------------------------------------------------------------------ */
#define RESOLVE(name) do { \
    real_##name = (fn_generic_t)GetProcAddress(g_real_dll, #name); \
    if (!real_##name) log_write("WARNING: Failed to resolve " #name); \
} while(0)

#define RESOLVE_TYPED(name, type) do { \
    real_##name = (type)GetProcAddress(g_real_dll, #name); \
    if (!real_##name) log_write("WARNING: Failed to resolve " #name); \
} while(0)

static void resolve_all(void) {
    /* Hooked functions with typed pointers */
    RESOLVE_TYPED(curl_easy_init,    fn_curl_easy_init_t);
    RESOLVE_TYPED(curl_easy_setopt,  fn_curl_easy_setopt_t);
    RESOLVE_TYPED(curl_easy_perform, fn_curl_easy_perform_t);
    RESOLVE_TYPED(curl_easy_cleanup, fn_curl_easy_cleanup_t);

    /* All other pass-through functions */
    RESOLVE(curl_easy_duphandle);
    RESOLVE(curl_easy_escape);
    RESOLVE(curl_easy_getinfo);
    RESOLVE(curl_easy_option_by_id);
    RESOLVE(curl_easy_option_by_name);
    RESOLVE(curl_easy_option_next);
    RESOLVE(curl_easy_pause);
    RESOLVE(curl_easy_recv);
    RESOLVE(curl_easy_reset);
    RESOLVE(curl_easy_send);
    RESOLVE(curl_easy_strerror);
    RESOLVE(curl_easy_unescape);
    RESOLVE(curl_easy_upkeep);
    RESOLVE(curl_escape);
    RESOLVE(curl_formadd);
    RESOLVE(curl_formfree);
    RESOLVE(curl_formget);
    RESOLVE(curl_free);
    RESOLVE(curl_getdate);
    RESOLVE(curl_getenv);
    RESOLVE(curl_global_cleanup);
    RESOLVE(curl_global_init);
    RESOLVE(curl_global_init_mem);
    RESOLVE(curl_global_sslset);
    RESOLVE(curl_maprintf);
    RESOLVE(curl_mfprintf);
    RESOLVE(curl_mime_addpart);
    RESOLVE(curl_mime_data);
    RESOLVE(curl_mime_data_cb);
    RESOLVE(curl_mime_encoder);
    RESOLVE(curl_mime_filedata);
    RESOLVE(curl_mime_filename);
    RESOLVE(curl_mime_free);
    RESOLVE(curl_mime_headers);
    RESOLVE(curl_mime_init);
    RESOLVE(curl_mime_name);
    RESOLVE(curl_mime_subparts);
    RESOLVE(curl_mime_type);
    RESOLVE(curl_mprintf);
    RESOLVE(curl_msnprintf);
    RESOLVE(curl_msprintf);
    RESOLVE(curl_multi_add_handle);
    RESOLVE(curl_multi_assign);
    RESOLVE(curl_multi_cleanup);
    RESOLVE(curl_multi_fdset);
    RESOLVE(curl_multi_info_read);
    RESOLVE(curl_multi_init);
    RESOLVE(curl_multi_perform);
    RESOLVE(curl_multi_poll);
    RESOLVE(curl_multi_remove_handle);
    RESOLVE(curl_multi_setopt);
    RESOLVE(curl_multi_socket);
    RESOLVE(curl_multi_socket_action);
    RESOLVE(curl_multi_socket_all);
    RESOLVE(curl_multi_strerror);
    RESOLVE(curl_multi_timeout);
    RESOLVE(curl_multi_wait);
    RESOLVE(curl_multi_wakeup);
    RESOLVE(curl_mvaprintf);
    RESOLVE(curl_mvfprintf);
    RESOLVE(curl_mvprintf);
    RESOLVE(curl_mvsnprintf);
    RESOLVE(curl_mvsprintf);
    RESOLVE(curl_pushheader_byname);
    RESOLVE(curl_pushheader_bynum);
    RESOLVE(curl_share_cleanup);
    RESOLVE(curl_share_init);
    RESOLVE(curl_share_setopt);
    RESOLVE(curl_share_strerror);
    RESOLVE(curl_slist_append);
    RESOLVE(curl_slist_free_all);
    RESOLVE(curl_strequal);
    RESOLVE(curl_strnequal);
    RESOLVE(curl_unescape);
    RESOLVE(curl_url);
    RESOLVE(curl_url_cleanup);
    RESOLVE(curl_url_dup);
    RESOLVE(curl_url_get);
    RESOLVE(curl_url_set);
    RESOLVE(curl_url_strerror);
    RESOLVE(curl_version);
    RESOLVE(curl_version_info);
}

/* ------------------------------------------------------------------ */
/* Debug callback - captures all HTTP traffic                          */
/* ------------------------------------------------------------------ */
static int proxy_debug_callback(void *handle, int type, char *data, size_t size, void *userptr) {
    (void)userptr;
    const char *prefix;
    switch (type) {
        case CURLINFO_TEXT:       return 0;  /* skip info text */
        case CURLINFO_HEADER_IN:  prefix = "HEADER_IN";  break;
        case CURLINFO_HEADER_OUT: prefix = "HEADER_OUT"; break;
        case CURLINFO_DATA_IN:    prefix = "DATA_IN";    break;
        case CURLINFO_DATA_OUT:   prefix = "DATA_OUT";   break;
        default: return 0;
    }

    if (type == CURLINFO_HEADER_IN || type == CURLINFO_HEADER_OUT) {
        /* Headers are text - log directly */
        if (g_logfile) {
            EnterCriticalSection(&g_log_cs);
            SYSTEMTIME st;
            GetLocalTime(&st);
            fprintf(g_logfile, "[%04d-%02d-%02d %02d:%02d:%02d.%03d] %s (handle=%p, %zu bytes): ",
                    st.wYear, st.wMonth, st.wDay,
                    st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
                    prefix, handle, size);
            fwrite(data, 1, size, g_logfile);
            /* headers usually end with \r\n, but add newline if not */
            if (size > 0 && data[size-1] != '\n')
                fprintf(g_logfile, "\n");
            fflush(g_logfile);
            LeaveCriticalSection(&g_log_cs);
        }
    } else if (type == CURLINFO_DATA_IN || type == CURLINFO_DATA_OUT) {
        /* Response/request body - log with hex dump */
        log_hex_dump(prefix, handle, data, size);
    }

    return 0;
}

/* ------------------------------------------------------------------ */
/* Install debug callback on a handle                                  */
/* ------------------------------------------------------------------ */
static void install_debug_hooks(void *handle) {
    if (!real_curl_easy_setopt || !handle) return;
    real_curl_easy_setopt(handle, CURLOPT_VERBOSE, 1L);
    real_curl_easy_setopt(handle, CURLOPT_DEBUGFUNCTION, (void*)proxy_debug_callback);
    /* DEBUGDATA not needed since we don't use userptr */
}

/* ------------------------------------------------------------------ */
/* HOOKED: curl_easy_init                                              */
/* ------------------------------------------------------------------ */
__declspec(dllexport) void* proxy_curl_easy_init(void) {
    lazy_init();
    if (!real_curl_easy_init) return NULL;
    void *handle = real_curl_easy_init();
    if (handle) {
        log_write("curl_easy_init() => handle=%p", handle);
        install_debug_hooks(handle);
    }
    return handle;
}

/* ------------------------------------------------------------------ */
/* HOOKED: curl_easy_setopt                                            */
/* On x64, varargs curl_easy_setopt(handle, option, param) effectively */
/* passes: rcx=handle, edx=option, r8=param                           */
/* We capture the 3rd arg as a void* which covers all cases.           */
/* ------------------------------------------------------------------ */
__declspec(dllexport) int proxy_curl_easy_setopt(void *handle, long option, void *param) {
    lazy_init();
    if (!real_curl_easy_setopt) return -1;

    /* Log interesting options */
    if (option == CURLOPT_URL) {
        log_write("curl_easy_setopt(handle=%p, CURLOPT_URL, \"%s\")", handle, (const char*)param);
    } else if (option == CURLOPT_WRITEFUNCTION) {
        log_write("curl_easy_setopt(handle=%p, CURLOPT_WRITEFUNCTION, %p)", handle, param);
    }

    /* Forward the original call */
    int ret = real_curl_easy_setopt(handle, option, param);

    /* Re-install our debug hooks after every setopt to ensure they persist */
    /* (in case the app sets CURLOPT_VERBOSE=0 or overrides DEBUGFUNCTION) */
    if (option != CURLOPT_VERBOSE && option != CURLOPT_DEBUGFUNCTION && option != CURLOPT_DEBUGDATA) {
        install_debug_hooks(handle);
    }

    return ret;
}

/* ------------------------------------------------------------------ */
/* HOOKED: curl_easy_perform - log when requests are actually made     */
/* ------------------------------------------------------------------ */
__declspec(dllexport) int proxy_curl_easy_perform(void *handle) {
    lazy_init();
    if (!real_curl_easy_perform) return -1;
    log_write("curl_easy_perform(handle=%p) START", handle);
    /* Re-install hooks right before perform to be safe */
    install_debug_hooks(handle);
    int ret = real_curl_easy_perform(handle);
    log_write("curl_easy_perform(handle=%p) END => %d", handle, ret);
    return ret;
}

/* ------------------------------------------------------------------ */
/* HOOKED: curl_easy_cleanup - log handle destruction                  */
/* ------------------------------------------------------------------ */
__declspec(dllexport) void proxy_curl_easy_cleanup(void *handle) {
    lazy_init();
    if (!real_curl_easy_cleanup) return;
    log_write("curl_easy_cleanup(handle=%p)", handle);
    real_curl_easy_cleanup(handle);
}

/* ------------------------------------------------------------------ */
/* Assembly wrappers for hooked functions                              */
/* These have the real export names and jump to our proxy_ C functions */
/* This avoids name collision issues with the C compiler.              */
/* ------------------------------------------------------------------ */

/*
 * For hooked functions, we use naked asm that calls our C implementation.
 * We can't use DEFINE_THUNK because those jump to real_* pointers.
 * Instead we use proper C functions with the right names.
 *
 * Actually, let's use a simpler approach: the hooked functions ARE the
 * exports directly. We just need to avoid naming conflicts.
 * Since we define them as dllexport with the correct names in the .def
 * file, we need the C functions to have the exact export names.
 *
 * Strategy: Use asm-level aliases. The .def file maps export names to
 * our internal names.
 */

/* ------------------------------------------------------------------ */
/* NAKED JMP THUNKS for all 82 pass-through functions                  */
/* These forward ALL arguments (registers + stack) transparently.      */
/* ------------------------------------------------------------------ */

/* Safe thunk: calls lazy_init if real pointer is NULL, then jumps */
/* We can't use naked+call combo easily, so use a C wrapper that   */
/* saves/restores volatile regs and forwards via function pointer.  */
/* For variadic/arbitrary arg forwarding on x64, we use asm.        */
#define DEFINE_THUNK(name) \
    void __attribute__((naked)) thunk_##name(void) { \
        __asm__ __volatile__ ( \
            "cmpq $0, %0\n\t" \
            "jne 1f\n\t" \
            /* Save all arg registers */ \
            "push %%rcx\n\t" \
            "push %%rdx\n\t" \
            "push %%r8\n\t" \
            "push %%r9\n\t" \
            "sub $32, %%rsp\n\t" \
            "call lazy_init\n\t" \
            "add $32, %%rsp\n\t" \
            "pop %%r9\n\t" \
            "pop %%r8\n\t" \
            "pop %%rdx\n\t" \
            "pop %%rcx\n\t" \
            "1:\n\t" \
            "jmp *%0\n\t" \
            : : "m"(real_##name) \
        ); \
    }

DEFINE_THUNK(curl_easy_duphandle)
DEFINE_THUNK(curl_easy_escape)
DEFINE_THUNK(curl_easy_getinfo)
DEFINE_THUNK(curl_easy_option_by_id)
DEFINE_THUNK(curl_easy_option_by_name)
DEFINE_THUNK(curl_easy_option_next)
DEFINE_THUNK(curl_easy_pause)
DEFINE_THUNK(curl_easy_recv)
DEFINE_THUNK(curl_easy_reset)
DEFINE_THUNK(curl_easy_send)
DEFINE_THUNK(curl_easy_strerror)
DEFINE_THUNK(curl_easy_unescape)
DEFINE_THUNK(curl_easy_upkeep)
DEFINE_THUNK(curl_escape)
DEFINE_THUNK(curl_formadd)
DEFINE_THUNK(curl_formfree)
DEFINE_THUNK(curl_formget)
DEFINE_THUNK(curl_free)
DEFINE_THUNK(curl_getdate)
DEFINE_THUNK(curl_getenv)
DEFINE_THUNK(curl_global_cleanup)
/* curl_global_init triggers lazy_init - always called first */
/* curl_global_init_mem also triggers lazy_init for safety */
DEFINE_THUNK(curl_global_sslset)
DEFINE_THUNK(curl_maprintf)
DEFINE_THUNK(curl_mfprintf)
DEFINE_THUNK(curl_mime_addpart)
DEFINE_THUNK(curl_mime_data)
DEFINE_THUNK(curl_mime_data_cb)
DEFINE_THUNK(curl_mime_encoder)
DEFINE_THUNK(curl_mime_filedata)
DEFINE_THUNK(curl_mime_filename)
DEFINE_THUNK(curl_mime_free)
DEFINE_THUNK(curl_mime_headers)
DEFINE_THUNK(curl_mime_init)
DEFINE_THUNK(curl_mime_name)
DEFINE_THUNK(curl_mime_subparts)
DEFINE_THUNK(curl_mime_type)
DEFINE_THUNK(curl_mprintf)
DEFINE_THUNK(curl_msnprintf)
DEFINE_THUNK(curl_msprintf)
DEFINE_THUNK(curl_multi_add_handle)
DEFINE_THUNK(curl_multi_assign)
DEFINE_THUNK(curl_multi_cleanup)
DEFINE_THUNK(curl_multi_fdset)
DEFINE_THUNK(curl_multi_info_read)
DEFINE_THUNK(curl_multi_init)
DEFINE_THUNK(curl_multi_perform)
DEFINE_THUNK(curl_multi_poll)
DEFINE_THUNK(curl_multi_remove_handle)
DEFINE_THUNK(curl_multi_setopt)
DEFINE_THUNK(curl_multi_socket)
DEFINE_THUNK(curl_multi_socket_action)
DEFINE_THUNK(curl_multi_socket_all)
DEFINE_THUNK(curl_multi_strerror)
DEFINE_THUNK(curl_multi_timeout)
DEFINE_THUNK(curl_multi_wait)
DEFINE_THUNK(curl_multi_wakeup)
DEFINE_THUNK(curl_mvaprintf)
DEFINE_THUNK(curl_mvfprintf)
DEFINE_THUNK(curl_mvprintf)
DEFINE_THUNK(curl_mvsnprintf)
DEFINE_THUNK(curl_mvsprintf)
DEFINE_THUNK(curl_pushheader_byname)
DEFINE_THUNK(curl_pushheader_bynum)
DEFINE_THUNK(curl_share_cleanup)
DEFINE_THUNK(curl_share_init)
DEFINE_THUNK(curl_share_setopt)
DEFINE_THUNK(curl_share_strerror)
DEFINE_THUNK(curl_slist_append)
DEFINE_THUNK(curl_slist_free_all)
DEFINE_THUNK(curl_strequal)
DEFINE_THUNK(curl_strnequal)
DEFINE_THUNK(curl_unescape)
DEFINE_THUNK(curl_url)
DEFINE_THUNK(curl_url_cleanup)
DEFINE_THUNK(curl_url_dup)
DEFINE_THUNK(curl_url_get)
DEFINE_THUNK(curl_url_set)
DEFINE_THUNK(curl_url_strerror)
DEFINE_THUNK(curl_version)
DEFINE_THUNK(curl_version_info)

/* ------------------------------------------------------------------ */
/* Additional hooked functions for lazy init                           */
/* ------------------------------------------------------------------ */
typedef long (*fn_curl_global_init_t)(long flags);
typedef long (*fn_curl_global_init_mem_t)(long flags, void*, void*, void*, void*, void*);
static fn_curl_global_init_t real_curl_global_init_typed = NULL;
static fn_curl_global_init_mem_t real_curl_global_init_mem_typed = NULL;

__declspec(dllexport) long proxy_curl_global_init(long flags) {
    lazy_init();
    if (!real_curl_global_init_typed) {
        real_curl_global_init_typed = (fn_curl_global_init_t)(void*)real_curl_global_init;
    }
    if (!real_curl_global_init_typed) return -1;
    log_write("curl_global_init(flags=%ld)", flags);
    return real_curl_global_init_typed(flags);
}

__declspec(dllexport) long proxy_curl_global_init_mem(long flags, void *m, void *f, void *r, void *s, void *c) {
    lazy_init();
    if (!real_curl_global_init_mem_typed) {
        real_curl_global_init_mem_typed = (fn_curl_global_init_mem_t)(void*)real_curl_global_init_mem;
    }
    if (!real_curl_global_init_mem_typed) return -1;
    log_write("curl_global_init_mem(flags=%ld)", flags);
    return real_curl_global_init_mem_typed(flags, m, f, r, s, c);
}

/* ------------------------------------------------------------------ */
/* Lazy initialization - avoid LoadLibrary in DllMain (loader lock!)   */
/* ------------------------------------------------------------------ */
static HINSTANCE g_hinstDLL = NULL;
static volatile LONG g_init_done = 0;
static volatile LONG g_init_in_progress = 0;

static void lazy_init(void) {
    /* Double-checked locking */
    if (g_init_done) return;
    if (InterlockedCompareExchange(&g_init_in_progress, 1, 0) != 0) {
        /* Another thread is initializing, spin-wait */
        while (!g_init_done) Sleep(1);
        return;
    }

    log_init();
    log_write("=== libcurl proxy DLL lazy init (PID=%lu) ===", GetCurrentProcessId());

    /* Get directory of this DLL to find libcurl_real.dll alongside it */
    char dllpath[MAX_PATH];
    GetModuleFileNameA(g_hinstDLL, dllpath, MAX_PATH);
    char *slash = strrchr(dllpath, '\\');
    if (!slash) slash = strrchr(dllpath, '/');
    if (slash) *(slash + 1) = '\0';
    strcat(dllpath, "libcurl_real.dll");

    log_write("Loading real DLL from: %s", dllpath);
    g_real_dll = LoadLibraryA(dllpath);
    if (!g_real_dll) {
        log_write("FATAL: Failed to load libcurl_real.dll (error=%lu)", GetLastError());
        g_real_dll = LoadLibraryA("libcurl_real.dll");
    }

    if (g_real_dll) {
        log_write("Real DLL loaded at %p", g_real_dll);
        resolve_all();
        log_write("All function pointers resolved, proxy active");
    } else {
        log_write("FATAL: Could not load libcurl_real.dll at all!");
    }

    InterlockedExchange(&g_init_done, 1);
}

/* ------------------------------------------------------------------ */
/* DllMain - minimal, just save hinstDLL                               */
/* ------------------------------------------------------------------ */
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
    (void)lpReserved;
    if (fdwReason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hinstDLL);
        g_hinstDLL = hinstDLL;
        /* Minimal log in DllMain - just fopen, no LoadLibrary */
        {
            FILE *f = fopen("C:/Users/Administrator/Documents/aion2/curl_capture.log", "w");
            if (f) {
                fprintf(f, "[DllMain] libcurl proxy LOADED (PID=%lu)\n", GetCurrentProcessId());
                fflush(f);
                fclose(f);
            }
        }
    }
    else if (fdwReason == DLL_PROCESS_DETACH) {
        if (g_logfile) {
            fclose(g_logfile);
            g_logfile = NULL;
        }
        if (g_real_dll) {
            FreeLibrary(g_real_dll);
            g_real_dll = NULL;
        }
    }
    return TRUE;
}
