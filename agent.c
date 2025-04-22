#include <nyx.h>

#include <dlfcn.h>
#include <execinfo.h>
#include <inttypes.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

// afl++ coverage bit map
__attribute__((weak)) extern uint8_t* __afl_area_ptr;
__attribute__((weak)) extern uint32_t __afl_map_size;
// afl++ auto dictionary
__attribute__((weak)) extern uint32_t __afl_dictionary_len;
__attribute__((weak)) extern uint8_t* __afl_dictionary;

uint8_t* __nyx_bitcoin_trace_buffer = NULL;
uint32_t __nyx_bitcoin_trace_buffer_size = 0;

void initialize_crash_handling();

/** Initiliazes the nyx agent and returns the maximum size for generated fuzz
 * inputs. */
size_t nyx_init()
{
    static int done = 0;
    (void)__builtin_expect(done, 0);
    done = 1;

    initialize_crash_handling();

    host_config_t host_config;
    kAFL_hypercall(HYPERCALL_KAFL_GET_HOST_CONFIG, (uintptr_t)&host_config);

    if (host_config.host_magic != NYX_HOST_MAGIC) {
        habort(
            "Error: NYX_HOST_MAGIC not found in host configuration - You are "
            "probably using an outdated version of QEMU-Nyx...");
    }

    if (host_config.host_version != NYX_HOST_VERSION) {
        habort(
            "Error: NYX_HOST_VERSION not found in host configuration - You are "
            "probably using an outdated version of QEMU-Nyx...");
    }

    hprintf("[capablities] host_config.bitmap_size: 0x%" PRIx64 "\n",
            host_config.bitmap_size);
    hprintf("[capablities] host_config.ijon_bitmap_size: 0x%" PRIx64 "\n",
            host_config.ijon_bitmap_size);
    hprintf("[capablities] host_config.payload_buffer_size: 0x%" PRIx64 "x\n",
            host_config.payload_buffer_size);

    __nyx_bitcoin_trace_buffer =
        mmap((void*)NULL, host_config.bitmap_size, PROT_READ | PROT_WRITE,
             MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    memset(__nyx_bitcoin_trace_buffer, 0, host_config.bitmap_size);
    __nyx_bitcoin_trace_buffer_size = host_config.bitmap_size;

    agent_config_t agent_config = {0};

    agent_config.agent_magic = NYX_AGENT_MAGIC;
    agent_config.agent_version = NYX_AGENT_VERSION;
    agent_config.agent_timeout_detection = (uint8_t)0;
    agent_config.agent_tracing = (uint8_t)1;
    agent_config.trace_buffer_vaddr = (uintptr_t)__nyx_bitcoin_trace_buffer;
    agent_config.agent_ijon_tracing = 0;
    agent_config.ijon_trace_buffer_vaddr = (uintptr_t)NULL;
    agent_config.agent_non_reload_mode = (uint8_t)0; // changed from 1 to 0?

    kAFL_hypercall(HYPERCALL_KAFL_SET_AGENT_CONFIG, (uintptr_t)&agent_config);

    // Copy afl++ auto dictionary to host (if available)
    if (&__afl_dictionary_len && &__afl_dictionary &&
        __afl_dictionary_len && __afl_dictionary) {
        mlock((void*)__afl_dictionary, (size_t)__afl_dictionary_len);
        kafl_dump_file_t file_obj = {0};
        file_obj.file_name_str_ptr = (uintptr_t) "afl_autodict.txt";
        file_obj.append = 1;
        file_obj.bytes = __afl_dictionary_len;
        file_obj.data_ptr = (uintptr_t)__afl_dictionary;
        kAFL_hypercall(HYPERCALL_KAFL_DUMP_FILE, (uintptr_t)(&file_obj));
        munlock((void*)__afl_dictionary, (size_t)__afl_dictionary_len);
    }

    return host_config.payload_buffer_size;
}

/** Copies the next fuzz input into `data` and returns the new size of the
 * input.
 *
 * Note: This will take the snapshot on the first call. */
size_t nyx_get_fuzz_data(const uint8_t* data, size_t max_size)
{
    kAFL_payload* payload_buffer = mmap(NULL, max_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    mlock(payload_buffer, max_size);
    memset(payload_buffer, 0, max_size);

    // Register payload buffer
    kAFL_hypercall(HYPERCALL_KAFL_GET_PAYLOAD, (uintptr_t)payload_buffer);
    hprintf("[init] payload buffer is mapped at %p (size: 0x%lx)\n", payload_buffer, max_size);
    // Take snapshot
    kAFL_hypercall(HYPERCALL_KAFL_USER_SUBMIT_MODE, KAFL_MODE_64);
    kAFL_hypercall(HYPERCALL_KAFL_USER_FAST_ACQUIRE, 0);

    __nyx_bitcoin_trace_buffer[0] = 1;

    // Copy payload buffer into data
    memcpy((void*)data, payload_buffer->data, payload_buffer->size);

    return payload_buffer->size;
}

/** Resets the vm to the snapshot state. */
void nyx_release()
{
    // TODO this is hacky and slow
    memcpy(__nyx_bitcoin_trace_buffer, __afl_area_ptr, __nyx_bitcoin_trace_buffer_size);
    kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);
}

/** printf from inside the nyx vm. */
void nyx_printf(const char* format, ...)
{
    va_list args;
    va_start(args, format);
    hprintf(format, args);
    va_end(args);
}

/** Crash handling.
 *
 * We catch aborts, asserts and crash signals, and call
 * HYPERCALL_KAFL_PANIC_EXTENDED (with a backtrace as message) to let nyx know
 * that a crash has occured. */

#define MAX_BACKTRACE_SIZE 50
void panic_with_backtrace(const char* extra_msg)
{
    void* backtrace_buffer[MAX_BACKTRACE_SIZE];
    int backtrace_size = backtrace(backtrace_buffer, MAX_BACKTRACE_SIZE);

    char** symbolized_backtrace = backtrace_symbols(backtrace_buffer, backtrace_size);

    char panic_msg[0x1000];
    memset(panic_msg, 0, 0x1000);

    char* current = panic_msg;
    current += sprintf(current, "%s\n", "====== BACKTRACE ======");

    if (backtrace_size == MAX_BACKTRACE_SIZE) {
        current += sprintf(current, "(%s)\n", "backtrace may be truncated");
    }

    if (extra_msg != NULL) {
        current += sprintf(current, "Reason: %s\n", extra_msg);
    }

    for (int i = 0; i < backtrace_size; ++i) {
        current += sprintf(current, "%s\n", symbolized_backtrace[i]);
    }

    kAFL_hypercall(HYPERCALL_KAFL_PANIC_EXTENDED, (uintptr_t)panic_msg);
}

#define OVERRIDE_ABORT(abort_name)     \
    void abort_name(void)              \
    {                                  \
        panic_with_backtrace("abort"); \
        while (1) {                    \
        }                              \
    }

OVERRIDE_ABORT(abort)
OVERRIDE_ABORT(_abort)
OVERRIDE_ABORT(__abort)

void __assert(const char* func, const char* file, int line, const char* failed_expr)
{
    char signal_msg[0x1000];
    memset(signal_msg, 0, 0x1000);
    sprintf(signal_msg, "assertion failed: \"%s\" in %s (%s:%d)", failed_expr, func, file, line);
    panic_with_backtrace(signal_msg);
}
void __assert_fail(const char* assertion, const char* file, unsigned int line, const char* function)
{
    char signal_msg[0x1000];
    memset(signal_msg, 0, 0x1000);
    sprintf(signal_msg, "assertion failed: \"%s\" in %s (%s:%d)", assertion, function, file, line);
    panic_with_backtrace(signal_msg);
}
void __assert_perror_fail(int errnum, const char* file, unsigned int line, const char* function)
{
    char signal_msg[0x1000];
    memset(signal_msg, 0, 0x1000);
    sprintf(signal_msg, "assert_perror: in %s (%s:%d)", function, file, line);
    panic_with_backtrace(signal_msg);
}

/** Targets are not allowed to set their own sig handler for some signals as
 * that otherwise interfers with our crash handling ability.
 *
 * TODO: this will not work for some sanitizers (e.g. ASan). */
int sigaction(int signum, const struct sigaction* act, struct sigaction* oldact)
{
    int (*_sigaction)(int signum, const struct sigaction* act, struct sigaction* oldact) = dlsym(RTLD_NEXT, "sigaction");

    switch (signum) {
    /* forbidden signals */
    case SIGFPE:
    case SIGILL:
    case SIGBUS:
    case SIGABRT:
    case SIGTRAP:
    case SIGSYS:
    case SIGSEGV:
        hprintf("[warning] Target attempts to install own SIG: %d handler (ignoring)\n", signum);
        return 0;
    default:
        return _sigaction(signum, act, oldact);
    }
}

void fault_handler(int signo, siginfo_t* info, void* extra)
{
    char signal_msg[0x1000];
    memset(signal_msg, 0, 0x1000);
    sprintf(signal_msg, "caught signal: %d\n", signo);

    panic_with_backtrace(signal_msg);
}

void initialize_crash_handling()
{
    struct sigaction action;
    action.sa_flags = SA_SIGINFO;
    action.sa_sigaction = fault_handler;

    // We need to call the actual `sigaction` to register our handlers.
    int (*_sigaction)(int signum, const struct sigaction* act, struct sigaction* oldact) = dlsym(RTLD_NEXT, "sigaction");

    if (_sigaction(SIGSEGV, &action, NULL) == -1) {
        hprintf("sigsegv: sigaction");
        _exit(1);
    }
    if (_sigaction(SIGFPE, &action, NULL) == -1) {
        hprintf("sigfpe: sigaction");
        _exit(1);
    }
    if (_sigaction(SIGBUS, &action, NULL) == -1) {
        hprintf("sigbus: sigaction");
        _exit(1);
    }
    if (_sigaction(SIGILL, &action, NULL) == -1) {
        hprintf("sigill: sigaction");
        _exit(1);
    }
    if (_sigaction(SIGABRT, &action, NULL) == -1) {
        hprintf("sigabrt: sigaction");
        _exit(1);
    }
    if (_sigaction(SIGIOT, &action, NULL) == -1) {
        hprintf("sigiot: sigaction");
        _exit(1);
    }
    if (_sigaction(SIGTRAP, &action, NULL) == -1) {
        hprintf("sigiot: sigaction");
        _exit(1);
    }
    if (_sigaction(SIGSYS, &action, NULL) == -1) {
        hprintf("sigsys: sigaction");
        _exit(1);
    }
}
