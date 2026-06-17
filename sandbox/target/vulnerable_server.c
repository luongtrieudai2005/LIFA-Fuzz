/*
 * vulnerable_server_v2.c
 * ──────────────────────────────────────────────────────────────────
 * LIFA-Fuzz Live-Fire Target Server — Version 2
 *
 * ── WHY v1 WAS BROKEN FOR FUZZING RESEARCH ───────────────────────
 *  Problem 1: CRASH TOO EASILY
 *    Any packet with opcode=0x02 and length>32 triggered the crash.
 *    Even a dumb bit-flip fuzzer would stumble into this within
 *    seconds by accident → Baseline A ≈ Baseline C → no paper.
 *
 *  Problem 2: SINGLE-THREADED DEATH
 *    One crash killed the whole server. At 400 EPS, restarts every
 *    few seconds made the campaign unusable.
 *
 * ── WHAT v2 FIXES ────────────────────────────────────────────────
 *  Fix 1: fork() PER CONNECTION
 *    Parent process never dies. Only the child handling the crashing
 *    connection exits. CrashMonitor reads /tmp/lifa_crash_signal.jsonl
 *    (written by parent's SIGCHLD handler) instead of ConnectionRefused.
 *    Optional: parent exits after CRASH_THRESHOLD crashes if you want
 *    to keep the old ConnectionRefused detection.
 *
 *  Fix 2: STATE MACHINE (the critical differentiator)
 *    Connection starts in INIT state. PROCESS_DATA (the vulnerable
 *    opcode) is SILENTLY REJECTED unless the connection is in
 *    AUTHENTICATED state. Only a valid PING transitions INIT → AUTH.
 *
 *    To trigger the crash, the fuzzer MUST execute the sequence:
 *        [new connection] → PING → PROCESS_DATA(overflow)
 *
 *    This means:
 *      Baseline A (dumb, single-packet): P(crash) ≈ 0%
 *        → sends one packet per connection, always lands in INIT
 *        → PROCESS_DATA silently rejected every time
 *
 *      Baseline B (math-only): P(crash) ≈ 0%
 *        → knows magic bytes and length field, but has no semantic
 *           knowledge that PING must come before PROCESS_DATA
 *        → still fails because _execute_sequence() won't know the order
 *
 *      Baseline C (LLM + math): P(crash) ≈ HIGH
 *        → LLM sees PONG responses after PING in traffic log
 *        → infers PING = "authentication step" before PROCESS
 *        → generates [PING, PROCESS_DATA(length=128)] sequence
 *        → crash found reliably
 *
 *  Fix 3: RICHER GRAMMAR (better test for DifferentialAnalyzer)
 *    Header enlarged to 8 bytes. length field is now uint16_le (2
 *    bytes), not uint8. DifferentialAnalyzer should detect:
 *      bytes [0-3]  → STATIC (magic "LIFA")
 *      byte  [4]    → STATIC (version 0x01)
 *      byte  [5]    → LOW_ENTROPY / ENUM (opcode, 4 valid values)
 *      bytes [6-7]  → CALCULATED (Pearson r with packet length)
 *      bytes [8+]   → HIGH_ENTROPY (payload)
 *    LLM should then add DICTIONARY values for opcode [01,02,03,04]
 *    and BOUNDARY_VALUES for the length field.
 *
 *  Fix 4: BUFFER ENLARGED TO 64 BYTES
 *    Harder to accidentally overflow. Requires length > 64, not > 32.
 *
 * ── PROTOCOL v2  (8-byte fixed header) ───────────────────────────
 *  Offset  Bytes  Field    Type        Value
 *  ──────  ─────  ───────  ──────────  ──────────────────────────
 *  0       4      magic    bytes       "LIFA" (0x4C 0x49 0x46 0x41)
 *  4       1      version  uint8       0x01 (must match exactly)
 *  5       1      opcode   enum        see OP_* constants
 *  6       2      length   uint16_le   payload byte count
 *  8       var    payload  bytes       opcode-specific data
 *
 * ── STATE MACHINE (per-connection, in child process) ─────────────
 *
 *         ┌─────────────────────────────────────────────┐
 *         │                                             │
 *         ▼                                             │
 *   ┌───────────┐   OP_PING (valid)   ┌────────────────┴──┐
 *   │   INIT    │ ────────────────►  │  AUTHENTICATED    │
 *   └───────────┘                    └───────────────────┘
 *         ▲                                  │
 *         │         OP_RESET                 │  OP_PROCESS
 *         └──────────────────────────────────┘  (VULNERABLE, then → INIT)
 *
 *   OP_STATUS and unknown opcodes: valid in any state, no transition
 *
 * ── VULNERABILITY ────────────────────────────────────────────────
 *  OP_PROCESS in AUTHENTICATED state, payload_len > 64:
 *    memcpy(buf[64], payload, payload_len)  ← no bounds check
 *    → stack overflow
 *    → NULL function pointer dereference (simulates corrupted vtable)
 *    → SIGSEGV in child process
 *
 * ── CRASH DETECTION (update your CrashMonitor) ───────────────────
 *  Primary:   Poll /tmp/lifa_crash_signal.jsonl
 *             Format: {"pid":N,"sig":11,"crash_num":N,"ts":N}\n
 *  Secondary: After CRASH_THRESHOLD crashes, parent exits →
 *             ConnectionRefusedError (backward compat with old CrashMonitor)
 *
 * ── COMPILE ──────────────────────────────────────────────────────
 *  gcc -O0 -fno-stack-protector -z execstack \
 *      -o vulnerable_server_v2 vulnerable_server_v2.c
 *
 * ── RUN ──────────────────────────────────────────────────────────
 *  ./vulnerable_server_v2          # default port 9000
 *  ./vulnerable_server_v2 9001     # custom port
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* ═══════════════════════════════════════════════════════════════════
 * ASAN runtime options (baked in — no shell/env needed for PID-1).
 * Only active when compiled with -fsanitize=address (__SANITIZE_ADDRESS__).
 *   abort_on_error=1  → SIGABRT (deterministic crash, report printed first)
 *   halt_on_error=1   → stop on first error
 *   symbolize=0       → no llvm-symbolizer in the minimal rootfs (-g still
 *                       gives function+offset); avoids noisy "can't symbolize"
 *   detect_leaks=0    → leak detection needs runtime support we don't ship
 * The report goes to stderr (fd 2) via an unbuffered write() BEFORE abort,
 * so it reaches the serial console (ttyS0) and the fuzzer's crash classifier
 * can detect it as `asan_violation`.
 *
 * NOTE on the v2 vulnerability under ASAN: the child calls
 *   memcpy(buf[64], payload, plen)   with plen > 64   (no bounds check).
 * ASAN intercepts memcpy → catches the stack-buffer-overflow at the memcpy
 * itself → abort_on_error → SIGABRT (exit 134). The NULL function-pointer
 * dereference at the "POST-OVERFLOW SIMULATION" point is therefore never
 * reached under ASAN; the deterministic crash still happens, just earlier
 * and with a detailed report.
 * ═══════════════════════════════════════════════════════════════════ */
#if defined(__SANITIZE_ADDRESS__)
const char *__asan_default_options(void) {
    return "abort_on_error=1:halt_on_error=1:print_stacktrace=1:"
           "detect_leaks=0:allocator_may_return_null=1:symbolize=0";
}
#endif

/* ═══════════════════════════════════════════════════════════════════
 * Protocol constants
 * ═══════════════════════════════════════════════════════════════════ */

static const uint8_t MAGIC[4] = {0x4C, 0x49, 0x46, 0x41};   /* "LIFA" */

#define PROTO_VERSION       0x01
#define HEADER_LEN          8    /* magic(4) + version(1) + opcode(1) + len_le(2) */
#define MAX_PAYLOAD         4096
#define PROCESS_BUF_SIZE    64   /* the vulnerable buffer  ← only 64 bytes! */

/* Client → Server opcodes */
#define OP_PING             0x01  /* Auth handshake — INIT → AUTHENTICATED       */
#define OP_PROCESS          0x02  /* VULNERABLE — only valid in AUTHENTICATED      */
#define OP_STATUS           0x03  /* Query connection state — always valid         */
#define OP_RESET            0x04  /* Return to INIT — always valid                 */

/* Server → Client response opcodes */
#define OP_PONG             0x81  /* Response to PING (echoes payload)             */
#define OP_ACK              0x82  /* Response to PROCESS (safe path) or RESET      */
#define OP_STATUS_RESP      0x83  /* Response to STATUS                            */
#define OP_ERROR            0xFF  /* Error response                                */

/* Error payload byte */
#define ERR_BAD_MAGIC       0x01
#define ERR_BAD_VERSION     0x02
#define ERR_BAD_STATE       0x03  /* right packet, wrong state  */
#define ERR_UNKNOWN_OPCODE  0x04
#define ERR_SHORT_PACKET    0x05

/* Server tuning */
#define DEFAULT_PORT        9000
#define LISTEN_BACKLOG      256   /* large backlog survives fuzzing bursts */
#define RECV_TIMEOUT_SEC    3
#define CRASH_SIGNAL_PATH   "/tmp/lifa_crash_signal.jsonl"
/* LIFA-Fuzz integration: =1 so the parent exits on the FIRST child crash.
 * CrashMonitor detects crashes via VM-exit (is_target_alive checks the
 * Firecracker process returncode), not via the crash signal file. With
 * THRESHOLD=1: child SIGSEGV/SIGABRT → parent exits → VM exits → returncode
 * set → detected. Each crash then triggers a snapshot-restore (~10ms) to a
 * clean VM. fork() per-connection is still useful: the parent survives all
 * SAFE traffic (PING, safe PROCESS, STATUS) between crashes without restart. */
#define CRASH_THRESHOLD     1     /* parent exits after this many unique crashes  */

/* ═══════════════════════════════════════════════════════════════════
 * Per-connection state machine
 * ═══════════════════════════════════════════════════════════════════ */
typedef enum {
    CONN_INIT = 0,
    CONN_AUTHENTICATED
} conn_state_t;

/* ═══════════════════════════════════════════════════════════════════
 * Parent-process global counters  (volatile for signal handler)
 * ═══════════════════════════════════════════════════════════════════ */
static volatile sig_atomic_t g_crash_count = 0;
static volatile sig_atomic_t g_conn_count  = 0;

/* ═══════════════════════════════════════════════════════════════════
 * Helpers
 * ═══════════════════════════════════════════════════════════════════ */

static void hex_print(const char *prefix, const uint8_t *data, size_t len)
{
    fprintf(stdout, "%s", prefix);
    size_t show = len < 24 ? len : 24;
    for (size_t i = 0; i < show; i++)
        fprintf(stdout, "%02x", data[i]);
    if (len > 24)
        fprintf(stdout, "...(+%zu)", len - 24);
    fputc('\n', stdout);
}

/*
 * build_packet — write a server response into buf[].
 * Returns total packet size.
 *
 * Layout:  [MAGIC(4)] [VERSION(1)] [OPCODE(1)] [LEN_LE16(2)] [PAYLOAD(n)]
 */
static size_t build_packet(uint8_t *buf, size_t buf_cap,
                            uint8_t opcode,
                            const uint8_t *payload, uint16_t plen)
{
    if (HEADER_LEN + plen > buf_cap)
        plen = (uint16_t)(buf_cap - HEADER_LEN);

    memcpy(buf, MAGIC, 4);
    buf[4] = PROTO_VERSION;
    buf[5] = opcode;
    buf[6] = (uint8_t)(plen & 0xFF);           /* little-endian */
    buf[7] = (uint8_t)((plen >> 8) & 0xFF);
    if (plen > 0 && payload)
        memcpy(buf + HEADER_LEN, payload, plen);

    return HEADER_LEN + plen;
}

static void send_pkt(int fd, uint8_t opcode,
                      const uint8_t *payload, uint16_t plen)
{
    uint8_t frame[HEADER_LEN + 512];
    size_t n = build_packet(frame, sizeof(frame), opcode, payload, plen);
    send(fd, frame, n, MSG_NOSIGNAL);
}

static void send_error(int fd, uint8_t err_code)
{
    send_pkt(fd, OP_ERROR, &err_code, 1);
}

/* ═══════════════════════════════════════════════════════════════════
 * Connection handler — runs in CHILD PROCESS
 *
 * Parses incoming packets, maintains state machine, dispatches to
 * opcodes, and contains the VULNERABLE OP_PROCESS path.
 * ═══════════════════════════════════════════════════════════════════ */
static void handle_connection(int client_fd, const struct sockaddr_in *addr)
{
    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &addr->sin_addr, ip, sizeof(ip));
    uint16_t port = ntohs(addr->sin_port);

    fprintf(stdout, "[CONN] %s:%u  (pid=%d)\n", ip, port, (int)getpid());
    fflush(stdout);

    /* Per-connection state */
    conn_state_t state      = CONN_INIT;
    int          ping_count = 0;

    uint8_t rx[HEADER_LEN + MAX_PAYLOAD];

    while (1) {
        ssize_t n = recv(client_fd, rx, sizeof(rx), 0);

        if (n == 0) {
            fprintf(stdout, "  [EOF ] client disconnected\n");
            break;
        }
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                fprintf(stdout, "  [TOUT] recv timeout\n");
            else
                fprintf(stdout, "  [ERR ] recv: %s\n", strerror(errno));
            break;
        }

        /* ─────── Basic header validation ─────────────────────────── */
        if (n < HEADER_LEN) {
            fprintf(stdout, "  [DROP] packet too short (%zd B)\n", n);
            send_error(client_fd, ERR_SHORT_PACKET);
            continue;
        }

        /* Magic bytes: must be exactly "LIFA" */
        if (memcmp(rx, MAGIC, 4) != 0) {
            fprintf(stdout, "  [DROP] bad magic\n");
            send_error(client_fd, ERR_BAD_MAGIC);
            continue;
        }

        /* Version: must be 0x01 */
        if (rx[4] != PROTO_VERSION) {
            fprintf(stdout, "  [DROP] bad version 0x%02x\n", rx[4]);
            send_error(client_fd, ERR_BAD_VERSION);
            continue;
        }

        uint8_t  opcode = rx[5];
        uint16_t plen   = (uint16_t)rx[6] | ((uint16_t)rx[7] << 8);   /* LE */
        uint8_t *payload = rx + HEADER_LEN;

        /* Clamp declared length to actual received bytes */
        size_t actual = (size_t)(n - HEADER_LEN);
        if (plen > actual)
            plen = (uint16_t)actual;

        fprintf(stdout, "  [PKT ] state=%-4s  opcode=0x%02x  plen=%u  ",
                state == CONN_INIT ? "INIT" : "AUTH", opcode, plen);
        hex_print("hex=", payload, plen);

        /* ─────── Opcode dispatch ──────────────────────────────────── */
        switch (opcode) {

        /* ────── OP_PING (0x01): Auth handshake ─────────────────────
         *
         * Valid in any state. Transitions INIT → AUTHENTICATED.
         * Returns PONG with echo of payload (useful for LLM to
         * observe the response pattern and infer "PING = auth step").
         *
         * Server response reveals state transition in STATUS:
         *   → LLM can learn: after PING, STATUS.state_byte changes
         */
        case OP_PING: {
            if (state == CONN_INIT) {
                state = CONN_AUTHENTICATED;
                fprintf(stdout, "  [PING] INIT → AUTHENTICATED  (ping #%d)\n",
                        ++ping_count);
            } else {
                fprintf(stdout, "  [PING] already AUTH — ping #%d\n",
                        ++ping_count);
            }
            /* Echo payload back as PONG so fuzzer can observe response */
            send_pkt(client_fd, OP_PONG, payload, plen);
            fprintf(stdout, "  [PONG] sent %u bytes\n", plen);
            break;
        }

        /* ────── OP_PROCESS (0x02): VULNERABLE PATH ─────────────────
         *
         * THE VULNERABILITY:
         *   memcpy(buf[64], payload, plen)  — no bounds check on plen
         *
         * GUARD: state MUST be AUTHENTICATED.
         *   If INIT → silent rejection with ERR_BAD_STATE.
         *
         *   This is the KEY design decision:
         *   Dumb fuzzer  → sends OP_PROCESS on fresh connection (INIT)
         *                → gets ERR_BAD_STATE, never crashes server
         *   Smart fuzzer → infers from traffic that PING must come first
         *                → sends [PING, PROCESS_DATA(len=128)] sequence
         *                → triggers overflow → SIGSEGV in this child
         *
         * POST-OVERFLOW SIMULATION:
         *   A real server would try to USE a corrupted data structure.
         *   We simulate this with a NULL function pointer call, which
         *   reliably produces SIGSEGV regardless of ASLR or stack layout.
         *   Compiled with -fno-stack-protector so there is no canary.
         */
        case OP_PROCESS: {

            /* ── STATE GUARD: this is the barrier for dumb fuzzers ── */
            if (state != CONN_AUTHENTICATED) {
                fprintf(stdout,
                        "  [PROC] REJECTED — not authenticated (state=INIT)\n");
                send_error(client_fd, ERR_BAD_STATE);
                break;
                /*
                 * A dumb fuzzer lands here EVERY TIME because:
                 *   - It sends OP_PROCESS on a fresh connection
                 *   - Fresh connection = INIT state
                 *   - ERR_BAD_STATE returned, no crash, server lives
                 *
                 * A smart fuzzer (with LLM sequence inference) reaches
                 * the code below by first sending OP_PING, observing
                 * the PONG response, then sending OP_PROCESS with a
                 * large payload in the same TCP session.
                 */
            }

            /* Reset state: each PROCESS requires fresh authentication */
            state = CONN_INIT;
            fprintf(stdout,
                    "  [PROC] AUTH → INIT  plen=%u  buf_size=%d\n",
                    plen, PROCESS_BUF_SIZE);

            /* ── VULNERABILITY: stack buffer overflow ────────────── */
            char buf[PROCESS_BUF_SIZE];         /* only 64 bytes */
            memcpy(buf, payload, plen);         /* NO BOUNDS CHECK — intentional */

            if (plen > PROCESS_BUF_SIZE) {
                /*
                 * Stack frame is now corrupted.
                 *
                 * In a real CVE, the server would try to use a
                 * function pointer or vtable that was overwritten by
                 * the overflow. We simulate this deterministically:
                 * call a NULL function pointer that was "stored" in
                 * the buffer region.
                 *
                 * With -fno-stack-protector: no canary to detect this.
                 * With -z execstack: stack is executable (extra attack surface).
                 * Result: SIGSEGV → child exits → parent writes crash signal.
                 */
                fprintf(stdout,
                        "  [VULN] plen=%u > buf=%d — OVERFLOW! "
                        "Dereferencing corrupted pointer...\n",
                        plen, PROCESS_BUF_SIZE);
                fflush(stdout);

                /* Simulate use of a corrupted function pointer */
                void (*corrupted_fn)(const char *, uint32_t) = NULL;
                corrupted_fn(buf, plen);    /* SIGSEGV here */
                /* ^ unreachable — child dies above */
            }

            /* Safe path (plen ≤ 64): acknowledge processing */
            uint8_t ack[3] = {0x00, (uint8_t)plen, (uint8_t)(plen >> 8)};
            send_pkt(client_fd, OP_ACK, ack, sizeof(ack));
            fprintf(stdout,
                    "  [ACK ] processed %u bytes safely (no overflow)\n",
                    plen);
            break;
        }

        /* ────── OP_STATUS (0x03): Query server state ───────────────
         *
         * Returns a 6-byte status payload. Useful for LLM to observe
         * state transitions: state_byte changes from 0x00 to 0x01
         * after a successful PING. This gives the LLM evidence of the
         * state machine without being explicitly told.
         *
         *  Byte 0: conn_state (0x00=INIT, 0x01=AUTH)
         *  Byte 1: ping_count (number of successful PINGs this session)
         *  Byte 2: server version (0x01)
         *  Byte 3: process_buf_size (0x40 = 64, tells fuzzer the threshold)
         *  Byte 4-5: reserved (0x00)
         */
        case OP_STATUS: {
            uint8_t info[6] = {
                (uint8_t)state,             /* 0x00 or 0x01 */
                (uint8_t)ping_count,
                PROTO_VERSION,
                PROCESS_BUF_SIZE,           /* hints at the buffer size! */
                0x00, 0x00,
            };
            send_pkt(client_fd, OP_STATUS_RESP, info, sizeof(info));
            fprintf(stdout,
                    "  [STAT] state=0x%02x  pings=%d  buf_size=%d\n",
                    (uint8_t)state, ping_count, PROCESS_BUF_SIZE);
            break;
        }

        /* ────── OP_RESET (0x04): Return to INIT ────────────────────
         *
         * Allows clean re-authentication. Sends ACK and resets state.
         * Useful for the fuzzer to test state transitions explicitly.
         */
        case OP_RESET: {
            conn_state_t prev = state;
            state = CONN_INIT;
            uint8_t ack = (uint8_t)prev;    /* echo previous state */
            send_pkt(client_fd, OP_ACK, &ack, 1);
            fprintf(stdout,
                    "  [RST ] %s → INIT\n",
                    prev == CONN_INIT ? "INIT" : "AUTH");
            break;
        }

        /* ────── Unknown opcode ──────────────────────────────────── */
        default: {
            fprintf(stdout,
                    "  [WARN] unknown opcode 0x%02x — ignoring\n", opcode);
            send_error(client_fd, ERR_UNKNOWN_OPCODE);
            break;
        }

        } /* switch (opcode) */

        fflush(stdout);
    } /* recv loop */

    close(client_fd);
    fprintf(stdout,
            "[GONE] %s:%u  (pid=%d, final_state=%s)\n",
            ip, port, (int)getpid(),
            state == CONN_INIT ? "INIT" : "AUTH");
    fflush(stdout);
}

/* ═══════════════════════════════════════════════════════════════════
 * SIGCHLD handler — runs in PARENT PROCESS only
 *
 * Called when a child exits (normal or due to SIGSEGV crash).
 * Writes crash metadata to /tmp/lifa_crash_signal.jsonl so that
 * LIFA-Fuzz's CrashMonitor can detect the event.
 *
 * ASYNC-SIGNAL-SAFE: uses only open(2), write(2), close(2).
 * snprintf is technically not AS-safe but is safe in practice on Linux.
 * ═══════════════════════════════════════════════════════════════════ */
static void on_child_exit(int sig)
{
    (void)sig;
    int    wstatus;
    pid_t  pid;

    while ((pid = waitpid(-1, &wstatus, WNOHANG)) > 0) {

        if (!WIFSIGNALED(wstatus))
            continue;   /* normal exit, not a crash */

        int signo = WTERMSIG(wstatus);
        g_crash_count++;

        /* Append one JSON line to the crash signal file */
        int fd = open(CRASH_SIGNAL_PATH,
                      O_WRONLY | O_CREAT | O_APPEND, 0644);
        if (fd >= 0) {
            char line[256];
            int  n = snprintf(line, sizeof(line),
                "{\"pid\":%d,\"sig\":%d,\"sig_name\":\"%s\","
                "\"crash_num\":%d,\"ts\":%ld}\n",
                (int)pid,
                signo,
                signo == 11 ? "SIGSEGV" :
                signo ==  6 ? "SIGABRT" : "OTHER",
                (int)g_crash_count,
                (long)time(NULL));
            if (n > 0)
                write(fd, line, (size_t)n);
            close(fd);
        }
    }
}

/* ═══════════════════════════════════════════════════════════════════
 * main
 * ═══════════════════════════════════════════════════════════════════ */
int main(int argc, char *argv[])
{
    int port = DEFAULT_PORT;
    if (argc > 1) port = atoi(argv[1]);

    /* ── Truncate crash signal file on startup ─────────────────── */
    int init_fd = open(CRASH_SIGNAL_PATH,
                        O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (init_fd >= 0) close(init_fd);

    /* ── Install SIGCHLD handler ───────────────────────────────── */
    struct sigaction sa = {0};
    sa.sa_handler = on_child_exit;
    sigemptyset(&sa.sa_mask);
    /* NO SA_RESTART: when a child crashes, the SIGCHLD handler must interrupt
     * accept() (→ EINTR) so the main loop re-checks CRASH_THRESHOLD and exits.
     * With SA_RESTART, accept() auto-restarts and the parent would hang forever
     * after the first crash, defeating VM-exit crash detection. */
    sa.sa_flags = SA_NOCLDSTOP;
    if (sigaction(SIGCHLD, &sa, NULL) < 0) {
        perror("sigaction"); return 1;
    }

    /* ── Ignore SIGPIPE (broken client connections) ────────────── */
    signal(SIGPIPE, SIG_IGN);

    /* ── Create TCP server socket ──────────────────────────────── */
    int srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv < 0) { perror("socket"); return 1; }

    int opt = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    setsockopt(srv, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));

    struct sockaddr_in bind_addr = {0};
    bind_addr.sin_family      = AF_INET;
    bind_addr.sin_addr.s_addr = INADDR_ANY;
    bind_addr.sin_port        = htons((uint16_t)port);

    if (bind(srv, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) < 0) {
        perror("bind"); close(srv); return 1;
    }
    if (listen(srv, LISTEN_BACKLOG) < 0) {
        perror("listen"); close(srv); return 1;
    }

    fprintf(stdout,
        "╔══════════════════════════════════════════════════════════╗\n"
        "║  LIFA-Fuzz Vulnerable Target Server  v2                  ║\n"
        "╠══════════════════════════════════════════════════════════╣\n"
        "║  Port:       %-5d                                        ║\n"
        "║  Protocol:   LIFA v2 — 8-byte header                     ║\n"
        "║  Header:     magic(4) version(1) opcode(1) len_le16(2)   ║\n"
        "║  Opcodes:    PING=01  PROCESS=02  STATUS=03  RESET=04    ║\n"
        "║  State:      INIT ──[PING]──► AUTH ──[PROCESS]──► INIT  ║\n"
        "║  Vuln:       PROCESS w/ payload > 64B → stack overflow    ║\n"
        "║  Isolation:  fork() per connection — parent never dies    ║\n"
        "║  Crash log:  %-42s ║\n"
        "╚══════════════════════════════════════════════════════════╝\n",
        port, CRASH_SIGNAL_PATH);
    fflush(stdout);

    /* ── Accept loop ───────────────────────────────────────────── */
    while (1) {

        /*
         * Optional backward-compat: after CRASH_THRESHOLD crashes,
         * the parent itself exits. This allows old CrashMonitor code
         * that watches for ConnectionRefusedError to still work.
         * Set CRASH_THRESHOLD to 0 to disable this behaviour.
         */
        if (CRASH_THRESHOLD > 0 &&
            g_crash_count >= (sig_atomic_t)CRASH_THRESHOLD)
        {
            /* A child crashed and CRASH_THRESHOLD is reached. Exit with a
             * NON-ZERO code so the host's CrashMonitor treats this as an
             * actionable crash (exit 0 would be misclassified as a normal
             * shutdown, is_actionable=False, and the crash would be lost).
             * We use exit code 1 (the fuzzer's `unknown`/non-signal crash
             * path, is_actionable=True). The ASAN report from the child was
             * already flushed to ttyS0 before the child abort(), so the
             * fuzzer's serial classifier can also tag it `asan_violation`. */
            fprintf(stdout,
                "[PARENT] %d child crash(es) — exiting (CRASH_THRESHOLD=%d) "
                "to signal crash to fuzzer\n",
                (int)g_crash_count, CRASH_THRESHOLD);
            fflush(stdout);
            close(srv);
            _exit(1);
        }

        struct sockaddr_in cli_addr;
        socklen_t cli_len = sizeof(cli_addr);

        int cli_fd = accept(srv,
                            (struct sockaddr *)&cli_addr, &cli_len);
        if (cli_fd < 0) {
            if (errno == EINTR) continue;   /* interrupted by SIGCHLD */
            perror("accept");
            continue;
        }

        g_conn_count++;

        /* Per-client recv timeout */
        struct timeval tv = { RECV_TIMEOUT_SEC, 0 };
        setsockopt(cli_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        /* ── Fork: child handles the connection ──────────────────
         *
         * If child crashes (SIGSEGV from the vulnerable path),
         * it simply exits with signal. Parent's SIGCHLD handler
         * fires, writes crash signal, and keeps listening.
         * Parent is NEVER affected by client crashes.
         */
        pid_t pid = fork();

        if (pid < 0) {
            perror("fork");
            close(cli_fd);
            continue;
        }

        if (pid == 0) {
            /* ── CHILD PROCESS ── */
            close(srv);                          /* don't need listener */
            handle_connection(cli_fd, &cli_addr);
            close(cli_fd);
            exit(EXIT_SUCCESS);
            /*
             * If SIGSEGV fires inside handle_connection(), the child
             * exits with signal 11 instead of EXIT_SUCCESS.
             * The parent's SIGCHLD handler catches this and writes
             * the crash to /tmp/lifa_crash_signal.jsonl
             */
        }

        /* ── PARENT: close client fd and accept next connection ── */
        close(cli_fd);
    }

    close(srv);
    fprintf(stdout,
        "[PARENT] Done. total_crashes=%d  total_conns=%d\n",
        (int)g_crash_count, (int)g_conn_count);
    return 0;
}