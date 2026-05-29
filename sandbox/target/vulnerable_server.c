/*
 * vulnerable_server.c
 * ─────────────────────
 * Deliberately vulnerable TCP server for LIFA-Fuzz live-fire testing.
 *
 * Protocol (LIFA binary protocol):
 *   Bytes 0-3:  Magic Bytes  "LIFA"  (0x4C 0x49 0x46 0x41)
 *   Byte  4:    Opcode
 *               0x01 = PING         → reply with PONG + same payload
 *               0x02 = PROCESS_DATA → copy payload to stack buffer
 *   Byte  5:    Payload Length (uint8)
 *   Bytes 6+:   Payload data
 *
 * VULNERABILITY:
 *   Opcode 0x02 (PROCESS_DATA) copies the payload into a fixed 32-byte
 *   stack buffer using memcpy(buf, payload, length) WITHOUT checking
 *   if length > 32.  This is a classic stack buffer overflow.
 *
 *   A fuzzed packet with opcode=0x02 and length > 32 will corrupt
 *   the stack frame → SIGSEGV on return (with -fno-stack-protector).
 *
 * Compile (inside Docker):
 *   gcc -O0 -fno-stack-protector -z execstack -o server vulnerable_server.c
 *
 * Run:
 *   ./server
 *   # Listens on TCP port 9000
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* ── Protocol Constants ─────────────────────────────────────────── */
#define MAGIC       "LIFA"                      /* 0x4C 0x49 0x46 0x41 */
#define MAGIC_LEN   4
#define HEADER_LEN  6                            /* magic(4) + opcode(1) + length(1) */

#define OPCODE_PING         0x01
#define OPCODE_PROCESS      0x02

#define DEFAULT_PORT        9000
#define MAX_RECV            4096
#define RECV_TIMEOUT_SEC    5

/* The vulnerable buffer size — deliberately small */
#define PROCESS_BUF_SIZE    32

/* ── Helpers ─────────────────────────────────────────────────────── */

static void hexdump(const unsigned char *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        fprintf(stdout, "%02x", data[i]);
    }
}

/*
 * handle_packet — process one parsed packet.
 *
 * Returns:
 *   0  on success (packet processed normally)
 *  -1  if the connection should be closed
 *
 * BUG: The PROCESS_DATA path does not validate length against
 *      PROCESS_BUF_SIZE.  If length > 32, memcpy overflows the
 *      stack buffer, corrupting the return address.
 */
static int handle_packet(const unsigned char *packet, size_t pkt_len,
                         int client_fd)
{
    if (pkt_len < HEADER_LEN) {
        fprintf(stdout, "  [RECV] Packet too short (%zu bytes), ignoring\n",
                pkt_len);
        return 0;
    }

    /* Verify magic */
    if (memcmp(packet, MAGIC, MAGIC_LEN) != 0) {
        fprintf(stdout, "  [RECV] Bad magic (expected LIFA), ignoring\n");
        return 0;
    }

    unsigned char opcode   = packet[4];
    unsigned char payload_len = packet[5];
    const unsigned char *payload = packet + HEADER_LEN;

    /* Sanity: actual payload bytes available */
    size_t actual_payload = pkt_len - HEADER_LEN;
    if (actual_payload < (size_t)payload_len) {
        payload_len = (unsigned char)actual_payload;
    }

    fprintf(stdout, "  [RECV] opcode=0x%02x  length=%u  payload=",
            opcode, payload_len);
    hexdump(payload, payload_len);
    fprintf(stdout, "\n");

    switch (opcode) {

    /* ── PING → respond with PONG ──────────────────────────────── */
    case OPCODE_PING: {
        unsigned char response[HEADER_LEN + 256];
        memcpy(response, MAGIC, MAGIC_LEN);
        response[4] = 0x01;              /* PONG opcode */
        response[5] = payload_len;
        if (payload_len > 0) {
            memcpy(response + HEADER_LEN, payload, payload_len);
        }
        send(client_fd, response, HEADER_LEN + payload_len, 0);
        fprintf(stdout, "  [SEND] PONG (%u bytes payload)\n", payload_len);
        break;
    }

    /* ── PROCESS_DATA → VULNERABLE PATH ───────────────────────────
     *
     * BUG: We copy `payload_len` bytes into a 32-byte stack buffer
     *      without checking if payload_len > PROCESS_BUF_SIZE.
     *
     *      memcpy overflow corrupts the stack.  On modern x86_64 the
     *      corrupted return address may land in mapped memory, so the
     *      process doesn't always crash on return.  To make the crash
     *      deterministic (essential for fuzz testing), we simulate
     *      what a REAL vulnerable server does after the overflow:
     *      dereference a pointer that was stored in the buffer region
     *      which got corrupted by the overflow.
     *
     *      This is exactly how real CVEs work — the overflow corrupts
     *      a function pointer or data pointer, and the server crashes
     *      when it tries to USE that corrupted pointer.
     *
     *      Compiled with -fno-stack-protector so there is no canary.
     */
    case OPCODE_PROCESS: {
        char buffer[PROCESS_BUF_SIZE];   /* ← only 32 bytes! */

        /* VULNERABILITY: no bounds check on payload_len vs 32 */
        memcpy(buffer, payload, payload_len);  /* overflow if payload_len > 32 */

        /*
         * POST-OVERFLOW CRASH: A real server would try to "process"
         * the data. We simulate this by calling a function pointer
         * stored just past the buffer. When the overflow corrupts
         * this pointer, the call jumps to a bad address → SIGSEGV.
         *
         * This is realistic: many CVEs involve corrupted vtable
         * pointers or callback function pointers on the stack.
         */
        if (payload_len > PROCESS_BUF_SIZE) {
            /* The overflow corrupted the stack. Simulate a real
             * server that tries to use a corrupted function pointer
             * or data pointer that was stored after the buffer. */
            fprintf(stdout, "  [PROC] Buffer overflow detected (%u > %d) — "
                    "dereferencing corrupted pointer...\n",
                    payload_len, PROCESS_BUF_SIZE);
            fflush(stdout);

            /* Store a function pointer on the stack right after the buffer.
             * The overflow has already happened, so this simulates the
             * server trying to use a pointer that was in the buffer region
             * and got corrupted by the overflow. */
            void (*process_callback)(const char *, unsigned int) = NULL;

            /* The overflow wrote past buffer[]. In a real vulnerability,
             * this would corrupt this function pointer. We check if
             * the overflow touched our stack frame and if so, crash. */
            if (process_callback == NULL) {
                /* Null function pointer dereference → SIGSEGV */
                process_callback(buffer, payload_len);
            }
        } else {
            /* Safe path — normal processing */
            fprintf(stdout, "  [PROC] first_byte=0x%02x  copied=%u into %d-byte buffer\n",
                    (unsigned char)buffer[0], payload_len, PROCESS_BUF_SIZE);
        }

        /* Acknowledge */
        unsigned char ack[HEADER_LEN];
        memcpy(ack, MAGIC, MAGIC_LEN);
        ack[4] = 0x02;
        ack[5] = 0x00;
        send(client_fd, ack, HEADER_LEN, 0);
        fprintf(stdout, "  [SEND] ACK\n");
        break;
    }

    default:
        fprintf(stdout, "  [WARN] Unknown opcode 0x%02x, ignoring\n", opcode);
        break;
    }

    fflush(stdout);
    return 0;
}

/* ── Connection Handler ──────────────────────────────────────────── */

static void handle_connection(int client_fd,
                              struct sockaddr_in *client_addr)
{
    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &client_addr->sin_addr, ip, sizeof(ip));
    unsigned short port = ntohs(client_addr->sin_port);

    fprintf(stdout, "[CONN] New connection from %s:%d\n", ip, port);
    fflush(stdout);

    unsigned char buf[MAX_RECV];

    while (1) {
        ssize_t n = recv(client_fd, buf, sizeof(buf), 0);
        if (n <= 0) {
            if (n == 0) {
                fprintf(stdout, "[CONN] Client disconnected (%s:%d)\n", ip, port);
            } else {
                fprintf(stdout, "[CONN] recv error: %s\n", strerror(errno));
            }
            break;
        }

        fprintf(stdout, "[CONN] %s:%d — %zd bytes: ", ip, port, n);
        hexdump(buf, (size_t)n);
        fprintf(stdout, "\n");
        fflush(stdout);

        handle_packet(buf, (size_t)n, client_fd);
    }

    close(client_fd);
}

/* ── Main ────────────────────────────────────────────────────────── */

int main(void)
{
    int server_fd;
    struct sockaddr_in addr;
    int opt = 1;

    /* Create TCP socket */
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket");
        return 1;
    }

    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons(DEFAULT_PORT);

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(server_fd);
        return 1;
    }

    if (listen(server_fd, 10) < 0) {
        perror("listen");
        close(server_fd);
        return 1;
    }

    fprintf(stdout, "╔══════════════════════════════════════════════╗\n");
    fprintf(stdout, "║  LIFA-Fuzz Vulnerable Target Server          ║\n");
    fprintf(stdout, "║  Listening on 0.0.0.0:%d                     ║\n", DEFAULT_PORT);
    fprintf(stdout, "║  Protocol: LIFA binary                       ║\n");
    fprintf(stdout, "║  Vulnerability: PROCESS_DATA stack overflow  ║\n");
    fprintf(stdout, "║  Buffer size: %d bytes (no bounds check)     ║\n", PROCESS_BUF_SIZE);
    fprintf(stdout, "╚══════════════════════════════════════════════╝\n");
    fflush(stdout);

    /*
     * NOTE: Single-threaded, no fork.
     *
     * We deliberately do NOT fork() so that a crash in handle_packet
     * kills the entire process.  This is essential for the fuzzer's
     * CrashMonitor to detect the crash via Docker container exit.
     *
     * A forking server would only crash the child — the parent would
     * stay alive and the CrashMonitor would never notice.
     */
    while (1) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_fd = accept(server_fd,
                               (struct sockaddr *)&client_addr,
                               &client_len);
        if (client_fd < 0) {
            perror("accept");
            continue;
        }

        /* Set recv timeout */
        struct timeval tv;
        tv.tv_sec  = RECV_TIMEOUT_SEC;
        tv.tv_usec = 0;
        setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        handle_connection(client_fd, &client_addr);
    }

    close(server_fd);
    return 0;
}
