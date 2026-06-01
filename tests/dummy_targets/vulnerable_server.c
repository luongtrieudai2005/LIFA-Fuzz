/*
 * tests/dummy_targets/vulnerable_server.c
 * ────────────────────────────────────────────
 * Deliberately vulnerable stateful TCP server for E2E fuzzing tests.
 *
 * Protocol (stateful, two-step handshake):
 *   1. Client sends "HELLO\n"  → Server responds "OK\n"
 *   2. Client sends payload    → Server responds "BYE\n" and closes
 *
 * Crash triggers (SIGSEGV via null-pointer dereference):
 *   - Payload contains the string "CRASH_ME"
 *   - Payload length exceeds 1024 bytes
 *
 * Compile:
 *   gcc -o vulnerable_server vulnerable_server.c -Wall -Wextra -O0 -g
 *
 * Run:
 *   ./vulnerable_server 9999
 *
 * Exit codes:
 *   139 = SIGSEGV (crash triggered)
 *    0  = clean shutdown (SIGTERM)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define MAX_PAYLOAD 4096
#define CRASH_THRESHOLD 1024

static volatile int running = 1;

static void handle_sigterm(int sig) {
    (void)sig;
    running = 0;
}

static void handle_connection(int client_fd) {
    char buf[MAX_PAYLOAD + 1];
    ssize_t n;

    /* Step 1: Read HELLO */
    memset(buf, 0, sizeof(buf));
    n = read(client_fd, buf, MAX_PAYLOAD);
    if (n <= 0) {
        close(client_fd);
        return;
    }

    /* Verify HELLO handshake */
    if (strncmp(buf, "HELLO", 5) != 0) {
        write(client_fd, "ERROR\n", 6);
        close(client_fd);
        return;
    }

    /* Respond OK */
    write(client_fd, "OK\n", 3);

    /* Step 2: Read payload */
    memset(buf, 0, sizeof(buf));
    n = read(client_fd, buf, MAX_PAYLOAD);
    if (n <= 0) {
        close(client_fd);
        return;
    }

    /* ── Crash triggers ─────────────────────────────────────── */

    /* Trigger 1: payload contains "CRASH_ME" */
    if (memmem(buf, n, "CRASH_ME", 8) != NULL) {
        /* Null-pointer dereference → SIGSEGV */
        int *p = NULL;
        *p = 0xDEAD;
        /* Unreachable */
    }

    /* Trigger 2: payload exceeds threshold */
    if (n > CRASH_THRESHOLD) {
        /* Null-pointer dereference → SIGSEGV */
        int *p = NULL;
        *p = 0xDEAD;
        /* Unreachable */
    }

    /* Normal response */
    write(client_fd, "BYE\n", 4);
    close(client_fd);
}

int main(int argc, char *argv[]) {
    int port = 9999;
    int server_fd, client_fd;
    struct sockaddr_in addr;
    int opt = 1;

    if (argc > 1) {
        port = atoi(argv[1]);
    }
    if (port <= 0 || port > 65535) {
        fprintf(stderr, "Usage: %s [port]\n", argv[0]);
        return 1;
    }

    /* Use sigaction without SA_RESTART so that accept() returns EINTR
     * when SIGTERM arrives.  Plain signal() on Linux sets SA_RESTART,
     * which causes accept() to auto-restart — the process never re-
     * evaluates the `while (running)` loop and hangs forever. */
    {
        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = handle_sigterm;
        /* Deliberately do NOT set SA_RESTART */
        sigaction(SIGTERM, &sa, NULL);
    }

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket");
        return 1;
    }

    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);

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

    printf("Vulnerable server listening on 127.0.0.1:%d (PID=%d)\n", port, getpid());
    fflush(stdout);

    while (running) {
        client_fd = accept(server_fd, NULL, NULL);
        if (client_fd < 0) continue;

        /* Handle connection in-process (no fork).
         * When a crash occurs, the whole process dies — which is exactly
         * what the E2E test needs to verify crash detection. */
        handle_connection(client_fd);
    }

    close(server_fd);
    printf("Server shutting down\n");
    return 0;
}
