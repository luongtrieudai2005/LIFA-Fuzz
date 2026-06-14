/* gcov_flush.c — force-flush gcov .gcda on signal.
 *
 * Problem: LightFTP's main() is an infinite server loop with no signal
 * handler, so it never calls exit(). gcov only writes .gcda on exit()
 * (atexit handler) — a signal-terminated server leaves NO coverage data.
 *
 * Fix: a gcc constructor installs a SIGTERM/SIGINT handler that calls
 * __gcov_dump() (the gcov-runtime flush, gcc >= 11) then _exit(). Linking
 * this object into fftp means `kill -TERM/-INT <fftp-pid>` reliably produces
 * .gcda at the baked absolute object path, ready for `docker cp` + lcov.
 *
 * Compiled with the same -fprofile-arcs -ftest-coverage as fftp.
 */
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern void __gcov_dump(void);  /* gcc >= 11; resolves to the linked gcov runtime */

static void _gcov_on_signal(int sig) {
    (void)sig;
    __gcov_dump();   /* write .gcda to the guest page cache */
    sync();          /* flush page cache → virtio-block → backing rootfs ext4.
                      * Without this, the guest panics on PID-1 exit (panic=1)
                      * before the kernel syncs, and .gcda never reaches the
                      * host's ext4 file. */
    /* For crash signals (SIGABRT/SIGSEGV) we have already flushed .gcda above
     * — that is the coverage goal. We then _exit(0). NOTE: the raise() below
     * is effectively a no-op for termination — the signal is blocked during
     * its own handler (default sa_mask) and _exit(0) wins. So a crash shows
     * up as a clean exit(0) from the OS's view. That is FINE for coverage
     * mode (we only care that .gcda was flushed; crashes aren't counted there).
     * It would be WRONG for the production fuzzer — but this handler is only
     * linked into the coverage build, never production. */
    if (sig == SIGABRT || sig == SIGSEGV) {
        struct sigaction dfl;
        memset(&dfl, 0, sizeof(dfl));
        dfl.sa_handler = SIG_DFL;
        sigaction(sig, &dfl, NULL);
        raise(sig);  /* pending (blocked); _exit below terminates first */
    }
    _exit(0);
}

__attribute__((constructor))
static void _install_gcov_flush_handler(void) {
    struct sigaction sa;
    sa.sa_handler = _gcov_on_signal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    /* SIGTERM/SIGINT: graceful (timer / CtrlAltDel). SIGABRT: ASAN abort on
     * memory error. SIGSEGV: illegal access. Catching the latter two lets a
     * REPLAY flush .gcda even when a mutation crashes ffp — so the coverage
     * of the crashing segment survives and accumulates across restarts. */
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGABRT, &sa, NULL);
    sigaction(SIGSEGV, &sa, NULL);
}
