#!/usr/bin/env bash
#
# Does this system's C library actually unwind?
#
# glibc implements pthread_exit(), pthread_cancel() and backtrace() by dlopening
# libgcc_s.so.1 at the moment it needs them and forcing a stack unwind through
# it. If the loader cannot then tell the unwinder which object an address
# belongs to, libgcc gives up with a bare abort() - no message, no diagnostic,
# just SIGABRT. A whole class of ordinary programs dies that way.
#
# That is not hypothetical. It is why the Kryptik kernel build failed at the
# final link: scripts/sorttable ends its sorter threads with pthread_exit(),
# and the only thing the log said was "Failed to sort kernel tables".
#
# Run this inside the chroot, or on a booted Kryptik system. It needs a
# compiler; without one it skips (77) rather than claiming a pass.
#
set -uo pipefail

CC="${CC:-cc}"
pass=0; fail=0
work=""

cleanup() { [[ -n "$work" && -d "$work" ]] && rm -rf "$work"; }
trap cleanup EXIT INT TERM

ok()   { printf '  ok   %s\n' "$*"; pass=$((pass + 1)); }
bad()  { printf '  FAIL %s\n' "$*"; fail=$((fail + 1)); }
note() { printf '       %s\n' "$*"; }

command -v "$CC" >/dev/null 2>&1 || {
    echo "no compiler ($CC) - cannot test the unwinder"
    exit 77
}

work="$(mktemp -d)" || { echo "mktemp failed"; exit 1; }
cd "$work" || exit 1

# Every probe runs with no controlling terminal and with glibc's fatal messages
# forced to stderr. Without both, a glibc diagnostic goes to /dev/tty and never
# reaches the log - which is exactly how this defect stayed invisible.
# `setsid` without -w forks and exits 0 when it is already a process-group
# leader, which would throw away the child's exit status and make every probe
# look like it passed. Prefer -w; the abort() control below catches it either
# way, but a harness should not depend on a control to notice it is lying.
SETSID=(setsid)
if setsid -w true >/dev/null 2>&1; then
    SETSID=(setsid -w)
fi

run_probe() {
    "${SETSID[@]}" env LIBC_FATAL_STDERR_=1 "$@" </dev/null >probe.out 2>&1
}

echo "=== the harness can tell a failure from a pass (positive controls) ==="

cat > ctl_ok.c <<'EOF'
int main(void) { return 0; }
EOF
cat > ctl_abort.c <<'EOF'
#include <stdlib.h>
int main(void) { abort(); }
EOF

if "$CC" -O0 -o ctl_ok ctl_ok.c 2>cc.log && "$CC" -O0 -o ctl_abort ctl_abort.c 2>>cc.log; then
    run_probe ./ctl_ok
    [[ $? -eq 0 ]] && ok "a program that returns 0 is seen as passing" \
                   || bad "a program that returns 0 was seen as failing"
    run_probe ./ctl_abort
    if [[ $? -ne 0 ]]; then
        ok "a program that abort()s is seen as failing"
    else
        bad "a deliberate abort() was seen as passing - this harness proves nothing"
    fi
else
    bad "could not build the controls"
    sed 's/^/       /' cc.log
fi

echo
echo "=== the unwinder itself ==="

cat > pexit.c <<'EOF'
#include <pthread.h>
#include <stdio.h>
static void *worker(void *a) { (void) a; pthread_exit(NULL); }
int main(void) {
    pthread_t t;
    if (pthread_create(&t, NULL, worker, NULL) != 0) return 2;
    pthread_join(t, NULL);
    puts("ok");
    return 0;
}
EOF

cat > pcancel.c <<'EOF'
#include <pthread.h>
#include <stdio.h>
#include <unistd.h>
static void *worker(void *a) { (void) a; for (;;) pause(); return NULL; }
int main(void) {
    pthread_t t;
    if (pthread_create(&t, NULL, worker, NULL) != 0) return 2;
    usleep(100000);
    pthread_cancel(t);
    void *r;
    pthread_join(t, &r);
    return r == PTHREAD_CANCELED ? 0 : 3;
}
EOF

cat > bt.c <<'EOF'
#define _GNU_SOURCE
#include <execinfo.h>
#include <stdio.h>
int main(void) {
    void *b[32];
    int n = backtrace(b, 32);
    printf("%d\n", n);
    return n > 0 ? 0 : 4;
}
EOF

probe() {
    local tag="$1" src="$2"; shift 2
    if ! "$CC" -O0 -g -o "${src%.c}" "$src" "$@" 2>cc.log; then
        bad "${tag}: did not compile"
        sed 's/^/       /' cc.log
        return
    fi
    run_probe "./${src%.c}"
    local rc=$?
    if [[ $rc -eq 0 ]]; then
        ok "${tag}"
    else
        bad "${tag}: exited ${rc}"
        [[ -s probe.out ]] && sed 's/^/       /' probe.out
        [[ $rc -eq 134 ]] && note "SIGABRT with no message is the signature of" \
                          && note "libgcc's unwinder failing to find its own FDEs."
    fi
}

probe "pthread_exit() from a thread"  pexit.c   -lpthread
probe "pthread_cancel() a thread"     pcancel.c -lpthread
probe "backtrace() returns frames"    bt.c

echo
echo "=== why, if the above failed: which object does the loader blame? ==="

cat > dlfo.c <<'EOF'
#define _GNU_SOURCE
#include <dlfcn.h>
#include <link.h>
#include <stdio.h>
#include <string.h>
/* _dl_find_object is what libgcc's unwinder asks "which object holds this
   address, and where is its .eh_frame". Ask it about a library loaded after
   startup - the case that matters, because that is how glibc loads libgcc_s. */
int main(void) {
    void *h = dlopen("libgcc_s.so.1", RTLD_NOW | RTLD_GLOBAL);
    if (h == NULL) { printf("dlopen failed: %s\n", dlerror()); return 1; }
    void *sym = dlsym(h, "_Unwind_ForcedUnwind");
    if (sym == NULL) { printf("no _Unwind_ForcedUnwind\n"); return 1; }
    struct dl_find_object d;
    memset(&d, 0, sizeof d);
    if (_dl_find_object(sym, &d) != 0) { printf("NOT FOUND\n"); return 2; }
    struct link_map *m = d.dlfo_link_map;
    printf("%s\n", (m != NULL && m->l_name[0] != '\0') ? m->l_name : "<main program>");
    return 0;
}
EOF

if "$CC" -O0 -o dlfo dlfo.c 2>cc.log; then
    run_probe ./dlfo
    blamed="$(cat probe.out 2>/dev/null)"
    case "$blamed" in
        *libgcc_s.so.1)
            ok "_dl_find_object attributes a dlopened object correctly"
            ;;
        *)
            bad "_dl_find_object blames the wrong object for a dlopened address"
            note "it answered: ${blamed:-<nothing>}"
            note "expected a path ending in libgcc_s.so.1."
            note "The unwinder trusts this answer, reads that object's"
            note ".eh_frame, finds no FDE for the address, and aborts."
            ;;
    esac
else
    bad "the _dl_find_object probe did not compile"
    sed 's/^/       /' cc.log
fi

echo
echo "passed ${pass}, failed ${fail}"
[[ "$fail" -eq 0 ]] || {
    echo
    echo "This system cannot unwind through a library loaded after startup."
    echo "Programs affected: anything calling pthread_exit, pthread_cancel or"
    echo "backtrace() that does not already link libgcc_s.so.1. They die on"
    echo "SIGABRT with no message. See build/BLOCKER.md."
    exit 1
}
