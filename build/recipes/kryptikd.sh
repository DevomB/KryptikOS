#!/usr/bin/env bash

# kryptikd, built outside (no Rust here); its path and hash are arguments, so the stamp covers them.
s_kryptikd() {
    local src="$1" want_sha="${2:-absent}" zones_sha="${3:-nozones}"
    [[ "$src" == "none" ]] && src=""
    echo "requested: ${src:-<none>} (sha256 ${want_sha})"
    echo "zone definitions: ${zones_sha}"

    # Privileged readers use the verified root; the replaceable /etc link serves only `kryptik`.
    install -d -m 0755 /etc/kryptik /usr/lib/kryptik
    install -d -m 0755 /usr/lib/kryptik/zones /usr/lib/kryptik/zones/policy
    if [[ -d "${KRYPTIK_ROOT}/compartments/zones" ]]; then
        install -m 0644 "${KRYPTIK_ROOT}"/compartments/zones/*.toml /usr/lib/kryptik/zones/
        # The seccomp and Landlock policies the zone files name.
        install -m 0644 "${KRYPTIK_ROOT}"/compartments/zones/policy/* /usr/lib/kryptik/zones/policy/
        echo "installed zone definitions and policies:"
        ls -la /usr/lib/kryptik/zones/ /usr/lib/kryptik/zones/policy/
        local z p
        for z in /usr/lib/kryptik/zones/*.toml; do
            for p in $(sed -n 's/^[[:space:]]*\(seccomp\|landlock\)[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\2/p' "$z"); do
                [[ "$p" == /* ]] || p="/usr/lib/kryptik/zones/$p"
                [[ -f "$p" ]] || { echo "FAIL: $(basename "$z") names policy ${p}, which is not installed"; return 1; }
            done
        done
        echo "every policy a zone names is installed"
    else
        echo "no zone definitions at ${KRYPTIK_ROOT}/compartments/zones"
    fi
    if [[ -d /etc/kryptik/zones && ! -L /etc/kryptik/zones ]]; then
        rm -rf /etc/kryptik/zones
    fi
    ln -sfn /usr/lib/kryptik/zones /etc/kryptik/zones

    if [[ -z "$src" ]]; then
        echo "KRYPTIK_KRYPTIKD_BIN is not set: kryptikd was NOT installed."
        echo
        echo "This image has the zone definitions and none of the code that"
        echo "enforces them. Build a static kryptikd outside the chroot and"
        echo "point KRYPTIK_KRYPTIKD_BIN at it:"
        echo
        echo "  cd compartments/kryptikd"
        echo "  cargo build --release --target x86_64-unknown-linux-musl"
        echo "  KRYPTIK_KRYPTIKD_BIN=\$PWD/target/x86_64-unknown-linux-musl/release/kryptikd \\"
        echo "      make system"
        echo
        echo "Recorded as absent, not as installed."
        : > /etc/kryptik/kryptikd-absent
        return 0
    fi

    [[ -f "$src" ]] || { echo "KRYPTIK_KRYPTIKD_BIN=${src} does not exist"; return 1; }

    # The hash was taken outside the chroot; a mismatch means the file changed under the build.
    local got_sha; got_sha="$(sha256_of "$src")"
    if [[ "$want_sha" != "absent" && "$got_sha" != "$want_sha" ]]; then
        echo "kryptikd binary changed during the build:"
        echo "  fingerprinted: ${want_sha}"
        echo "  now:           ${got_sha}"
        return 1
    fi
    echo "sha256: ${got_sha}"

    install -Dm755 "$src" /usr/bin/kryptikd
    rm -f /etc/kryptik/kryptikd-absent

    # It must run here: one linked against the host's libc installs fine and fails at boot.
    echo "--- installed kryptikd ---"
    ls -la /usr/bin/kryptikd
    readelf -l /usr/bin/kryptikd 2>/dev/null | grep 'Requesting program interpreter' \
        || echo "  (static binary, no interpreter - good)"
    # --help exits 0 and touches nothing; `check` would probe the build host's kernel.
    /usr/bin/kryptikd --help > /dev/null || {
        echo "FAIL: the installed kryptikd does not run inside the target."
        echo "A binary built against the host's libc installs fine and fails here."
        return 1
    }
    echo "kryptikd --help: ok"

    # And it must parse the zone definitions it will boot with.
    if /usr/bin/kryptikd list --zones /usr/lib/kryptik/zones; then
        echo "kryptikd parses the installed zone definitions"
    else
        echo "FAIL: kryptikd cannot read /usr/lib/kryptik/zones"
        return 1
    fi

    # The user's command (tools/kryptik), beside the daemon it wraps.
    install -m 0755 "${KRYPTIK_ROOT}/tools/kryptik" /usr/bin/kryptik
    bash -n /usr/bin/kryptik || { echo "FAIL: /usr/bin/kryptik has a syntax error"; return 1; }
    echo "installed /usr/bin/kryptik (sha256 ${4:-unknown})"
}
