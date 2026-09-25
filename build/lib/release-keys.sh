# shellcheck shell=bash
# The keys an image is signed with and the anchor it trusts. Sourced by stage
# 06, which runs on the host: no private key is ever inside the chroot, where
# every upstream build script runs as root.
#
#   release_keys ROLE   sets ANCHOR, RELEASE_KEY, LATEST_KEY, SB_KEY, SB_CERT
#
# development: developer keys under ${KRYPTIK_WORK}/keys, made when missing.
# production: KRYPTIK_KEYS names the key medium, a directory holding
#   release-signers, kryptik-release and kryptik-release.pub, kryptik-sb.key,
#   kryptik-sb.crt and, optionally, kryptik-latest and kryptik-latest.pub.
#   Nothing is made. Every file is checked before any is used, and the private
#   keys are read only by the tools that sign with them, by path.

release_keys() {
    case "$1" in
        development) dev_keys ;;
        production) medium_keys ;;
        *) die "KRYPTIK_ROLE=$1: an image is development or production" ;;
    esac
}

dev_keys() {
    local rel="${KRYPTIK_WORK}/keys/release" sb="${KRYPTIK_WORK}/keys/sb" k
    mkdir -p "$rel" "$sb"; chmod 0700 "$rel" "$sb"
    for k in kryptik-release kryptik-latest; do
        if [[ ! -f "${rel}/${k}" ]]; then
            ssh-keygen -q -t ed25519 -N "" -C "${k} (developer)" -f "${rel}/${k}" < /dev/null
            echo "generated a new developer key: ${k}"
        fi
    done
    # Each key honoured in its own namespace only, so the one kept at hand for
    # re-signing the channel's statement can never sign a release.
    {
        printf 'kryptik-release namespaces="kryptik-release" %s\n' "$(cut -d' ' -f1,2 "${rel}/kryptik-release.pub")"
        printf 'kryptik-latest namespaces="kryptik-latest" %s\n' "$(cut -d' ' -f1,2 "${rel}/kryptik-latest.pub")"
    } > "${rel}/release-signers"
    if [[ ! -f "${sb}/kryptik-sb.key" ]]; then
        openssl req -new -x509 -newkey rsa:3072 -nodes -days 3650 -sha256 \
            -subj "/CN=Kryptik developer Secure Boot key/" \
            -keyout "${sb}/kryptik-sb.key" -out "${sb}/kryptik-sb.crt" 2>/dev/null
        chmod 0600 "${sb}/kryptik-sb.key"
        openssl x509 -in "${sb}/kryptik-sb.crt" -outform DER -out "${sb}/kryptik-sb.der"
        cat > "${sb}/README" <<'EOF'
DEVELOPER Secure Boot key. Generated on the build host, not escrowed, not
rotated, enrolled only into disposable OVMF variable stores. It proves the
boot chain enforces a key and that Kryptik's kernels are bound to one. It is
not a production certificate and must never be enrolled in real firmware.
EOF
        echo "generated a new developer Secure Boot key"
    fi
    ANCHOR="${rel}/release-signers"; RELEASE_KEY="${rel}/kryptik-release"; LATEST_KEY="${rel}/kryptik-latest"
    # shellcheck disable=SC2034  # read by stage 06
    SB_KEY="${sb}/kryptik-sb.key" SB_CERT="${sb}/kryptik-sb.crt"
    probe_anchor
}

# A probe signed by each developer key and by a foreign one, in each namespace,
# verified through the anchor: only release/kryptik-release and
# latest/kryptik-latest may pass. The production keys sign nothing but what
# they are for, so this runs for development alone.
probe_anchor() {
    local t key ns want got
    t="$(mktemp -d)"
    ssh-keygen -q -t ed25519 -N "" -f "$t/foreign" < /dev/null
    printf 'probe\n' > "$t/probe"
    for key in "$RELEASE_KEY" "$LATEST_KEY" "$t/foreign"; do
        for ns in kryptik-release kryptik-latest; do
            want=refused
            if [[ "$key:$ns" == "$RELEASE_KEY:kryptik-release" || "$key:$ns" == "$LATEST_KEY:kryptik-latest" ]]; then
                want=accepted
            fi
            rm -f "$t/probe.sig"
            # A refusal counts only when there was a signature to refuse.
            if ! ssh-keygen -Y sign -f "$key" -n "$ns" "$t/probe" < /dev/null > /dev/null 2>&1 || [[ ! -s "$t/probe.sig" ]]; then
                rm -rf "$t"; die "could not sign a probe with ${key##*/} in ${ns}"
            fi
            got=refused
            if ssh-keygen -Y verify -f "$ANCHOR" -I "$ns" -n "$ns" -s "$t/probe.sig" < "$t/probe" > /dev/null 2>&1; then
                got=accepted
            fi
            [[ "$got" == "$want" ]] || { rm -rf "$t"; die "${ANCHOR} ${got} a probe signed by ${key##*/} in ${ns}"; }
        done
    done
    rm -rf "$t"
}

medium_keys() {
    local m="${KRYPTIK_KEYS:-}" w f
    [[ -n "$m" ]] || die "a production image is signed only with keys it is handed: set KRYPTIK_KEYS to the key medium"
    [[ -d "$m" ]] || die "KRYPTIK_KEYS=${m} is not a directory"
    m="$(cd "$m" && pwd -P)"
    for w in "${KRYPTIK_WORK:-}" "${KRYPTIK_OUT:-}"; do
        [[ -n "$w" && -d "$w" ]] || continue
        w="$(cd "$w" && pwd -P)"
        [[ "$m/" != "$w/"* ]] || die "KRYPTIK_KEYS=${m} is inside ${w}: production keys never live in the build's trees"
    done
    for f in release-signers kryptik-release kryptik-release.pub kryptik-sb.key kryptik-sb.crt; do
        [[ -f "${m}/${f}" ]] || die "the key medium ${m} has no ${f}"
    done
    if [[ -e "${m}/kryptik-latest" && ! -f "${m}/kryptik-latest.pub" ]]; then
        die "the key medium ${m} has kryptik-latest but no kryptik-latest.pub"
    fi
    for f in release-signers kryptik-release kryptik-release.pub kryptik-latest kryptik-latest.pub kryptik-sb.key kryptik-sb.crt; do
        [[ ! -L "${m}/${f}" ]] || die "${m}/${f} is a symlink: the medium holds its files itself"
    done
    for f in kryptik-release kryptik-latest kryptik-sb.key; do
        if [[ -e "${m}/${f}" ]]; then private_ok "${m}/${f}"; fi
    done
    anchor_ok "${m}/release-signers"
    pub_in_anchor "${m}/kryptik-release.pub" kryptik-release "${m}/release-signers"
    if [[ -e "${m}/kryptik-latest" ]]; then
        pub_in_anchor "${m}/kryptik-latest.pub" kryptik-latest "${m}/release-signers"
    fi
    openssl x509 -in "${m}/kryptik-sb.crt" -noout -checkend 0 > /dev/null 2>&1 \
        || die "${m}/kryptik-sb.crt is not a certificate in force"
    ANCHOR="${m}/release-signers"; RELEASE_KEY="${m}/kryptik-release"; LATEST_KEY=""
    if [[ -e "${m}/kryptik-latest" ]]; then LATEST_KEY="${m}/kryptik-latest"; fi
    # shellcheck disable=SC2034  # read by stage 06
    SB_KEY="${m}/kryptik-sb.key" SB_CERT="${m}/kryptik-sb.crt"
}

# A private key readable by its owner alone, who is root or whoever ran the
# build: said early and by name, before ssh-keygen or sbsign meets it.
private_ok() {
    local mode owner who="${SUDO_UID:-$EUID}"
    mode="$(stat -c %a "$1")"; owner="$(stat -c %u "$1")"
    (( (8#$mode & 8#077) == 0 )) || die "$1 is mode ${mode}: a private key is readable by its owner alone"
    [[ "$owner" == 0 || "$owner" == "$who" ]] || die "$1 belongs to uid ${owner}, not to root or the user running the build (${who})"
}

# Exactly kryptik-release and kryptik-latest, each held to its own namespace,
# with two different Ed25519 keys (a security key's included).
anchor_ok() {
    local a="$1" p ns t k seen="" keys=""
    while read -r p ns t k _; do
        case "$p" in ""|"#"*) continue ;; esac
        case "$p" in kryptik-release|kryptik-latest) ;; *) die "${a}: ${p} is neither kryptik-release nor kryptik-latest" ;; esac
        [[ " $seen " != *" $p "* ]] || die "${a}: ${p} is listed twice"
        [[ "$ns" == "namespaces=\"${p}\"" ]] || die "${a}: ${p} is not held to its own namespace (namespaces=\"${p}\")"
        case "$t" in ssh-ed25519|sk-ssh-ed25519@openssh.com) ;; *) die "${a}: ${p}'s key is ${t}, not Ed25519" ;; esac
        [[ " $keys " != *" $k "* ]] || die "${a}: kryptik-release and kryptik-latest are the same key"
        seen+=" $p"; keys+=" $k"
    done < "$a"
    [[ "$seen" == *kryptik-release* && "$seen" == *kryptik-latest* ]] || die "${a}: it must list both kryptik-release and kryptik-latest"
}

# The public half beside a private key is the one the anchor lists for WHO.
pub_in_anchor() {   # pub_in_anchor PUB WHO ANCHOR
    local pub line
    pub="$(cut -d' ' -f1,2 "$1")"
    line="$(awk -v p="$2" '$1 == p { print $3, $4; exit }' "$3")"
    [[ -n "$pub" && "$pub" == "$line" ]] || die "$1 is not the key ${3} lists for $2"
}
