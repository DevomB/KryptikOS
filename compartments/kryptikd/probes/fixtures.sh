#!/usr/bin/env bash
# Synthetic zones for boundary-checks.sh, under $F (zones/, zones/policy/, roots/; removed on exit).
set -u

F="$(mktemp -d -t kryptik-probe-XXXXXX)"
export F
# shellcheck disable=SC2064
trap "rm -rf '$F'" EXIT

mkdir -p "$F/zones/policy" "$F/roots"

zone() { # zone NAME BODY...
    local name="$1"; shift
    printf '%s\n' "$@" > "$F/zones/$name.toml"
    mkdir -p "$F/roots/$name"
}

# probe: where most checks run, with no policy file: the base allowlist and CAP_NET_BIND_SERVICE.
zone probe \
    '[zone]' 'name = "probe"' \
    '[network]' 'mode = "routed"' \
    '[storage]' 'mode = "ephemeral"' 'size = "64M"' \
    '[transfer]' 'to = "packet"' \
    '[ui]' 'border_color = "#123456"'

# packet: the transfer destination, allowed AF_PACKET but no capability, so the kernel refuses it.
zone packet \
    '[zone]' 'name = "packet"' \
    '[network]' 'mode = "none"' \
    '[storage]' 'mode = "ephemeral"' 'size = "64M"' \
    '[policy]' 'seccomp = "policy/packet.seccomp"' \
    '[transfer]' 'max_bytes = 16' \
    '[ui]' 'border_color = "#654321"'
printf '%s\n' \
    '# Synthetic: the socket family is allowed, no capability is kept.' \
    'allow-socket AF_PACKET' > "$F/zones/policy/packet.seccomp"

# capped: declares [limits], which must be refused where cgroups cannot be created.
zone capped \
    '[zone]' 'name = "capped"' \
    '[network]' 'mode = "none"' \
    '[storage]' 'mode = "ephemeral"' 'size = "64M"' \
    '[limits]' 'memory_max = "256M"' 'pids_max = 64' \
    '[ui]' 'border_color = "#abcdef"'

# keeper: persistent storage, a plain directory kept between launches.
zone keeper \
    '[zone]' 'name = "keeper"' \
    '[network]' 'mode = "none"' \
    '[storage]' 'mode = "persistent"' \
    '[ui]' 'border_color = "#fedcba"'

# sealed: encrypted storage must refuse to start, never fall back to a plain directory.
zone sealed \
    '[zone]' 'name = "sealed"' \
    '[network]' 'mode = "none"' \
    '[storage]' 'mode = "encrypted"' 'volume = "/dev/null"' \
    '[ui]' 'border_color = "#0f0f0f"'

# nicholder: the NIC owner every zone set needs; it names no interface, so none is moved.
zone nicholder \
    '[zone]' 'name = "nicholder"' \
    '[network]' 'mode = "nic"' \
    '[storage]' 'mode = "ephemeral"' 'size = "64M"' \
    '[policy]' 'seccomp = "policy/nic.seccomp"' \
    '[ui]' 'border_color = "#00ff88"'
printf '%s\n' \
    '# Synthetic: what a NIC-owning zone is allowed to keep.' \
    'allow-socket AF_PACKET' \
    'keep-capability CAP_NET_RAW' \
    'keep-capability CAP_NET_ADMIN' > "$F/zones/policy/nic.seccomp"

# routedraw: does not own the NIC, so it may not keep CAP_NET_RAW whatever its policy says.
zone routedraw \
    '[zone]' 'name = "routedraw"' \
    '[network]' 'mode = "routed"' \
    '[storage]' 'mode = "ephemeral"' 'size = "64M"' \
    '[policy]' 'seccomp = "policy/nic.seccomp"' \
    '[ui]' 'border_color = "#ff0088"'

# nopolicy: a missing policy file is a refusal, never a fallback to the base rules.
zone nopolicy \
    '[zone]' 'name = "nopolicy"' \
    '[network]' 'mode = "none"' \
    '[storage]' 'mode = "ephemeral"' 'size = "64M"' \
    '[policy]' 'seccomp = "policy/absent.seccomp"' \
    '[ui]' 'border_color = "#333333"'

# narrowed: its Landlock policy grants write only in /tmp and /dev, so its HOME is read-only.
zone narrowed \
    '[zone]' 'name = "narrowed"' \
    '[network]' 'mode = "none"' \
    '[storage]' 'mode = "ephemeral"' 'size = "64M"' \
    '[policy]' 'landlock = "policy/narrowed.landlock"' \
    '[ui]' 'border_color = "#778899"'
printf '%s\n' \
    '# Synthetic: read anywhere, write only where a scratch file belongs.' \
    'read-exec  /' \
    'read-write /tmp' \
    'read-write /dev' > "$F/zones/policy/narrowed.landlock"

# swapped: can replace work/bin with a link to HOME, which its next start must refuse, not follow.
zone swapped \
    '[zone]' 'name = "swapped"' \
    '[network]' 'mode = "none"' \
    '[storage]' 'mode = "persistent"' \
    '[policy]' 'landlock = "policy/swapped.landlock"' \
    '[ui]' 'border_color = "#556677"'
mkdir -p "$F/roots/swapped/work/bin"
printf '%s\n' \
    '# Synthetic: HOME read-only but for work; exec only in work/bin.' \
    'read-exec       /' \
    'read-write      /tmp' \
    'read-write      /dev' \
    'read-write      /home/swapped/work' \
    'read-write-exec /home/swapped/work/bin' > "$F/zones/policy/swapped.landlock"

# badfs: Landlock only grants, so there is no deny directive to parse.
zone badfs \
    '[zone]' 'name = "badfs"' \
    '[network]' 'mode = "none"' \
    '[storage]' 'mode = "ephemeral"' 'size = "64M"' \
    '[policy]' 'landlock = "policy/badfs.landlock"' \
    '[ui]' 'border_color = "#998877"'
printf '%s\n' 'deny /tmp' > "$F/zones/policy/badfs.landlock"

# relfs: a relative Landlock path would resolve against the launcher's cwd.
zone relfs \
    '[zone]' 'name = "relfs"' \
    '[network]' 'mode = "none"' \
    '[storage]' 'mode = "ephemeral"' 'size = "64M"' \
    '[policy]' 'landlock = "policy/relfs.landlock"' \
    '[ui]' 'border_color = "#887799"'
printf '%s\n' 'read-exec /' 'read-write tmp' > "$F/zones/policy/relfs.landlock"

# badpolicy: re-allows something on the denied list, which must be refused.
zone badpolicy \
    '[zone]' 'name = "badpolicy"' \
    '[network]' 'mode = "none"' \
    '[storage]' 'mode = "ephemeral"' 'size = "64M"' \
    '[policy]' 'seccomp = "policy/bad.seccomp"' \
    '[ui]' 'border_color = "#444444"'
printf '%s\n' \
    '# Synthetic: ptrace is on the denied list and may not be re-allowed.' \
    'allow-syscall ptrace' > "$F/zones/policy/bad.seccomp"
