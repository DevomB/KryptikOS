#!/usr/bin/env bash
# Synthetic zones for the kryptikd boundary probes, sourced by boundary-checks.sh.
# Exports $F, a temporary root (removed on exit) holding zones/, zones/policy/
# and roots/. Nothing here is secret; payloads are the strings a check greps for.
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

# probe: the ordinary zone most checks run in. No policy file: base seccomp
# allowlist and CAP_NET_BIND_SERVICE only.
zone probe \
    '[zone]' 'name = "probe"' \
    '[network]' 'mode = "routed"' \
    '[storage]' 'mode = "ephemeral"' 'size = "64M"' \
    '[transfer]' 'to = "packet"' \
    '[ui]' 'border_color = "#123456"'

# packet: the transfer destination. Its policy allows AF_PACKET but keeps no
# capability, so the socket passes seccomp and the kernel refuses it.
zone packet \
    '[zone]' 'name = "packet"' \
    '[network]' 'mode = "none"' \
    '[storage]' 'mode = "ephemeral"' 'size = "64M"' \
    '[policy]' 'seccomp = "policy/packet.seccomp"' \
    '[ui]' 'border_color = "#654321"'
printf '%s\n' \
    '# Synthetic: the socket family is allowed, no capability is kept.' \
    'allow-socket AF_PACKET' > "$F/zones/policy/packet.seccomp"

# capped: declares [limits]. Where cgroups cannot be created it must be
# refused, naming [limits].
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

# sealed: encrypted storage must refuse to start, never fall back to a plain
# directory.
zone sealed \
    '[zone]' 'name = "sealed"' \
    '[network]' 'mode = "none"' \
    '[storage]' 'mode = "encrypted"' 'volume = "/dev/null"' \
    '[ui]' 'border_color = "#0f0f0f"'

# nicholder: the NIC owner every zone set needs, and the zone NIC-only policy
# rules apply to. It names no interface, so none is moved.
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

# routedraw: a zone that does not own the NIC may not keep CAP_NET_RAW,
# whatever its policy says.
zone routedraw \
    '[zone]' 'name = "routedraw"' \
    '[network]' 'mode = "routed"' \
    '[storage]' 'mode = "ephemeral"' 'size = "64M"' \
    '[policy]' 'seccomp = "policy/nic.seccomp"' \
    '[ui]' 'border_color = "#ff0088"'

# nopolicy: a missing policy file is a refusal, never a fallback to the base
# rules.
zone nopolicy \
    '[zone]' 'name = "nopolicy"' \
    '[network]' 'mode = "none"' \
    '[storage]' 'mode = "ephemeral"' 'size = "64M"' \
    '[policy]' 'seccomp = "policy/absent.seccomp"' \
    '[ui]' 'border_color = "#333333"'

# narrowed: Landlock grants read everywhere and write only in /tmp and /dev,
# so its HOME becomes read-only; the second layer can only subtract.
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
