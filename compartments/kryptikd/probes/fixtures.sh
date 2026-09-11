#!/usr/bin/env bash
# Synthetic zone fixtures for the kryptikd boundary probes.
#
# Everything here is disposable and contains no secret, real or pretend: the
# payloads are the literal strings a check greps for. Sourced by
# boundary-checks.sh, which exports $F (the fixture root) and expects
# $F/zones, $F/zones/policy and $F/roots to exist.
#
# The zones are named for what they exercise, not for anything shipped:
# compartments/zones/*.toml are the real ones and are never written here.
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

# probe: the ordinary zone almost every check runs in. No policy file, so it
# gets the base seccomp allowlist and CAP_NET_BIND_SERVICE only.
zone probe \
    '[zone]' 'name = "probe"' \
    '[network]' 'mode = "routed"' \
    '[storage]' 'mode = "ephemeral"' 'size = "64M"' \
    '[transfer]' 'to = "packet"' \
    '[ui]' 'border_color = "#123456"'

# packet: the transfer destination, and the zone whose policy allows the
# AF_PACKET socket family without keeping any capability - so the socket
# passes seccomp and is then refused by the kernel, which is the point.
zone packet \
    '[zone]' 'name = "packet"' \
    '[network]' 'mode = "none"' \
    '[storage]' 'mode = "ephemeral"' 'size = "64M"' \
    '[policy]' 'seccomp = "policy/packet.seccomp"' \
    '[ui]' 'border_color = "#654321"'
printf '%s\n' \
    '# Synthetic: the socket family is allowed, no capability is kept.' \
    'allow-socket AF_PACKET' > "$F/zones/policy/packet.seccomp"

# capped: declares [limits]. On a host that cannot create cgroups this zone
# must be REFUSED, and the refusal must name [limits].
zone capped \
    '[zone]' 'name = "capped"' \
    '[network]' 'mode = "none"' \
    '[storage]' 'mode = "ephemeral"' 'size = "64M"' \
    '[limits]' 'memory_max = "256M"' 'pids_max = 64' \
    '[ui]' 'border_color = "#abcdef"'

# keeper: persistent storage - a plain directory, kept between launches.
zone keeper \
    '[zone]' 'name = "keeper"' \
    '[network]' 'mode = "none"' \
    '[storage]' 'mode = "persistent"' \
    '[ui]' 'border_color = "#fedcba"'

# sealed: declares encryption, which is not implemented, so it must refuse
# to start rather than run on a plain directory.
zone sealed \
    '[zone]' 'name = "sealed"' \
    '[network]' 'mode = "none"' \
    '[storage]' 'mode = "encrypted"' 'volume = "/dev/null"' \
    '[ui]' 'border_color = "#0f0f0f"'

# nicholder: owns the NIC. Unprivileged nothing is moved; it is here so the
# policy rules that depend on NIC ownership have a zone to apply to.
zone nicholder \
    '[zone]' 'name = "nicholder"' \
    '[network]' 'mode = "nic"' 'bridge = "kryptik0"' \
    '[storage]' 'mode = "ephemeral"' 'size = "64M"' \
    '[policy]' 'seccomp = "policy/nic.seccomp"' \
    '[ui]' 'border_color = "#00ff88"'
printf '%s\n' \
    '# Synthetic: what a NIC-owning zone is allowed to keep.' \
    'allow-socket AF_PACKET' \
    'keep-capability CAP_NET_RAW' \
    'keep-capability CAP_NET_ADMIN' > "$F/zones/policy/nic.seccomp"

# routedraw: the refusal case for the rule above - a zone that does not own
# the NIC may not keep CAP_NET_RAW, whatever its policy file says.
zone routedraw \
    '[zone]' 'name = "routedraw"' \
    '[network]' 'mode = "routed"' \
    '[storage]' 'mode = "ephemeral"' 'size = "64M"' \
    '[policy]' 'seccomp = "policy/nic.seccomp"' \
    '[ui]' 'border_color = "#ff0088"'

# nopolicy: names a policy file that does not exist. A missing policy is a
# refusal, never a silent fallback to the base rules.
zone nopolicy \
    '[zone]' 'name = "nopolicy"' \
    '[network]' 'mode = "none"' \
    '[storage]' 'mode = "ephemeral"' 'size = "64M"' \
    '[policy]' 'seccomp = "policy/absent.seccomp"' \
    '[ui]' 'border_color = "#333333"'

# narrowed: a zone whose Landlock policy file grants read everywhere and
# write only in /tmp and /dev - so its own HOME, which the base rules make
# writable, becomes read-only. The second layer can only subtract.
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

# badfs: a Landlock policy the parser must refuse. There is no deny
# directive, because Landlock grants rather than subtracts.
zone badfs \
    '[zone]' 'name = "badfs"' \
    '[network]' 'mode = "none"' \
    '[storage]' 'mode = "ephemeral"' 'size = "64M"' \
    '[policy]' 'landlock = "policy/badfs.landlock"' \
    '[ui]' 'border_color = "#998877"'
printf '%s\n' 'deny /tmp' > "$F/zones/policy/badfs.landlock"

# relfs: a Landlock policy naming a relative path, which would be resolved
# against whatever the launcher's cwd happened to be.
zone relfs \
    '[zone]' 'name = "relfs"' \
    '[network]' 'mode = "none"' \
    '[storage]' 'mode = "ephemeral"' 'size = "64M"' \
    '[policy]' 'landlock = "policy/relfs.landlock"' \
    '[ui]' 'border_color = "#887799"'
printf '%s\n' 'read-exec /' 'read-write tmp' > "$F/zones/policy/relfs.landlock"

# badpolicy: a policy file that tries to re-allow something on the denied
# list. The parser must refuse it.
zone badpolicy \
    '[zone]' 'name = "badpolicy"' \
    '[network]' 'mode = "none"' \
    '[storage]' 'mode = "ephemeral"' 'size = "64M"' \
    '[policy]' 'seccomp = "policy/bad.seccomp"' \
    '[ui]' 'border_color = "#444444"'
printf '%s\n' \
    '# Synthetic: ptrace is on the denied list and may not be re-allowed.' \
    'allow-syscall ptrace' > "$F/zones/policy/bad.seccomp"
