#!/usr/bin/env bash
# For the update suite, as root in the guest: a zone granted the probe image's call runs
# /usr/bin/kryptik-probe from the image the running root's list names, wherever that list came from.
# Prints one line: "IMAGE-PROBE <what the probe printed>", or "IMAGE-PROBE FAILED <why>".
set -u
d=/root/zt/image-probe
mkdir -p "$d/policy"
printf 'allow-syscall mlockall\n' > "$d/policy/probe.seccomp"
cat > "$d/upimg.toml" <<'EOF'
[zone]
name = "upimg"
description = "software image check"
[network]
mode = "none"
[storage]
mode = "ephemeral"
size = "64M"
[policy]
seccomp = "policy/probe.seccomp"
[software]
images = "probe"
[identity]
uid_base = 4128768
[ui]
border_color = "#0a1b5c"
EOF
out="$(timeout -k 5 60 /usr/bin/kryptikd run upimg --zones "$d" --rootfs /var/lib/kryptik/zones -- /usr/bin/kryptik-probe 2>&1)"
line="$(grep -m1 '^kryptik-probe 1.0, from the probe image: ' <<<"$out")"
if [[ -n "$line" ]]; then
    echo "IMAGE-PROBE $line"
else
    echo "IMAGE-PROBE FAILED $(tail -3 <<<"$out" | tr '\n' ' ')"
fi
