#!/bin/sh
# What the install medium's root shell is for, above its first prompt on the screen and on a
# serial console: the guide's install and recovery, by their first commands.
v="$(sed -n 's/^VERSION_ID=//p' /etc/os-release 2>/dev/null | tr -d '"' | head -1)"
cat <<EOF

Kryptik ${v:+$v }install medium: a root shell.
  lsblk                                          the disks
  kryptik-install --target /dev/sdY --dry-run    the install's plan; nothing is written
  kryptik-recover --disk /dev/sdY --status       an installed disk, read
Every step is in INSTRUCTIONS.md, beside the image on its release page.

EOF
