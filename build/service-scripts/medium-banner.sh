#!/bin/sh
# What the install medium's root shell is for, above its first prompt on the screen and on a
# serial console: the guide's install and recovery, by their first commands, and whether the
# firmware checked the kernel's signature, which boot-smoke tells only the serial console.
v="$(sed -n 's/^VERSION_ID=//p' /etc/os-release 2>/dev/null | tr -d '"' | head -1)"
case "$(od -An -tu1 -j4 -N1 /sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c 2>/dev/null | tr -d ' ')" in
    1) sb="on: the firmware checked this kernel's signature" ;;
    0) sb="off" ;;
    *) sb="unknown (no SecureBoot variable)" ;;
esac
cat <<EOF

Kryptik ${v:+$v }install medium: a root shell. Secure Boot is ${sb}.
  lsblk                                          the disks
  kryptik-install --target /dev/sdY --dry-run    the install's plan; nothing is written
  kryptik-recover --disk /dev/sdY --status       an installed disk, read
Every step is in INSTRUCTIONS.md, beside the image on its release page.

EOF
