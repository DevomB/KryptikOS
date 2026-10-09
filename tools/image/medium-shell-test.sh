#!/usr/bin/env bash
# The install medium's console is a root shell: whoever boots it types
# kryptik-install there. Every suite installs through a control disk, so this
# is the one that types: a command runs as root, the installer and the
# recovery tool are found by name, and poweroff ends the session. On the USB
# medium, with a blank disk attached: /root, /var and /tmp are memory, a dry
# run shows the plan and writes nothing, ERASE and the passphrase are asked
# before the first write, and the installer refuses a partition, and a disk
# with a partition mounted, used as swap or held open by device-mapper. Then
# the user guide's steps are typed as it gives them: the layouts, an install
# with ERASE and the passphrase twice, the state header kept on a second disk
# mounted at /mnt, and kryptik-recover's status, commit and restore. The disk
# installed so boots alone, unlocks with that passphrase and asks for a user.
#
#   tools/image/medium-shell-test.sh (--usb IMG | --iso ISO)... [--timeout N]
set -uo pipefail
SELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "${SELF}/../../build/lib/common.sh"
trap - ERR; set +e

MEDIA=(); TIMEOUT=300
while [[ "$#" -gt 0 ]]; do
    case "$1" in
        --usb|--iso) MEDIA+=("$1" "${2:?}"); shift 2 ;;
        --timeout) TIMEOUT="${2:?}"; shift 2 ;;
        -h|--help) sed -n '2,15p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done
[[ "${#MEDIA[@]}" -gt 0 ]] || die "--usb IMG or --iso ISO is required"
VMDIR="${KRYPTIK_WORK}/vm"; mkdir -p "$VMDIR"

# shellcheck source=tools/image/suite-lib.sh
source "${SELF}/suite-lib.sh"

for ((i = 0; i < ${#MEDIA[@]}; i += 2)); do
    kind="${MEDIA[i]#--}"; medium="${MEDIA[i+1]}"
    [[ -f "$medium" ]] || die "no such medium: ${medium}"
    step "the ${kind} medium's console"
    disk=(); typed=()
    if [[ "$kind" == usb ]]; then
        TARGET="${VMDIR}/medium-shell-target.img"; rm -f "$TARGET"
        truncate -s "$("${SELF}/test-disk-size.sh" --medium "$medium")" "$TARGET" || die "could not make the target disk"
        # A second disk to keep the state header on, as the guide says.
        BACKUP="${VMDIR}/medium-shell-backup.img"; rm -f "$BACKUP"; truncate -s 64M "$BACKUP"
        disk=(--disk "$TARGET" --disk "$BACKUP")
        # As above, each answer is made by the shell or said by the installer.
        typed=(
            'send:echo mem-$(stat -f -c %T /root)-$(stat -f -c %T /var)-$(stat -f -c %T /tmp)' "expect:mem-tmpfs-tmpfs-tmpfs"
            "send:kryptik-install --target /dev/vda --dry-run" "expect:layout +esp [0-9]+ MiB, kryptik-a [0-9]+ MiB"
            "expect:dry run: every check passed; nothing was written"
            "send:kryptik-install --target /dev/vda" "expect:Type ERASE to continue: ?" "send:no" "expect:not confirmed; nothing was written"
            "send:kryptik-install --target /dev/vda" "expect:Type ERASE to continue: ?" "send:ERASE"
            "expect:asked at every boot: ?" "send:one" "expect:again: ?" "send:two" "expect:the two passphrases differ; nothing was written"
            'send:echo written-$(head -c 4194304 /dev/vda | tr -d "\000" | wc -c)-table-$(sfdisk -d /dev/vda >/dev/null 2>&1 && echo yes || echo no)'
            "expect:written-0-table-no"
            'send:echo size=64M | sfdisk -q -X gpt /dev/vda; sleep 1; echo part-$(test -b /dev/vda1 && echo made)' "expect:part-made"
            "send:kryptik-install --target /dev/vda1 --dry-run" "expect:is a partition, not a whole disk"
            "send:mkfs.ext4 -q -F /dev/vda1 && mkdir -p /run/target && mount /dev/vda1 /run/target; kryptik-install --target /dev/vda --dry-run; umount /run/target"
            "expect:the target has mounted filesystems"
            "send:mkswap /dev/vda1 >/dev/null && swapon /dev/vda1; kryptik-install --target /dev/vda --dry-run; swapoff /dev/vda1"
            "expect:has active swap on it"
            "send:printf x | cryptsetup -q luksFormat --type luks2 --pbkdf pbkdf2 --pbkdf-force-iterations 1000 --key-file=- /dev/vda1 && printf x | cryptsetup open --key-file=- /dev/vda1 held; kryptik-install --target /dev/vda --dry-run; cryptsetup close held"
            "expect:is in use: held open by"
            "send:kryptik keyboard" 'expect:\* us\r?\n +uk'
            "send:kryptik-install --target /dev/vda" "expect:Type ERASE to continue: " "send:ERASE"
            "expect:asked at every boot: " "send:${KRYPTIK_STATE_PASSPHRASE}" "expect:again: " "send:${KRYPTIK_STATE_PASSPHRASE}"
            "expect:installed [^ ]+ to /dev/vda: boot it from firmware with the medium removed"
            'send:echo ,,L | sfdisk -q -X gpt /dev/vdb; sleep 1; mkfs.ext4 -q -F /dev/vdb1; echo second-$(test -b /dev/vdb1 && echo disk)' "expect:second-disk"
            "send:mount /dev/vdb1 /mnt"
            "send:kryptik-recover --disk /dev/vda --backup-state-header /mnt/kryptik-state-header" "expect:is in /mnt/kryptik-state-header"
            "send:umount /mnt"
            "send:kryptik-recover --disk /dev/vda --status" "expect:committed slot a" "expect:slot a +version [0-9]"
            "send:kryptik-recover --disk /dev/vda --commit-slot a" "expect:committed: BOOTX64.EFI is now slot a"
            "send:kryptik-recover --disk /dev/vda --restore-slot a" "expect:done: boot /dev/vda without the medium"
        )
    fi
    out="$("${SELF}/run-ovmf.sh" "--${kind}" "$medium" "${disk[@]}" --mode serve --name "medium-shell-${kind}")"
    SER="$(sed -n 's/^serial=//p' <<<"$out")"; PIDF="$(sed -n 's/^pid=//p' <<<"$out")"; LOG="$(sed -n 's/^log=//p' <<<"$out")"
    [[ -S "$SER" ]] || die "no serial socket: ${out}"
    # The shell's own arithmetic and substitutions answer, never the echo of
    # what was typed; a getty drops its first second's input, so the first
    # line goes twice.
    python3 "$DRV" --serial "$SER" --timeout "$TIMEOUT" \
        "expect:KRYPTIK_SMOKE: END" "sleep:3" \
        'send:echo shell-$((6 * 7))' "sleep:2" 'send:echo shell-$((6 * 7))' "expect:shell-42" \
        'send:echo uid-$(id -u)' "expect:uid-0" \
        'send:echo found-$(command -v kryptik-install)-$(command -v kryptik-recover)' \
        "expect:found-/usr/sbin/kryptik-install-/usr/sbin/kryptik-recover" \
        "send:kryptik-install --help" "expect:usage: kryptik-install --target" \
        "${typed[@]}" \
        "send:poweroff" "expect:Power down" "wait-exit"
    drc=$?
    stop_vm
    [[ "$drc" -eq 0 ]] && green "${kind}: commands typed at the console ran as root, the installer is on its path, and poweroff took" \
        || red "${kind}: the console did not take commands (see above)"
    if txt | grep -q 'kryptik login:'; then red "${kind}: the medium's console asked for a login"; else green "${kind}: no login prompt on the medium"; fi
    if txt | grep -qE 'KRYPTIK_SMOKE: early_getty_pid=[0-9]+ comm=bash'; then green "${kind}: the console's process is the shell"; else red "${kind}: the console's process is not a shell: $(txt | grep -m1 -o 'early_getty_pid=.*' | cut -c1-80)"; fi
    if [[ "$kind" == usb ]]; then
        t="$(txt)"
        said() { if grep -q -- "$1" <<<"$t"; then green "usb: $2"; else red "usb: $2"; fi; }
        said 'mem-tmpfs-tmpfs-tmpfs' "/root, /var and /tmp on the medium are memory"
        said 'dry run: every check passed; nothing was written' "--dry-run shows the plan and stops before writing"
        said 'not confirmed; nothing was written' "the installer asks for ERASE, and stops on anything else"
        said 'the two passphrases differ; nothing was written' "it asks for the state passphrase twice, and stops when the two differ"
        said 'written-0-table-no' "after those three the disk is still blank: no partition table, its first 4 MiB zero"
        said 'is a partition, not a whole disk' "a partition is refused as a target"
        said 'the target has mounted filesystems' "a disk with a mounted partition is refused"
        said 'has active swap on it' "a disk with a partition used as swap is refused"
        said 'is in use: held open by' "a disk with a partition held open by device-mapper is refused"
        said '\* us' "kryptik keyboard lists the layouts, the one in force marked"
        said 'installed [^ ]* to /dev/vda: boot it from firmware' "an install typed at the console, ERASE and the passphrase twice, completed"
        said 'is in /mnt/kryptik-state-header' "kryptik-recover kept the state header on a second disk mounted at /mnt"
        said 'committed slot a' "kryptik-recover --status read the installed disk"
        said 'committed: BOOTX64.EFI is now slot a' "kryptik-recover --commit-slot a, typed, made slot a the boot file"
        said 'done: boot /dev/vda without the medium' "kryptik-recover --restore-slot a, typed, rewrote slot a from the medium"
        if LC_ALL=C grep -aq $'LUKS\xba\xbe' "$BACKUP"; then green "usb: the second disk holds the LUKS2 header"; else red "usb: no LUKS2 header on the second disk"; fi
        # The disk installed at the console, alone: the driver answers the passphrase typed there.
        out="$("${SELF}/run-ovmf.sh" --no-media --disk "$TARGET" --mode serve --name medium-shell-installed)"
        SER="$(sed -n 's/^serial=//p' <<<"$out")"; PIDF="$(sed -n 's/^pid=//p' <<<"$out")"; LOG="$(sed -n 's/^log=//p' <<<"$out")"
        [[ -S "$SER" ]] || die "no serial socket: ${out}"
        python3 "$DRV" --serial "$SER" --timeout "$TIMEOUT" "expect:User name: "
        irc=$?
        stop_vm
        [[ "$irc" -eq 0 ]] && green "usb: that disk boots alone, unlocks with the passphrase typed at the console, and asks for its first user" \
            || red "usb: the disk installed at the console did not reach first-boot setup"
        rm -f "$TARGET" "$BACKUP"
    fi
done

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]] || exit 1
