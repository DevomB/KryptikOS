#!/bin/sh
# The root image an install medium carries, as kryptik-install and
# kryptik-recover take it onto a disk. root.json is the medium's own record,
# not signed material: a rewritten record must be able to make a tool fail and
# nothing else, so every field is checked for form before it is used, and what
# lands on a disk is verified against the root hash the signed kernel carries.
# POSIX sh, sourced; the caller defines die.
#   medium_root JSON CMDLINE  the record, checked; sets ROOT_BYTES ROOT_SHA
#                             VERSION and the table's V_BLOCKS V_HASH_START
#                             V_HASH V_SALT
#   kernel_names_root EFI     the kernel's command line carries V_HASH
#   root_verifies DEV         DEV holds the root V_HASH names

decimal_field() {   # decimal_field NAME VALUE: a bounded decimal, or die
    case "$2" in ''|*[!0-9]*) die "root.json: $1 is not a number" ;; esac
    [ "${#2}" -le 15 ] || die "root.json: $1 is too large"
}
hex_field() {   # hex_field NAME VALUE LENGTH: lowercase hex of that length, or die
    case "$2" in *[!0-9a-f]*) die "root.json: $1 is not a hash" ;; esac
    [ "${#2}" -eq "$3" ] || die "root.json: $1 is not a hash"
}
# The root's dm-verity table from the signed command line, as
# "data_blocks hash_start_block root_hash salt"; empty when there is none.
verity_of() {   # verity_of FILE
    sed -n 's/.* verity 1 [^ ]* [^ ]* 4096 4096 \([0-9][0-9]*\) \([0-9][0-9]*\) sha256 \([0-9a-f]\{64\}\) \([0-9a-f]*\) .*/\1 \2 \3 \4/p' "$1" | head -1
}
json_field() {   # json_field JSON NAME: a top-level field of root.json
    sed -n "s/^  \"$2\": \"\{0,1\}\([^\",]*\)\"\{0,1\},\{0,1\}\$/\1/p" "$1" | head -1
}

medium_root() {   # medium_root JSON CMDLINE
    [ -r "$1" ] || die "no root.json on the medium"
    ROOT_BYTES="$(json_field "$1" total_bytes)"; ROOT_SHA="$(json_field "$1" sha256)"; VERSION="$(json_field "$1" version)"
    [ -n "$ROOT_BYTES" ] && [ -n "$ROOT_SHA" ] || die "root.json is incomplete"
    decimal_field total_bytes "$ROOT_BYTES"
    hex_field sha256 "$ROOT_SHA" 64
    case "$VERSION" in ''|*[!A-Za-z0-9._-]*) die "root.json: version is not a version" ;; esac
    VERITY="$(verity_of "$2")"
    [ -n "$VERITY" ] || die "could not read the root's verity table from the signed command line"
    read -r V_BLOCKS V_HASH_START V_HASH V_SALT <<EOF
$VERITY
EOF
    # The record must name the root the signed kernel carries, and its size
    # must hold that root and its hash tree without being absurd. Each field's
    # form comes first, so a refusal never prints what is not a hash or number.
    mr_hash="$(json_field "$1" root_hash)"; mr_blocks="$(json_field "$1" data_blocks)"
    hex_field root_hash "$mr_hash" 64
    decimal_field data_blocks "$mr_blocks"
    [ "$mr_hash" = "$V_HASH" ] || die "root.json names root hash ${mr_hash}; the signed kernel carries ${V_HASH}"
    [ "$mr_blocks" = "$V_BLOCKS" ] || die "root.json names ${mr_blocks} data blocks; the signed kernel carries ${V_BLOCKS}"
    [ "$ROOT_BYTES" -ge $(( (V_HASH_START + 1) * 4096 )) ] || die "root.json: total_bytes is smaller than the root and its hash tree"
    [ "$ROOT_BYTES" -le $(( V_BLOCKS * 4096 + V_BLOCKS * 64 + 16777216 )) ] || die "root.json: total_bytes is larger than a root and its hash tree can be"
}

# A slot's kernel boots the root its command line names. Its signature is the
# firmware's to check, at boot; this keeps one that names another release, or
# is no kernel at all, off a disk the tool would call bootable.
kernel_names_root() {   # kernel_names_root EFI
    [ -f "$1" ] && grep -a -q -F "$V_HASH" "$1"
}

# The record can lie about itself; the signed kernel's root hash cannot.
root_verifies() {   # root_verifies DEV
    veritysetup verify --no-superblock --hash=sha256 --data-block-size=4096 --hash-block-size=4096 \
        --data-blocks="$V_BLOCKS" --hash-offset=$(( V_HASH_START * 4096 )) --salt="$V_SALT" "$1" "$1" "$V_HASH"
}
