#!/bin/sh
# Software images on the state partition (docs/design/software-delivery.md), for kryptik-update (a
# release's payload) and kryptik-install (the medium): each list kept under the root hash it is built
# for, each image it names under its own root hash. Sourced; the caller defines say, die and uncache.

# images_keep LIST SIG STORE BASE READER: keep in STORE the images LIST names, for the root BASE, which
# LIST must be built for. READER NAME writes image NAME's bytes to stdout. Each copy is checked against
# the size and hash LIST signs before it takes its name, none takes its name until every one has
# checked, and LIST and SIG are kept last. kryptikd checks LIST's signature at every use.
images_keep() {
    _l="$1"; _s="$2"; _store="$3"; _base="$4"; _read="$5"
    [ "$(head -1 "$_l")" = KRYPTIK-IMAGES-1 ] || die "the image list is not a KRYPTIK-IMAGES-1"
    [ "$(sed -n 's/^base: //p' "$_l")" = "$_base" ] || die "the image list is for another root than the one it comes with"
    mkdir -p "$_store" && chmod 0700 "$_store" || die "cannot make $_store"
    _staged=""
    while read -r _ _name _ _bytes _sha _ _hash _; do
        [ -n "$_name" ] || continue
        _bytes="${_bytes#bytes=}"; _sha="${_sha#sha256=}"; _hash="${_hash#root-hash=}"
        case "$_name" in ''|*[!a-z0-9-]*) die "the image list names '$_name'" ;; esac
        case "$_bytes" in ''|*[!0-9]*) die "image $_name: its size in the list is not a number" ;; esac
        case "$_hash$_sha" in *[!0-9a-f]*) die "image $_name: its hashes in the list are not hex" ;; esac
        [ "${#_hash}" = 64 ] && [ "${#_sha}" = 64 ] || die "image $_name: its hashes in the list are not 64 digits"
        _f="$_store/$_name/$_hash.img"
        if [ -f "$_f" ] && [ "$(stat -c %s "$_f")" = "$_bytes" ] && [ "$(sha256sum "$_f" | cut -c1-64)" = "$_sha" ]; then
            say "image $_name: already kept"
            continue
        fi
        mkdir -p "$_store/$_name" || die "cannot make $_store/$_name"
        "$_read" "$_name" > "$_f.new" || { rm -f "$_f.new"; die "image $_name could not be read, or written into the store"; }
        sync -f "$_f.new"
        uncache "$_f.new"
        if [ "$(stat -c %s "$_f.new")" != "$_bytes" ] || [ "$(sha256sum "$_f.new" | cut -c1-64)" != "$_sha" ]; then
            rm -f "$_f.new"
            die "image $_name is not the bytes its list signs"
        fi
        _staged="$_staged $_f"
        say "image $_name: kept and checked ($_bytes bytes)"
    done <<EOF
$(grep '^image: ' "$_l")
EOF
    for _f in $_staged; do mv -f "$_f.new" "$_f" || die "cannot keep $_f"; done
    cp "$_l" "$_store/$_base.manifest.new" && cp "$_s" "$_store/$_base.manifest.sig.new" \
        && sync && mv -f "$_store/$_base.manifest.new" "$_store/$_base.manifest" \
        && mv -f "$_store/$_base.manifest.sig.new" "$_store/$_base.manifest.sig" \
        || die "the image list could not be kept"
}

# images_prune STORE ROOT-HASH...: keep the lists for those roots and the images they name; a list for
# any other root, an image no kept list names and a copy left half-made all go.
images_prune() {
    _store="$1"; shift
    [ -d "$_store" ] || return 0
    _keep=" $* "
    for _l in "$_store"/*.manifest; do
        [ -f "$_l" ] || continue
        case "$_keep" in *" $(basename "$_l" .manifest) "*) ;; *) rm -f "$_l" "$_l.sig" ;; esac
    done
    _wanted="$(cat "$_store"/*.manifest 2>/dev/null | sed -n 's/^image: \([a-z0-9-]*\) .* root-hash=\([0-9a-f]*\) .*/\1\/\2.img/p')"
    for _f in "$_store"/*/*.img "$_store"/*/*.img.new; do
        [ -f "$_f" ] || continue
        printf '%s\n' "$_wanted" | grep -Fxq -- "${_f#"$_store"/}" || rm -f "$_f"
    done
}
