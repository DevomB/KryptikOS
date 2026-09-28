#!/usr/bin/env bash
# tools/production-pair.sh, with a stand-in for `make media` that writes what
# stage 06 names for a version: the pair moves to images-production and a
# development release stays, the medium is gone afterwards, and a private key
# in the work tree, whole or only its seed's line, fails it.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PASS=0; FAIL=0
ok()  { printf '  PASS  %s\n' "$1"; PASS=$((PASS + 1)); }
bad() { printf '  FAIL  %s\n' "$1"; FAIL=$((FAIL + 1)); }
for t in ssh-keygen openssl; do command -v "$t" > /dev/null || { echo "${t} required"; exit 77; }; done

T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
W="$T/work"; I="$W/images"; P="$W/images-production"
mkdir -p "$T/bin"
cat > "$T/bin/make" <<'EOF'
#!/usr/bin/env bash
for a in "$@"; do
    case "$a" in KRYPTIK_VERSION=*) v="${a#*=}" ;; KRYPTIK_KEYS=*) m="${a#*=}" ;; KRYPTIK_ROLE=*) r="${a#*=}" ;; esac
done
i="$KRYPTIK_WORK/images"
for f in "kryptik-$v-usb.img" "kryptik-$v-usb.img.sha256" "kryptik-$v.iso" "kryptik-$v.iso.sha256" "kryptik-$v.SHA256SUMS" "kryptik-$v.SHA256SUMS.sig"; do
    echo "$v" > "$i/$f"
done
mkdir -p "$i/payload-$v" "$i/channel-$v"
echo "$v" > "$i/payload-$v/manifest"; echo sig > "$i/payload-$v/manifest.sig"; echo latest > "$i/channel-$v/latest"
echo "$m $r" > "$KRYPTIK_WORK/made-with"
case "${LEAK:-}" in
    key) cp "$m/kryptik-release" "$i/leaked" ;;
    seed) sed -n 5p "$m/kryptik-latest" > "$i/build.log" ;;
esac
EOF
chmod +x "$T/bin/make"

fresh() { rm -rf "$W"; mkdir -p "$I/payload-0.1.1"; echo dev > "$I/kryptik-0.1.1-usb.img"; }
run() { PATH="$T/bin:$PATH" KRYPTIK_WORK="$W" KRYPTIK_ROOT="$ROOT" SUDO="" NO_COLOR=1 bash "$ROOT/tools/production-pair.sh" 2>&1; }
medium() { cut -d' ' -f1 "$W/made-with"; }

fresh; out="$(run)"; rc=$?
[[ "$rc" -eq 0 ]] && ok "the pair is built" || bad "rc=$rc: $out"
[[ "$(cut -d' ' -f2 "$W/made-with")" == production ]] && ok "each release is built with KRYPTIK_ROLE=production" || bad "role: $(cat "$W/made-with")"
missing=""
for v in 1.0.0 1.0.1; do
    for f in "kryptik-$v-usb.img" "kryptik-$v.iso.sha256" "kryptik-$v.SHA256SUMS.sig" "payload-$v/manifest" "channel-$v/latest"; do
        [[ -e "$P/$f" ]] || missing="$missing $f"
    done
done
[[ -z "$missing" && -f "$P/kryptik-sb.crt" ]] && ok "the pair, its channels and its certificate are in images-production" || bad "missing from images-production:${missing}"
left="$(cd "$I" && ls -d ./*1.0.[01]* 2>/dev/null)"
[[ -z "$left" && -f "$I/kryptik-0.1.1-usb.img" && -d "$I/payload-0.1.1" ]] && ok "images/ keeps the development release and none of the pair" || bad "images/ holds: ${left}"
[[ -n "$(medium)" && ! -e "$(medium)" ]] && ok "the key medium is gone" || bad "the medium $(medium) is still there"

fresh; out="$(LEAK=key run)"; rc=$?
[[ "$rc" -ne 0 && "$out" == *"a throwaway private key is in the work tree"* ]] && ok "a private key copied into the work tree fails it" || bad "a copied key passed: rc=$rc: $out"
[[ ! -e "$(medium)" ]] && ok "and the medium is gone then too" || bad "the medium survived a failure"
fresh; out="$(LEAK=seed run)"; rc=$?
[[ "$rc" -ne 0 && "$out" == *"a throwaway private key is in the work tree"* ]] && ok "a line holding only a key's seed fails it" || bad "a seed line passed: rc=$rc: $out"

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
