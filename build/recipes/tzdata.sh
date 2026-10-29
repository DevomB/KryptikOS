#!/usr/bin/env bash

s_tzdata() {
    # Data, compiled by glibc's zic. The tarball has no top directory, so it is given one.
    local src="${BUILDDIR}/tzdata-${V_TZDATA}" z
    rm -rf "$src"; mkdir -p "$src"
    tar -xf "${KRYPTIK_SOURCES}/tzdata${V_TZDATA}.tar.gz" -C "$src"
    cd "$src"
    # fat: a slim file from zic 2023d to 2026a, glibc's among them, drops America/Vancouver's
    # 2026-11-01 change (tzdata's NEWS for 2026b). No leap second files: the clock is POSIX time.
    rm -rf /usr/share/zoneinfo
    zic -b fat -d /usr/share/zoneinfo \
        africa antarctica asia australasia europe northamerica southamerica etcetera backward
    install -m 0644 zone.tab zone1970.tab iso3166.tab /usr/share/zoneinfo/
    install -Dm644 LICENSE /usr/share/licenses/tzdata/LICENSE
    for z in UTC Europe/Berlin America/New_York Asia/Kolkata; do
        [[ "$(head -c4 "/usr/share/zoneinfo/${z}")" == TZif ]] || die "zic made no TZif file for ${z}"
    done
    # 2026-01-15 and 2026-07-15, noon UTC: each zone's own offsets, summer time included.
    [[ "$(TZ=Europe/Berlin date -d @1768478400 +%H%Z) $(TZ=Europe/Berlin date -d @1784116800 +%H%Z)" == "13CET 14CEST" ]] \
        || die "Europe/Berlin does not read 13CET and 14CEST"
    [[ "$(TZ=America/New_York date -d @1768478400 +%H%Z) $(TZ=Asia/Kolkata date -d @1768478400 +%H%M)" == "07EST 1730" ]] \
        || die "America/New_York or Asia/Kolkata reads wrong"
}
