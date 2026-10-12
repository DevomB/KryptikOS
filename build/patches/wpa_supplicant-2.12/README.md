# wpa_supplicant 2.12: scan ages in a time namespace

Applied by `s_wpa_supplicant` in stage 04 through `apply_repo_patches`;
`SHA256SUMS` is verified before anything is applied.

Every zone runs in a time namespace of its own, whose boot clock starts at a
random point between an hour and thirty days
([net zone surface](../../../docs/design/net-zone-surface.md#a-time-namespace-per-zone)).
The net zone's supplicant took a scan result's age from the kernel's stamp on
the machine's boot clock against its own, so every result read as hours or
days old and left the BSS table within ten seconds of its scan:
`wpa_cli scan_results` came back empty while the radio heard its networks,
and anything decided from the table between scans had nothing to go on. The
patch keeps the kernel's own millisecond age whenever the two disagree. The
zones suite's `wifi-bss-age` reads the age of the access point the station
joined.

The patch is Kryptik's own; delete this directory when a wpa_supplicant
release carries an equivalent.
