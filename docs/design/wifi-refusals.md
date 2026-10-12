# Saying why a Wi-Fi network was not joined

**A proposal, waiting for the owner's decision.** Nothing here is built. A
saved network whose passphrase is wrong leaves the net zone's status at
`wifi=connecting` for as long as the zone runs, and nothing says why. This
note sets out what wpa_supplicant 2.12 knows about a refused join, where it
says so, and three ways the net zone could pass it on, with a
recommendation.

## What wpa_supplicant knows

- **WPA2.** A four-way handshake that fails on a new connection to a PSK
  network is taken for a wrong key: `could_be_psk_mismatch`
  (`events.c:5092`) logs "pre-shared key may be incorrect" and calls
  `wpas_auth_failed(…, "WRONG_KEY")` (`events.c:5149`).
- **WPA3.** That test is skipped for SAE (`events.c:5098`). A wrong SAE
  password fails the authentication itself. An access point that answers
  the station's confirm with a status code makes it report
  `CTRL-EVENT-AUTH-REJECT … auth_type=3 … status_code=N` (`sme.c:2915`);
  one that drops the frame leaves a timeout, as an access point that has
  gone does. Kryptik saves a network given a passphrase (not a 64-digit
  key) as `WPA-PSK WPA-PSK-SHA256 SAE`, and the supplicant takes SAE
  wherever the access point offers it, so on a WPA3 network a wrong
  passphrase can look exactly like an absent one.
- **Any cause, after four.** More than three failed joins in a row reach
  `wpas_auth_failed(…, "CONN_FAILED")` (`wpa_supplicant.c:9156-9159`),
  whatever failed.
- `wpas_auth_failed` holds the network back, 10 s at first and up to 300 s,
  and says so once, as the event `CTRL-EVENT-SSID-TEMP-DISABLED id=…
  ssid="…" auth_failures=N duration=S reason=…` with `WRONG_KEY`,
  `AUTH_FAILED`, `CONN_FAILED` or `NO_PSK_AVAILABLE`
  (`wpa_supplicant.c:9624`). The control interface keeps no reason:
  `LIST_NETWORKS` flags `[TEMP-DISABLED]` for all of them
  (`ctrl_iface.c:2857`).
- `wpa_cli -a` hands its script CONNECTED, DISCONNECTED and a fixed list of
  access point, mesh, P2P, WPS and DPP events (`wpa_cli.c:4582-4690`);
  neither TEMP-DISABLED nor AUTH-REJECT is among them.
- The net zone starts the supplicant with `-B`, so its own output goes
  nowhere. The recipe builds `CONFIG_DEBUG_FILE`
  (`build/recipes/wpa-supplicant.sh:24`), so `-f FILE` would keep its
  messages, events among them.
- The supplicant's control socket is its own user's. The net zone's loop
  (`wifi_state` in `tools/net/netzone-init.sh`) reads the link from the
  kernel instead, `operstate` and `iw dev N link`; the zone's root reaches
  the socket only through `kryptikd supplicant -- wpa_cli …`, as
  `start_wifi` does once per start.

## Three ways

**Read the flag in the loop.** While no radio has joined, each pass of the
ten-second loop would also run `list_networks` through that door, and a
saved network flagged `[TEMP-DISABLED]` would give the status a shape of its
own, `wifi=refused:SSID`, shown as "SSID refused the last joins: the
passphrase may be wrong, or the network is out of reach". It adds a
short-lived door call to each pass while nothing is joined, and one status
shape: no process that stays, no file, no privilege. It cannot tell a wrong
passphrase from an absent network, and on WPA3 nothing can.

**Keep the supplicant's log.** Started with
`-f /run/wpa_supplicant/RADIO.log` (its Landlock rules let it write under
`/run/wpa_supplicant` alone), the supplicant writes every event to a file
in the zone's tmpfs. The loop would take the last TEMP-DISABLED and
AUTH-REJECT lines and turn `reason=WRONG_KEY`, or SAE's `status_code=15`
(the access point could not verify the station's confirm), into "the
passphrase is wrong". Every scan and event lengthens the file, so the loop
must also cut it, and the reading depends on the text of informational
messages, of which only the event names are kept stable. The answer is
definite for WPA2, and for WPA3 access points that reject rather than drop.

**Listen on the control socket.** A process in the net zone attached
(`ATTACH`) to each supplicant's socket, writing the last reason to a file
the loop reads. `wpa_cli` cannot be it (above), so it is a new program that
holds the supplicant's socket for as long as the zone runs. It gives the
same answers as the log, at the cost of a program to build, review and ship.

## Recommendation

The first. It adds nothing that stays running and no file, and what it says
is true on every network; neither of the others can say more on a WPA3
network that drops a wrong confirm. If the owner also wants WPA2's definite
answer, the log is the smaller step on top of it, and the listener is not
worth its program.

Two things for whoever builds it. The flag clears once its hold-off has
passed and the supplicant picks networks again (10 s at first, then 20, 30,
60, 120 and 300 s), so on a ten-second loop it would come and go between
attempts: the status should keep `refused` until a join, or until the saved
networks change. And `wifi=` already mixes words with SSIDs (`none`,
`unconfigured`, `connecting`, or the SSID), so a network named like a word
reads as that word; a shape that is no SSID, `refused:SSID`, adds no such
name.
