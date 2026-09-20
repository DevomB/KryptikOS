#!/bin/sh
# The clock's floor (docs/design/time.md). A clock that reads earlier than
# this system was built is wrong by definition - a dead RTC battery starts a
# machine in 1970 or 2000 - and zone 0 repairs that here, by itself, before
# anything asks the network: `kryptikd time floor` sets such a clock to the
# image's build date and leaves any other clock alone. Every later claim the
# net zone makes about the time is then judged from a clock that is at least
# plausible, by the same rule as on any other machine.
#
# Deliberately not `-e`, and the exit status is always 0: a clock that could
# not be repaired is a line in the log, not a machine whose net zone never
# starts because a oneshot it depends on failed.
log=/var/log/kryptik/time.log
mkdir -p /var/log/kryptik
out="$(/usr/bin/kryptikd time floor 2>&1)"; rc=$?
echo "=== time floor $(date -Iseconds 2>/dev/null) rc=${rc} === ${out}" >> "$log" 2>/dev/null
# On the console too, so a serial log shows it.
echo "time-floor: ${out}"
exit 0
