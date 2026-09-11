#!/bin/sh -e
# Replay the devices that already existed when udevd started, then wait for
# the queue to drain: without the settle a later service can race a node that
# is about to appear.
/usr/sbin/udevadm trigger --action=add --type=subsystems
/usr/sbin/udevadm trigger --action=add --type=devices
/usr/sbin/udevadm settle --timeout=30 || echo "eudev-trigger: settle timed out" >&2
echo "eudev-trigger: complete"
