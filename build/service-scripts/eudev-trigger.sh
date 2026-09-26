#!/bin/sh -e
# Replay devices that existed before udevd started, then settle, so a later
# service does not race a node that is about to appear.
/usr/sbin/udevadm trigger --action=add --type=subsystems
/usr/sbin/udevadm trigger --action=add --type=devices
/usr/sbin/udevadm settle --timeout=30 || echo "eudev-trigger: settle timed out" >&2
echo "eudev-trigger: complete"
