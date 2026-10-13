#!/bin/sh -e
# Replay the devices udevd missed and settle, so no later service races a node about to appear.
/usr/sbin/udevadm trigger --action=add --type=subsystems
/usr/sbin/udevadm trigger --action=add --type=devices
/usr/sbin/udevadm settle --timeout=30 || echo "eudev-trigger: settle timed out" >&2
echo "eudev-trigger: complete"
