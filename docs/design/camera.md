# Camera

A video call in a zone's Firefox has the microphone, granted to one zone at a
time from the chrome ([the laptop](laptop.md#sound)), and needs the camera
too. This design weighs adding one against the kernel code it brings into
every zone's kernel. It keeps the rules the
microphone set: one zone at a time, the user's gesture in zone 0 the only way
to grant it, and the grant visible for as long as it lasts.
[ADR-026](../decisions.md) decides it: the grant.

## What the kernel would add

- **Video for Linux.** `CONFIG_MEDIA_SUPPORT`, the V4L2 core and videobuf2,
  as modules. Once a zone opens the camera's node, every V4L2 ioctl it makes
  reaches that code: formats, buffers, memory maps, controls.
- **`uvcvideo`,** the driver for the USB Video Class, which nearly every
  laptop's built-in camera and every USB webcam speaks. It parses the
  class-specific descriptors a device sends: formats, frames and controls,
  laid out by the device. A bug in that parsing, of a device's frame
  descriptors (CVE-2024-53104), was used in the wild in 2025, from a USB
  device made for it.
- **Not covered:** the MIPI cameras of many Intel laptops since 2022, behind
  the IPU6, which need a camera stack in userspace (libcamera and Intel's
  image processing), and infrared face-login cameras.

## Who reaches that code, and when

- **Every USB device's standard descriptors** are parsed by the USB core as
  it arrives, a camera's like a keyboard's, whatever is decided here. The
  class-specific ones are kept as bytes and parsed only by the class's
  driver.
- **Loaded by alias,** as eudev loads every driver, `uvcvideo` would parse the
  descriptors of anything that says it is a camera the moment it is plugged
  in, locked screen or not. `blacklist uvcvideo` in `modprobe.d` stops that:
  eudev's loads by alias obey it, nothing in the kernel asks for modules
  (`STATIC_USERMODEHELPER`), and no other module depends on it. An explicit
  `modprobe uvcvideo` by root still loads it.
- **During a grant** the driver is loaded, and binds to whatever camera
  appears, the user's and any other plugged in meanwhile. Which USB devices
  are accepted at all is a question of its own, keyboards included.

## Options

- **No camera.** As now. Calls go without video, or a phone takes them.
- **A camera granted like the microphone.** Described below. The zone the
  user picks reaches V4L2 and uvcvideo through the node, for as long as the
  grant lasts.
- **A camera zone,** holding the device as the net zone holds the NICs, with
  frames passed to the calling zone through a proxy of Kryptik's. Every zone
  would reach only the proxy, but the proxy would be a new video pipe to
  write and keep, and Firefox would need a device it can open, a virtual
  V4L2 device or PipeWire, both more kernel or more daemon. Rejected for
  now.

## The decision

ADR-026 decides: a camera granted like the microphone, with the driver
loaded only for a grant.

- **The grant.** In the chrome, `k<N>` grants zone N the camera, as `c<N>`
  grants the microphone. kryptikd loads `uvcvideo`, finds the camera's node
  from sysfs (`/sys/class/video4linux`), and gives the zone the node. A zone
  file may refuse the camera (`[camera] use = false`), as `vault`'s will;
  the net zone never gets it.
- **The node in the zone.** Firefox finds cameras by opening `/dev/video*`,
  so a descriptor through the broker would not reach it. Each zone that may
  use the camera starts with `/dev/video0` a link to a file in a directory
  of its own, which kryptikd binds into the zone at start from a small
  tmpfs that allows device nodes; the directory is root's, and a zone, in
  a user namespace of its own, can make no device node anyway. The link
  points nowhere until a grant, when kryptikd makes the node there, owned
  by the zone's uid, mode 0600. Nothing mounts into a running zone. The
  open has two gates to pass besides the node's mode: the directory's mount
  must allow device nodes (not `nodev`), and the zone's Landlock ruleset
  must grant reading, writing and device ioctls beneath it, as it does for
  `/dev`, since the ruleset is checked on the path the link leads to.
- **The end.** `k` alone, the zone's stop, or the screen locking takes the
  camera back: no zone watches the room while the user is away. kryptikd
  removes the node, unbinds the driver from the device so that every
  descriptor open on it fails from then on, and unloads `uvcvideo`
  (`modprobe -r`, which takes the V4L2 core and videobuf2 with it once
  nothing uses them). Should the module not unload, something still
  holding it, the grant ends all the same, the node gone and the driver
  unbound; the module stays until the next grant, and the chrome says so.
- **What the user sees.** While a zone holds the camera, a window of the
  chrome's names the zone, as the microphone's does. The camera's light, on
  machines that tie it to the sensor in hardware, says when it captures.

## Check

QEMU has no USB camera. The kernel's `vivid`, a test driver that makes V4L2
devices with no hardware (as `test_power` makes a battery), stands in, built
as a module that the zones and desktop suites alone load; `uvcvideo`
itself waits for the tests on physical hardware.

- with no grant, no zone's `/dev/video0` opens, and loading by a camera's
  alias, as eudev does when one is plugged in, loads nothing
  (`modprobe -b` with a video-class alias);
- granted to `personal`, a probe there captures a frame from the stand-in;
  `work` finds no camera; the chrome's window names `personal`;
- `k` alone takes it back, and so does the screen locking: the probe's open
  descriptor fails at its next read, and the node is gone;
- a zone whose file refuses the camera is never offered it.

## Not covered

- MIPI cameras behind the IPU6, and infrared cameras.
- Which USB devices are accepted at all.
- Screen sharing, which is the compositor's question, not the camera's.
