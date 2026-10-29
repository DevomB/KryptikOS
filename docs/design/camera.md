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
  image processing); those behind the image processor of AMD's Ryzen AI Max
  (HP's ZBook Ultra G1a), whose driver came in Linux 7.2, after 6.18; and
  infrared face-login cameras.

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
- **The node in the zone.** Firefox finds cameras by opening `/dev/video*`
  when a page asks, and hears of no node made or removed later, so a
  descriptor through the broker would not reach it. Each zone that may
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
  camera back: no zone watches the room while the user is away. So does
  the camera taken away: udev's removal of its node runs `kryptikd camera
  gone`, which ends the grant at once, before another camera plugged in
  could take the node's number. Only the granted camera's node counts, and
  only a removal the kernel numbered after the grant, as a grant moving to
  another zone lets the camera go and takes it again at the same path.
  kryptikd removes the node, unbinds the driver from the device so that
  every descriptor open on it fails from then on, and unloads `uvcvideo`
  (`modprobe -r`, which takes the V4L2 core and videobuf2 with it once
  nothing uses them). Should the module not unload, something still
  holding it, the grant ends all the same, the node gone and the driver
  unbound; the module stays, and the chrome says so. A program that keeps
  its descriptor also keeps the driver's hold on the camera's streaming
  interface, which the camera probed again could not take. So a grant is
  refused, with the reason, until that program lets go.
- **What the user sees.** While a zone holds the camera, a window of the
  chrome's names the zone, as the microphone's does. The camera's light, on
  machines that tie it to the sensor in hardware, says when it captures.

## Check

QEMU has no USB camera. The kernel's `vivid`, a test driver that makes V4L2
devices with no hardware (as `test_power` makes a battery), stands in, built
as a module that the zones and desktop suites alone load. The probe takes
its frames by mmap streaming, as a browser does, since `uvcvideo` has no
`read()`.

- with no grant, no zone's `/dev/video0` opens, and loading by a camera's
  alias, as eudev does when one is plugged in, loads nothing
  (`modprobe -b` with a video-class alias);
- granted to `personal`, a probe there captures a frame from the stand-in,
  which offers MJPEG or YUYV; `work` finds no camera; the chrome's window
  names `personal`;
- taken away while granted (`vivid` unloaded), the grant ends and the node
  goes;
- of two stand-ins, the grant passes over the lower numbered, whose node
  offers only multi-planar formats, which Firefox does not read, for the
  other;
- `k` alone takes it back, and so does the screen locking: the probe's open
  descriptor fails at its next read, and the node is gone;
- a zone whose file refuses the camera is never offered it.

On a laptop, `camera-check.sh USER --hardware`
(`/usr/lib/kryptik/guest-tests`), run as root at a console with the user
logged in and nothing using the camera since boot, checks the same against
the laptop's own USB camera, with `vivid` never loaded, and what only
`uvcvideo` shows: a program that keeps its descriptor past `k` holds the
driver, which stays loaded, and no grant is given until it lets go; the
next grant after that captures again and unloads the driver at its end; and
the camera taken away (its USB device deauthorized, which takes an infrared
camera in the same module with it for those seconds) ends the grant, and
loads nothing when it comes back.

## Not covered

- MIPI cameras behind Intel's IPU6 and AMD's image processor (below), and
  infrared cameras. An infrared face-login camera is usually a second
  function of the same USB camera: a video4linux device of its own, whose
  capture node is `index` 0 like the colour camera's. Of several cameras, a
  grant gives the zone the lowest numbered node that is its device's first
  (`index` 0), which a camera's metadata node is not, and that offers a
  colour format (MJPEG, YUYV, NV12 and the like), which an infrared camera
  giving grey frames alone does not; when none does, the lowest numbered
  (`camera_in` in `camera.rs`). An infrared camera that offers a colour
  format too may still be the one given, and gives a call no picture.
- Which USB devices are accepted at all.
- Screen sharing, which is the compositor's question, not the camera's.

## MIPI cameras

Many Intel laptops since 2022 have a MIPI camera behind the image
processing unit (the IPU6, and the IPU7 from Lunar Lake on) instead of a
USB one. The kernel's half is upstream: `VIDEO_INTEL_IPU6` captures the
sensor's raw frames, `IPU_BRIDGE` describes the sensors from ACPI tables
made for Windows, `INTEL_SKL_INT3472` powers them, each sensor model has a
driver of its own, and many models of 2022 and 2023 put Intel's Visual
Sensing Controller between sensor and IPU (`INTEL_VSC`, with its MEI
driver). The IPU7's driver is still in staging in 6.18. Their firmware is
in linux-firmware 20260916: the IPU6's five files are 2.3 MB, the IPU7's
two 0.5 MB, and the Visual Sensing Controller's 29 files 11.5 MB, before
compression.

What the kernel gives is raw Bayer frames through a media-controller
graph: `/dev/media0`, several `/dev/video*` nodes and the sensors'
`/dev/v4l-subdev*`. Making a picture of them is userspace's work:
libcamera's software image processing, or Intel's closed one. There it
leaves ADR-026, which grants a zone one node that hands Firefox a format it
reads:

- **libcamera in the zone,** given the graph: the zone's kernel reaches the
  IPU6 driver's, the media controller's and the sensors' ioctls, and a
  grant has a graph to revoke rather than a node.
- **libcamera in zone 0,** handing the zone pictures: a camera stack and
  its image processing become trusted code, and the zone still needs a
  V4L2 node the pictures come out of, which only an out-of-tree module
  (v4l2loopback) makes.

Neither fits 1.0, which leaves these cameras unsupported, as ADR-026 has
it; a USB camera works on those laptops. The firmware is the small part of
the cost. Where the image processing runs and what a grant hands over are
the questions, and they wait for a machine with such a camera to answer
them on.

AMD's Ryzen AI Max has an image processor of its own, the ISP4, behind the
MIPI camera of HP's ZBook Ultra G1a. Its firmware drives the sensor and
makes the picture, and its driver gives one capture node of NV12 or YUYV
frames, as a USB camera does, rather than a graph of raw ones, so it would
fit a grant of one node. That driver (`VIDEO_AMD_ISP4_CAPTURE`) came in
Linux 7.2, and Kryptik builds 6.18. It would also need amdgpu's half
(`DRM_AMD_ISP`, off), platform cameras in the media filter (off), the
processor's firmware (`amdgpu/isp_*`, which `firmware.list` leaves out),
and kryptikd's grant loading it beside `uvcvideo`.
