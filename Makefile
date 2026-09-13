# Kryptik build orchestrator
# Kryptik must be built on Linux. On Windows use WSL2.

SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := help

# $(CURDIR), not $(dir $(abspath $(MAKEFILE_LIST))).
#
# GNU make's text functions operate on whitespace-separated LISTS, so abspath
# and dir silently mangle any path containing a space: this repository lives in
# ".../Linux Distro" and $(ROOT) came out as ".../Coding-Projects Distro",
# having dropped a word. Every target then failed with a path that looked
# almost right. $(CURDIR) is a single value and survives.
#
# Recipe uses must still be quoted - see the "$(TOOLS)" below.
ROOT    := $(CURDIR)
STAGES  := $(ROOT)/build/stages
TOOLS   := $(ROOT)/tools
CHROOTD := $(STAGES)/03-chroot-prep.sh

# --- the build contract -----------------------------------------------------
#
# Three paths and a job count. Everything - the Makefile, the stage scripts and
# the chroot - agrees on these names, and nothing derives a fourth path from
# them behind your back.
#
#   KRYPTIK_ROOT      the repository. Read-only during a build.
#   KRYPTIK_SOURCES   upstream tarballs. Read-only during a build.
#   KRYPTIK_WORK      everything the build writes: sysroot, stamps, logs, trees.
#
# `?=` deliberately: GNU make imports the environment, so an exported
# KRYPTIK_WORK from the caller wins, and
#
#   KRYPTIK_WORK=/build/kryptik make toolchain
#
# does what it looks like it does. This matters because the work tree must not
# live on a filesystem that cannot represent POSIX ownership - /mnt/c under
# WSL2, for instance - while the checkout very often does.
KRYPTIK_WORK    ?= $(ROOT)/build/work
KRYPTIK_SOURCES ?= $(ROOT)/sources
KRYPTIK_OUT     ?= $(ROOT)/out
# Empty means "let build/lib/common.sh choose from CPU count and RAM".
KRYPTIK_JOBS    ?=
# refuse | rebuild. See the stamp notes in build/lib/common.sh.
KRYPTIK_STALE   ?= refuse
# Stamped into /etc/os-release so a booted image names the commit that
# built it. --dirty on purpose: an image claiming a clean commit while the
# tree had edits is worse than one claiming nothing.
KRYPTIK_BUILD_COMMIT ?= $(shell git -C "$(ROOT)" describe --always --dirty --abbrev=40 2>/dev/null || echo unknown)
# Path to a kryptikd binary built outside the chroot; see `make help`.
KRYPTIK_KRYPTIKD_BIN ?=
# Same for the per-zone Wayland proxy (compositor/, package wlproxy, binary
# kryptik-wlproxy): Rust, static, built outside, installed by stage 04's
# desktop step.
KRYPTIK_WLPROXY_BIN ?=

export KRYPTIK_ROOT := $(ROOT)
# Pinned versions the image targets name. Read through the shell so the
# file stays shell syntax; a literal `include` would misparse its quotes.
V_LINUX := $(shell . "$(ROOT)/build/config/versions.env" && echo $$V_LINUX)
# The release name stamped into the media; override to build a "B" release.
KRYPTIK_VERSION ?=
export KRYPTIK_VERSION
export KRYPTIK_WORK
export KRYPTIK_SOURCES
export KRYPTIK_OUT
export KRYPTIK_JOBS
export KRYPTIK_STALE

# --- privilege --------------------------------------------------------------
#
# Exactly two things in this build need root: creating device nodes and
# bind-mounting virtual filesystems into the sysroot (stage 03), and the
# chroot() call itself. Nothing else runs privileged - not the compilers, not
# make, not the package recipes.
#
# So SUDO wraps the chroot driver and nothing else. Override it when you are
# already root (SUDO=) or when your site uses something other than sudo
# (SUDO=doas, SUDO="pkexec --keep-cwd").
SUDO ?= sudo

# sudo resets the environment, which is why the contract is passed explicitly
# rather than exported and hoped for. A `make system` that silently dropped
# KRYPTIK_WORK would build into $(ROOT)/build/work instead - a different tree,
# on possibly a different filesystem, with no error anywhere.
CHROOT_ENV := KRYPTIK_ROOT="$(ROOT)" \
              KRYPTIK_WORK="$(KRYPTIK_WORK)" \
              KRYPTIK_SOURCES="$(KRYPTIK_SOURCES)" \
              KRYPTIK_JOBS="$(KRYPTIK_JOBS)" \
              KRYPTIK_STALE="$(KRYPTIK_STALE)" \
              KRYPTIK_BUILD_COMMIT="$(KRYPTIK_BUILD_COMMIT)" \
              KRYPTIK_KRYPTIKD_BIN="$(KRYPTIK_KRYPTIKD_BIN)" \
              KRYPTIK_WLPROXY_BIN="$(KRYPTIK_WLPROXY_BIN)" \
              TERM="$(TERM)" \
              NO_COLOR="$(NO_COLOR)"

CHROOT_RUN := $(SUDO) env $(CHROOT_ENV) "$(CHROOTD)"

.PHONY: test help check check-kernel-eol sources lock verify verify-provenance \
	vm-disk vm-disk-boot vm-restart vm-measure cli-test update-tree-test identity-test serve-test \
        test-harness test-hardening test-artifacts audit-artifacts test-boot-success \
        audit-artifacts-strict manifest verify-manifest test-manifest \
        test-s6-init smoke-userspace test-services test-libc-unwind \
        sign-image verify-image test-image-signing test-installer test-mkdisk-guards \
        install-test \
        image image-boot \
        image-smoke \
        validate-kernel validate-kernel-hardened validate-kernel-boot \
        media ovmf-vars media-smoke-usb media-smoke-iso media-smoke-secureboot \
        media-refused-foreign-keys integrity-test update-test \
        toolchain temp-tools chroot chroot-enter chroot-umount chroot-status \
        system kernel iso audit zones zone-test paths reset-stamps \
        sysroot-ready \
        launcher-test zone-tests vm-image vm-boot \
        clean distclean

help:
	@echo "Kryptik build targets"
	@echo
	@echo "  make check       verify the host can build Kryptik"
	@echo "  make sources     fetch upstream tarballs, verify against sources.lock"
	@echo "  make lock        fetch and regenerate sources.lock (audit before committing)"
	@echo "  make toolchain   stage 01: cross toolchain            [Phase 1]"
	@echo "  make temp-tools  stage 02: temporary tools            [Phase 2]"
	@echo "                   (stages 01 and 02 are UNPRIVILEGED - run them as you)"
	@echo "  make system      stage 04: hardened base system       [Phase 3]"
	@echo "  make kernel      stage 05: hardened kernel            [Phase 4]"
	@echo "  make iso         stage 06: verified root image, signed kernels, USB image + ISO"
	@echo "  make media       stage 06 only (sysroot and kernel already built)"
	@echo "  make media-smoke-usb | media-smoke-iso   boot the media under OVMF, assert"
	@echo "  make media-smoke-secureboot              same with the developer key enrolled"
	@echo "  make media-refused-foreign-keys          Microsoft keys only: must be refused"
	@echo "  make install-test  install to a blank virtual disk, boot it alone, refusals"
	@echo "  make integrity-test  Secure Boot enforced, foreign boot file refused, root tamper refused, recovery"
	@echo "  make update-test PAYLOAD_A=.. PAYLOAD_B=..  A/B update, rollback, refusals, interruptions"
	@echo
	@echo "  'system' and 'kernel' build INSIDE the chroot. They mount it, run"
	@echo "  the stage, and unmount again. Only the mounts and the chroot call"
	@echo "  are privileged; override the escalation with SUDO=... or SUDO= ."
	@echo
	@echo "  make chroot          mount the chroot and leave it mounted"
	@echo "  make chroot-enter    interactive shell inside the chroot"
	@echo "  make chroot-umount   unmount it"
	@echo "  make chroot-status   what is mounted right now"
	@echo
	@echo "  make verify      verify upstream GPG signatures on fetched sources"
	@echo "  make verify-provenance  signed tags + publisher checksums for the rest"
	@echo "  make validate-kernel   check kernel fragment against pinned source"
	@echo "  make check-kernel-eol  fail if the pinned kernel is EOL or not LTS"
	@echo "  make validate-kernel-hardened  check the linux-hardened fragment"
	@echo "  make zones       validate zone definitions + kernel support"
	@echo "  make zone-test   run the Phase 5 adversarial exit test (primitives)"
	@echo "  make launcher-test  attack \`kryptikd run\` itself (the launch path)"
	@echo "  make zone-tests  both of the above; what a zone change must pass"
	@echo "  make cli-test    test \`kryptik\`, the command a person types"
	@echo "  make serve-test  drive \`kryptikd serve\`, the launch daemon, over its socket"
	@echo "  make update-tree-test  install a signed update into a kryptikd program/config"
	@echo "                   tree, interrupt it, roll it back (directories, no VM)"
	@echo "  make vm-image    build the developer VM initramfs (busybox userspace)"
	@echo "  make vm-boot     boot it under QEMU and check the serial log"
	@echo
	@echo "  With a stage 04 sysroot, the image is a real Kryptik userspace and"
	@echo "  is too big for an initramfs, so it becomes an ext4 disk instead:"
	@echo "  make vm-disk       SYSROOT=... S6ROOT=...   build the root filesystem"
	@echo "  make vm-disk-boot  KERNEL=...               boot it as /dev/vda"
	@echo "  make vm-restart    KERNEL=...               boot, reboot, come back"
	@echo "  make vm-measure                             what the last boot cost"
	@echo "  make test-harness      verify failed builds cannot be stamped ok"
	@echo "  make test-hardening    verify the flag set builds exes AND .so files"
	@echo "  make test-artifacts    self-test the artifact auditor (positive controls)"
	@echo "  make audit-artifacts   audit the ELF objects the build actually produced"
	@echo "  make audit-artifacts-strict   ... and fail on reported findings too"
	@echo "  make manifest          record what was built and what built it"
	@echo "  make verify-manifest   check the tree still matches that record"
	@echo "  make test-manifest     self-test the manifest tool (positive controls)"
	@echo "  make test-s6-init      check stage 04 produces a bootable s6 image"
	@echo "  make smoke-userspace   RUN the built userland in the chroot (needs root)"
	@echo "  make test-services     validate the s6-rc service tree"
	@echo "  make identity-test     zone files, compositor colour table and zoneid audit agree"
	@echo "  make test-libc-unwind  prove the target libc can unwind (needs root)"
	@echo "  make sign-image        sign the disk image with a developer key"
	@echo "  make verify-image      verify that signature against the image"
	@echo "  make test-image-signing  prove the verifier refuses what it should"
	@echo "  make test-installer    installer checks that need no VM"
	@echo "  make image KERNEL=...  build a bootable disk image from the sysroot"
	@echo "  make image-boot KERNEL=...  boot that image on a serial console"
	@echo "  make audit       run security audits over the build tree"
	@echo "  make paths       print the resolved build contract"
	@echo "  make reset-stamps  archive all build stamps (does not delete)"
	@echo "  make clean       remove the build work directory"
	@echo "  make distclean   also remove downloaded sources and output"
	@echo
	@echo "Contract (override any of these on the command line or in the env):"
	@echo "  KRYPTIK_WORK     = $(KRYPTIK_WORK)"
	@echo "  KRYPTIK_SOURCES  = $(KRYPTIK_SOURCES)"
	@echo "  KRYPTIK_JOBS     = $(if $(KRYPTIK_JOBS),$(KRYPTIK_JOBS),auto)"
	@echo "  KRYPTIK_STALE    = $(KRYPTIK_STALE)"
	@echo "  KRYPTIK_BUILD_COMMIT = $(KRYPTIK_BUILD_COMMIT)"
	@echo "  KRYPTIK_KRYPTIKD_BIN = $(if $(KRYPTIK_KRYPTIKD_BIN),$(KRYPTIK_KRYPTIKD_BIN),(not set - the image will have no kryptikd))"
	@echo "  KRYPTIK_WLPROXY_BIN  = $(if $(KRYPTIK_WLPROXY_BIN),$(KRYPTIK_WLPROXY_BIN),(not set - zones will have no display))"
	@echo "  SUDO             = $(if $(SUDO),$(SUDO),(none))"
	@echo
	@echo "Status: pre-alpha. See docs/roadmap.md for what actually works."

paths:
	@echo "KRYPTIK_ROOT    = $(ROOT)"
	@echo "KRYPTIK_BUILD_COMMIT = $(KRYPTIK_BUILD_COMMIT)"
	@echo "KRYPTIK_SOURCES = $(KRYPTIK_SOURCES)"
	@echo "KRYPTIK_WORK    = $(KRYPTIK_WORK)"
	@echo "  sysroot       = $(KRYPTIK_WORK)/sysroot"
	@echo "  stamps        = $(KRYPTIK_WORK)/.stamps"
	@echo "  logs          = $(KRYPTIK_WORK)/logs"
	@echo "  build trees   = $(KRYPTIK_WORK)/build"
	@echo "KRYPTIK_OUT     = $(KRYPTIK_OUT)"
	@echo
	@echo "Inside the chroot these appear as /kryptik, /kryptik-sources and"
	@echo "/kryptik-work; the sysroot is / and there is no second view of it."

check:
	@"$(STAGES)"/00-host-check.sh
	@"$(TOOLS)"/check-kernel-eol.sh

sources:
	@"$(TOOLS)"/fetch-sources.sh

lock:
	@"$(TOOLS)"/fetch-sources.sh --lock

verify:
	@"$(TOOLS)"/verify-signatures.sh

verify-provenance:
	@"$(TOOLS)"/verify-provenance.sh

validate-kernel:
	@"$(TOOLS)"/validate-kernel-config.sh

check-kernel-eol:
	@"$(TOOLS)"/check-kernel-eol.sh

validate-kernel-hardened:
	@"$(TOOLS)"/validate-kernel-config.sh --hardened

validate-kernel-boot:
	@"$(TOOLS)"/validate-kernel-config.sh --boot

toolchain: check sources
	@"$(STAGES)"/01-toolchain.sh

temp-tools: toolchain
	@"$(STAGES)"/02-temp-tools.sh

# --- the chroot stages ------------------------------------------------------
#
# These two targets used to print a wall of instructions and then `false`.
# That was honest about the constraint - stage 04 runs inside the chroot and
# needs root to get there - and useless as an entry point: the instructions
# hardcoded $(ROOT)/build/work, so they were wrong the moment KRYPTIK_WORK was
# overridden, and one of them had a stray quote that made the command it
# printed unrunnable.
#
# The constraint is real; a target can satisfy it. `03-chroot-prep.sh run`
# mounts, runs one command inside, and unmounts on every exit path.

system: sysroot-ready
	@$(CHROOT_RUN) run /kryptik/build/stages/04-base-system.sh

# The EOL check needs a network, and the chroot deliberately has none, so it
# runs out here before we go in. Stage 05 repeats it inside, where it degrades
# to a warning.
kernel: check-kernel-eol system
	@$(CHROOT_RUN) run /kryptik/build/stages/05-kernel.sh

chroot: sysroot-ready
	@$(CHROOT_RUN) mount

chroot-enter:
	@$(CHROOT_RUN) enter

chroot-umount:
	@$(CHROOT_RUN) umount

chroot-status:
	@"$(CHROOTD)" status

# Verify that stage 02 finished; do not silently run it.
#
# The unprivileged stages and the privileged ones want different uids, and a
# target that quietly does both under whichever one the caller happens to have
# is how a cross toolchain ends up owned by root. `make system` as root - the
# documented SUDO= configuration, and every container - would have rebuilt the
# whole toolchain as root, which stage 00 exists to refuse.
sysroot-ready:
	@if [[ ! -x "$(KRYPTIK_WORK)/sysroot/usr/bin/gcc" ]]; then \
	    echo "Stage 02 has not completed: no target compiler at"; \
	    echo "  $(KRYPTIK_WORK)/sysroot/usr/bin/gcc"; \
	    echo; \
	    echo "Build it first, UNPRIVILEGED:"; \
	    echo "  make temp-tools"; \
	    exit 1; \
	fi

# --- install media (Design 08) ----------------------------------------------
#
# Stage 06 builds the verity root image, relinks and signs a kernel per boot
# variant, and assembles the USB image and the ISO. It runs as root (the
# sysroot has root-only paths; the relink goes through the chroot) - SUDO=
# when you already are.
iso: kernel
	@$(SUDO) env $(CHROOT_ENV) KRYPTIK_VERSION="$(KRYPTIK_VERSION)" "$(STAGES)"/06-iso.sh

# Same, without rebuilding anything first: for a sysroot and kernel that exist.
media:
	@$(SUDO) env $(CHROOT_ENV) KRYPTIK_VERSION="$(KRYPTIK_VERSION)" "$(STAGES)"/06-iso.sh

MEDIA_USB ?= $(shell ls -t "$(KRYPTIK_WORK)"/images/kryptik-*-usb.img 2>/dev/null | head -1)
MEDIA_ISO ?= $(shell ls -t "$(KRYPTIK_WORK)"/images/kryptik-*.iso 2>/dev/null | head -1)

# The disposable OVMF variable stores: clean (no keys), enrolled (the
# developer key: Secure Boot on), ms (Microsoft keys only: ours are refused).
ovmf-vars:
	@"$(TOOLS)"/image/ovmf-vars.sh

# Boot the media through firmware alone and assert on the transcript.
media-smoke-usb:
	@test -n "$(MEDIA_USB)" || { echo "no USB image under $(KRYPTIK_WORK)/images; run make iso"; exit 1; }
	@"$(TOOLS)"/image/media-smoke.sh --usb "$(MEDIA_USB)" --vars clean
media-smoke-iso:
	@test -n "$(MEDIA_ISO)" || { echo "no ISO under $(KRYPTIK_WORK)/images; run make iso"; exit 1; }
	@"$(TOOLS)"/image/media-smoke.sh --iso "$(MEDIA_ISO)" --vars clean
# Under the enrolled developer key Secure Boot must be ON and boot must
# succeed; under Microsoft's keys the same medium must be refused.
media-smoke-secureboot: ovmf-vars
	@"$(TOOLS)"/image/media-smoke.sh --usb "$(MEDIA_USB)" --vars enrolled
media-refused-foreign-keys:
	@"$(TOOLS)"/image/media-smoke.sh --usb "$(MEDIA_USB)" --vars ms --expect-refused

# Install from the USB medium onto a blank virtual disk, then boot that disk
# alone: medium detached, variable store fresh; reboot and power off from
# inside; then the refusal cases. Needs KVM for a sane running time.
install-test:
	@test -n "$(MEDIA_USB)" || { echo "no USB image under $(KRYPTIK_WORK)/images; run make iso"; exit 1; }
	@"$(TOOLS)"/image/install-test.sh --usb "$(MEDIA_USB)" --vars $(or $(VARS),clean)

# Enforced Secure Boot, a foreign-signed boot file refused, a tampered root
# refused by dm-verity, recovery from the medium.
integrity-test: ovmf-vars
	@test -n "$(MEDIA_USB)" || { echo "no USB image under $(KRYPTIK_WORK)/images; run make iso"; exit 1; }
	@"$(TOOLS)"/image/integrity-test.sh --usb "$(MEDIA_USB)"

# A/B update, reboot, recovery/rollback, refusals, interruptions. Needs two
# releases: PAYLOAD_A and PAYLOAD_B are stage 06 payload directories and
# MEDIA_USB is release A's medium.
PAYLOAD_A ?=
PAYLOAD_B ?=
update-test:
	@test -n "$(PAYLOAD_A)" -a -n "$(PAYLOAD_B)" || { echo "set PAYLOAD_A=... PAYLOAD_B=... (stage 06 payload dirs of two releases)"; exit 1; }
	@"$(TOOLS)"/image/update-test.sh --usb-a "$(MEDIA_USB)" --payload-a "$(PAYLOAD_A)" --payload-b "$(PAYLOAD_B)" --vars $(or $(VARS),clean)

zones:
	@cd compartments/kryptikd && cargo build --quiet
	@compartments/kryptikd/target/debug/kryptikd check --zones compartments/zones

zone-test:
	@cd compartments/kryptikd && cargo build --quiet
	@compartments/tests/adversarial.sh

# adversarial.sh drives the isolation PRIMITIVES with unshare(1); launcher.sh
# drives `kryptikd run`. They are different claims - the primitives can be
# sound while the launcher applies them in the wrong order - so a change to
# the zone path has to pass both, and `zone-tests` is the target that says so.
launcher-test:
	@cd compartments/kryptikd && cargo build --quiet
	@compartments/tests/launcher.sh

zone-tests: zone-test launcher-test

# --- the developer VM ------------------------------------------------------
#
# KERNEL and SYSROOT are inputs rather than assumptions. Until stage 04 and 05
# produce them, point KERNEL at any bzImage and leave SYSROOT empty: the image
# records that its userspace is not Kryptik's and tools/vm/boot-smoke.sh
# reports "PASSED (HARNESS ONLY)" rather than claiming a Kryptik boot.
VM_OUT     ?= $(ROOT)/build/work/vm
VM_INITRD  ?= $(VM_OUT)/initramfs.cpio.gz
VM_LOG     ?= $(VM_OUT)/serial.log
VM_KRYPTIKD ?= $(ROOT)/compartments/kryptikd/target/x86_64-unknown-linux-musl/release/kryptikd
KERNEL     ?=
SYSROOT    ?=
S6ROOT     ?=

$(VM_KRYPTIKD):
	@cd compartments/kryptikd && cargo build --release --target x86_64-unknown-linux-musl

vm-image: $(VM_KRYPTIKD)
	@test -n "$(S6ROOT)" || { echo "set S6ROOT=<dir with usr/bin/{s6-svscan,busybox}>"; exit 1; }
	@mkdir -p "$(VM_OUT)"
	@"$(ROOT)"/tools/vm/mkinitramfs.sh --out "$(VM_INITRD)" \
	    --kryptikd "$(VM_KRYPTIKD)" --s6root "$(S6ROOT)" \
	    --zones "$(ROOT)/compartments/zones" \
	    $(if $(SYSROOT),--sysroot "$(SYSROOT)",)

# VM_NIC=user gives the guest a NIC on QEMU's internal user-mode NAT. The
# default is none, because a test VM that cannot reach anything is the right
# default - but with a NIC the launcher suite's H1 positive control becomes a
# real one: "the zone sees only lo" means nothing when the host sees only lo
# too, and without a NIC that check reports NOT RUN in the VM, which is the one
# place it runs as root.
VM_NIC ?= none

vm-boot: vm-image
	@test -n "$(KERNEL)" || { echo "set KERNEL=<path to a bzImage>"; exit 1; }
	@"$(ROOT)"/tools/vm/run-qemu.sh --kernel "$(KERNEL)" --initrd "$(VM_INITRD)" \
	    --log "$(VM_LOG)" --mode smoke --nic "$(VM_NIC)" || true
	@"$(ROOT)"/tools/vm/boot-smoke.sh "$(VM_LOG)"

# --- the disk image ---------------------------------------------------------
#
# A separate target from vm-image, and not a flag on it, because the two
# produce different things for different reasons. An initramfs is unpacked into
# the guest's RAM, which is fine for a busybox harness and impossible for a
# real userspace: the stage 04 sysroot is 3.6G. This writes an ext4 filesystem
# with mke2fs -d, which needs no root and no loop device.
VM_DISK      ?= $(VM_OUT)/kryptik-root.img
VM_DISK_SIZE ?= 6G

vm-disk: $(VM_KRYPTIKD)
	@test -n "$(S6ROOT)" || { echo "set S6ROOT=<dir with usr/bin/{s6-svscan,busybox}>"; exit 1; }
	@test -n "$(SYSROOT)" || { echo "set SYSROOT=<a stage 04 sysroot> — without one this would be a busybox image, and vm-image already builds those"; exit 1; }
	@mkdir -p "$(VM_OUT)"
	@"$(ROOT)"/tools/vm/mkinitramfs.sh --out "$(VM_DISK)" --as-disk "$(VM_DISK_SIZE)" \
	    --kryptikd "$(VM_KRYPTIKD)" --s6root "$(S6ROOT)" \
	    --zones "$(ROOT)/compartments/zones" --sysroot "$(SYSROOT)"

# Boot that disk AS the root filesystem. No initramfs: this kernel has
# virtio_blk and ext4 built in, which the guest reports rather than the harness
# assuming.
vm-disk-boot: vm-disk
	@test -n "$(KERNEL)" || { echo "set KERNEL=<path to a bzImage>"; exit 1; }
	@"$(ROOT)"/tools/vm/run-qemu.sh --kernel "$(KERNEL)" --disk "$(VM_DISK)" --root-disk \
	    --log "$(VM_LOG)" --mode smoke --nic "$(VM_NIC)" || true
	@"$(ROOT)"/tools/vm/boot-smoke.sh "$(VM_LOG)"

# Boot it, reboot it from inside, and require the second boot to come back and
# run a zone. Needs the disk: on an initramfs the boot counter would reset every
# time and the guest would reboot until the timeout.
VM_RESTART_LOG ?= $(VM_OUT)/serial-restart.log

vm-restart: vm-disk
	@test -n "$(KERNEL)" || { echo "set KERNEL=<path to a bzImage>"; exit 1; }
	@"$(ROOT)"/tools/vm/run-qemu.sh --kernel "$(KERNEL)" --disk "$(VM_DISK)" --root-disk \
	    --log "$(VM_RESTART_LOG)" --mode restart --nic "$(VM_NIC)" || true
	@"$(ROOT)"/tools/vm/boot-smoke.sh "$(VM_RESTART_LOG)"

# What the last boot cost. Reads the log that is already there rather than
# booting again, so it is free to run and says nothing new if nothing was run.
vm-measure:
	@test -r "$(VM_LOG)" || { echo "no serial log at $(VM_LOG) — run make vm-boot or vm-disk-boot first"; exit 1; }
	@"$(ROOT)"/tools/vm/measure.sh "$(VM_LOG)" $(if $(wildcard $(VM_DISK)),"$(VM_DISK)",)

# The user-facing command's own suite.
cli-test:
	@cd compartments/kryptikd && cargo build --quiet
	@compartments/tests/cli.sh

# The launch daemon, driven over its socket as the desktop drives it: who may
# ask, what a request may carry, the deadline, readiness, the proxy socket.
serve-test:
	@cd compartments/kryptikd && cargo build --quiet
	@compartments/tests/serve.sh

# Update, rollback and recovery of a kryptikd PROGRAM/CONFIG TREE in temporary
# directories (tools/apply-update.sh): the application-tree suite. It is not
# the installed-OS update - that is `update-test` above, which boots real A/B
# media under OVMF. The two used to share one target name, and GNU make took
# the later recipe, so `make update-test` silently ran this suite and the OS
# driver was unreachable. Needs ssh-keygen (the release manifests are OpenSSH
# signatures) and a built kryptikd; without either it exits 77 and says so.
update-tree-test:
	@cd compartments/kryptikd && cargo build --quiet
	@compartments/tests/update.sh

# Runs every unprivileged suite and then names the ones it did not run.
# The shell lives in tools/run-tests.sh rather than inline here: a recipe is
# a bad place for a loop, and make quoting is a bad place for a report.
test:
	@"$(TOOLS)"/run-tests.sh

test-harness:
	@"$(TOOLS)"/test-step-errexit.sh

test-hardening:
	@"$(TOOLS)"/test-hardening-flags.sh

test-artifacts:
	@"$(TOOLS)"/test-artifact-hardening.sh

# What the build PRODUCED, not what it was asked to use.
#
# test-hardening compiles two toy files and proves the flag set can build
# a hardened executable and a hardened shared library. It cannot tell you
# whether the fifty-eight packages in stage 04 actually received those
# flags, and the ways they quietly do not - a configure that overwrites
# CFLAGS, a Makefile with its own hardcoded -O2, libtool relinking at
# install time - fail nothing and are plainly visible in the ELF.
audit-artifacts:
	@"$(TOOLS)"/check-artifact-hardening.sh "$(KRYPTIK_WORK)/sysroot"

audit-artifacts-strict:
	@"$(TOOLS)"/check-artifact-hardening.sh "$(KRYPTIK_WORK)/sysroot" --strict

test-manifest:
	@"$(TOOLS)"/test-artifact-manifest.sh

# The init configuration is the last step of a four-hour stage, and its
# failure modes are quiet - a boot image with no stage 2 scripts, or an
# early getty naming a program that does not exist, both leave the maker
# exiting 0 and the machine booting to silence. The s6 stack builds in
# about a minute, so it is checked up front instead.
# Structural checks on build/services/ that cost a second, against
# mistakes that otherwise surface at the end of a four-hour stage: a
# dependency naming a service that does not exist, a shebang in an
# execline `up`, a script installed into every image that nothing runs.
test-services:
	@"$(TOOLS)"/test-services.sh

# boot-success.sh's decision table (commit, refuse, fall back), driven on
# the host with stand-ins for the services, the ESP and the firmware.
test-boot-success:
	@"$(TOOLS)"/test-boot-success.sh

# The zone identity contract: the zone files, the compositor's colour table
# (generated from them) and the distinctness invariant, checked together.
identity-test:
	@"$(TOOLS)"/test-desktop-identity.sh

# Runs inside the chroot, because it is the TARGET system's C library that has
# to be able to unwind - not the build host's.
# Boot integrity, developer tier. Proves an image is byte-for-byte what this
# build produced; it is not secure boot and not dm-verity, and the tools refuse
# to let a developer signature pass for a release one.
sign-image:
	@"$(TOOLS)"/image/sign-image.sh --image "$(KRYPTIK_WORK)/images/kryptik-dev.img" 		--kernel "$(KRYPTIK_WORK)/sysroot/boot/kryptik-$(V_LINUX)"

verify-image:
	@"$(TOOLS)"/image/verify-image.sh --image "$(KRYPTIK_WORK)/images/kryptik-dev.img" 		--key "$(KRYPTIK_WORK)/images/kryptik-dev.img.pub" --expect-kind developer

# mkdisk runs as root and rm -f's its --out. These prove it will only ever
# aim that at a regular file.
# Installs onto a blank virtual disk in one VM, then BOOTS that disk in a
# second one. The second half is the point: "the installer exited 0" and
# "what it wrote comes up" are different claims.

test-mkdisk-guards:
	@"$(TOOLS)"/test-mkdisk-guards.sh

test-installer:
	@"$(TOOLS)"/test-installer.sh

test-image-signing:
	@"$(TOOLS)"/test-image-signing.sh

test-libc-unwind:
	@$(CHROOT_RUN) run /kryptik/tools/test-libc-unwind.sh

# Build a bootable disk image from a finished sysroot and a kernel.
#   make image KERNEL=... IMAGE=...
IMAGE ?= $(KRYPTIK_OUT)/kryptik-dev.img
KERNEL ?=
image:
	@mkdir -p "$(dir $(IMAGE))"
	@"$(TOOLS)"/image/mkdisk.sh --sysroot "$(KRYPTIK_WORK)/sysroot" \
	    $(if $(KERNEL),--kernel "$(KERNEL)",) --out "$(IMAGE)"

image-smoke:
	@"$(TOOLS)"/image/boot-smoke.sh --image "$(IMAGE)" --kernel "$(KERNEL)"

image-boot:
	@"$(TOOLS)"/image/run-qemu-disk.sh --image "$(IMAGE)" \
	    $(if $(KERNEL),--kernel "$(KERNEL)",) --mode $(or $(MODE),console)

test-s6-init:
	@"$(TOOLS)"/test-s6-init-config.sh

# Runs the built userland instead of listing it. boot-check asserts files
# exist; this executes them, compiles a program with the target compiler
# inside the target, and loads hardened_malloc. Needs root and a finished
# sysroot, so it is not part of the unit suites.
smoke-userspace:
	@$(SUDO) "$(TOOLS)"/test-userspace-smoke.sh

# An identity record for the tree, and for what produced it. Answers the
# three questions you cannot answer by looking at a sysroot: is this the
# one you tested, what went into it, and has anything touched it since.
manifest:
	@"$(TOOLS)"/artifact-manifest.sh --root "$(KRYPTIK_WORK)/sysroot" \
	                                  --out  "$(KRYPTIK_WORK)/artifact-manifest.txt"

verify-manifest:
	@"$(TOOLS)"/artifact-manifest.sh --root "$(KRYPTIK_WORK)/sysroot" \
	                                  --verify "$(KRYPTIK_WORK)/artifact-manifest.txt"

audit:
	@"$(TOOLS)"/audit-setuid.sh

# Archive rather than delete. Stamps are the only record of what a previous
# run actually completed, and a stamp that can no longer be trusted is still
# evidence worth keeping.
reset-stamps:
	@if [[ -d "$(KRYPTIK_WORK)/.stamps" ]]; then \
	    dest="$(KRYPTIK_WORK)/.stamps/legacy/reset-$$(date +%Y%m%dT%H%M%S)"; \
	    mkdir -p "$$dest"; \
	    found=0; \
	    for f in "$(KRYPTIK_WORK)/.stamps"/*; do \
	        [[ -f "$$f" ]] || continue; \
	        mv "$$f" "$$dest/"; found=1; \
	    done; \
	    if [[ "$$found" == 1 ]]; then echo "archived stamps to $$dest"; \
	    else rmdir "$$dest" 2>/dev/null || true; echo "no stamps to archive"; fi; \
	else echo "no stamp directory at $(KRYPTIK_WORK)/.stamps"; fi

# Never remove a tree that still has filesystems mounted inside it. The chroot
# bind-mounts the host's /dev into the sysroot; rm -rf over that is how a build
# system eats its host.
clean:
	@"$(CHROOTD)" guard-unmounted
	@rm -rf "$(KRYPTIK_WORK)"
	@echo "removed $(KRYPTIK_WORK)"

distclean: clean
	@rm -rf "$(KRYPTIK_OUT)" "$(KRYPTIK_SOURCES)"
	@echo "removed $(KRYPTIK_OUT) and $(KRYPTIK_SOURCES)"
