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

export KRYPTIK_ROOT := $(ROOT)

.PHONY: help check check-kernel-eol sources lock verify verify-provenance test-harness validate-kernel validate-kernel-hardened toolchain temp-tools chroot system kernel iso audit zones zone-test launcher-test zone-tests vm-image vm-boot clean distclean

help:
	@echo "Kryptik build targets"
	@echo
	@echo "  make check       verify the host can build Kryptik"
	@echo "  make sources     fetch upstream tarballs, verify against sources.lock"
	@echo "  make lock        fetch and regenerate sources.lock (audit before committing)"
	@echo "  make toolchain   stage 01: cross toolchain           [Phase 1]"
	@echo "  make temp-tools  stage 02: temporary tools + chroot  [Phase 2]"
	@echo "  make chroot      stage 03: prepare chroot (needs root) [Phase 3]"
	@echo "  make system      stage 04: hardened base system      [Phase 3]"
	@echo "  make kernel      stage 05: hardened kernel           [Phase 4]"
	@echo "  make iso         stage 06: bootable image            [Phase 7]"
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
	@echo "  make vm-image    build the developer VM initramfs"
	@echo "  make vm-boot     boot it under QEMU and check the serial log"
	@echo "  make test-harness      verify failed builds cannot be stamped ok"
	@echo "  make audit       run security audits over the build tree"
	@echo "  make clean       remove build work directory"
	@echo "  make distclean   also remove downloaded sources and output"
	@echo
	@echo "Status: pre-alpha. See docs/roadmap.md for what actually works."

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

toolchain: check sources
	@"$(STAGES)"/01-toolchain.sh

temp-tools: toolchain
	@"$(STAGES)"/02-temp-tools.sh

chroot: temp-tools
	@echo "stage 03 needs root:"
	@echo "  sudo '$(STAGES)/03-chroot-prep.sh' mount"

# `make system` cannot simply run stage 04: that stage must execute INSIDE the
# chroot, and it refuses to run anywhere else. Invoking it directly from here
# always failed. Root is required to mount the chroot, so this target tells the
# operator exactly what to run rather than pretending it can do it itself.
system:
	@echo "Stage 04 builds the base system INSIDE the chroot, and needs root"
	@echo "to establish it. Run:"
	@echo
	@echo "  sudo '$(STAGES)/03-chroot-prep.sh' mount"
	@echo "  sudo chroot '$(ROOT)/build/work/sysroot' /usr/bin/env -i \\"
	@echo "      HOME=/root TERM=\$$TERM PATH=/usr/bin:/usr/sbin \\"
	@echo "      KRYPTIK_ROOT=/kryptik KRYPTIK_JOBS=\$$(nproc) \\"
	@echo "      /bin/bash -c /kryptik/build/stages/04-base-system.sh"
	@echo
	@echo "Then: sudo $(STAGES)/03-chroot-prep.sh' umount"
	@false

# Same constraint as `system`: the kernel is built inside the chroot.
kernel:
	@echo "Stage 05 runs inside the chroot, like stage 04. See: make system"
	@false

iso: kernel
	@"$(STAGES)"/06-iso.sh

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

vm-boot: vm-image
	@test -n "$(KERNEL)" || { echo "set KERNEL=<path to a bzImage>"; exit 1; }
	@"$(ROOT)"/tools/vm/run-qemu.sh --kernel "$(KERNEL)" --initrd "$(VM_INITRD)" \
	    --log "$(VM_LOG)" --mode smoke || true
	@"$(ROOT)"/tools/vm/boot-smoke.sh "$(VM_LOG)"

test-harness:
	@"$(TOOLS)"/test-step-errexit.sh

audit:
	@"$(TOOLS)"/audit-setuid.sh

clean:
	@rm -rf "$(ROOT)/build/work"
	@echo "removed build/work"

distclean: clean
	@rm -rf "$(ROOT)/out" "$(ROOT)/sources"
	@echo "removed out/ and sources/"
