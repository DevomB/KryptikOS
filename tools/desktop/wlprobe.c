/* wlprobe: list the Wayland globals a client is offered, and try to bind one.
 * A raw-socket client without libwayland (wire format: compositor/wlproxy/src/wire.rs).
 * In a zone it shows what the zone's proxy lets through; in zone 0, the
 * compositor's full set.
 *
 *   wlprobe list              print "global <name> <interface> <version>" per global
 *   wlprobe bind INTERFACE [NAME]
 *                             list, then bind INTERFACE by its offered name, or
 *                             as global NAME (from another client's list), or 1,
 *                             and print what came back
 *   wlprobe oversize EXTRA SECONDS [TITLE]
 *                             map a window and answer every configure with a
 *                             buffer EXTRA px wider and taller than asked, in a
 *                             colour no zone has; stay SECONDS, titled TITLE
 *                             ("oversize" by default, at most 255 bytes)
 *   wlprobe fullscreen SECONDS [late]
 *                             as oversize 0, and once drawn ask for fullscreen;
 *                             a commit says when its configure was fullscreen;
 *                             with late, ask once the keyboard has left the window
 *   wlprobe child SECONDS [late]
 *                             as oversize 0, and once drawn map a second window
 *                             that is a child of the first; with late, only
 *                             once the first's configure was fullscreen
 *   A held window's app_id is $WLPROBE_APP_ID (at most 255 bytes), or wlprobe.
 *   Every held window prints "keyboard entered|left the window|the child"
 *   as wl_keyboard reports it: where the keys go, not what a record says.
 *   wlprobe charge [keep]     map one unwritten 4 MiB shmem buffer for 10 s;
 *                             compare zone and compositor cgroup memory.current;
 *                             with keep, 4 s after it is drawn the buffer and its
 *                             pool go and the window unmaps, the pool's
 *                             descriptor kept, as a zone may keep it
 *   wlprobe cursor SECONDS [shape]
 *                             as oversize 0, and when the pointer enters, set a
 *                             cursor image twice the screen's size, hotspot in
 *                             its middle: drawn, it covers the whole screen.
 *                             Says when the window, and when the cursor image,
 *                             enters an output: the second only if the
 *                             compositor took the image, and each pointer
 *                             button it is sent. With shape, also ask
 *                             for the text cursor by name (wp_cursor_shape_v1)
 *   wlprobe animate SECONDS   as oversize 0, and once drawn commit again on
 *                             every frame callback for SECONDS; then say how
 *                             many frames came, how far the compositor's frame
 *                             times and this process's monotonic clock each
 *                             ran, and how far apart the two clocks are
 *   wlprobe popup SECONDS [grab]
 *                             as oversize 0, and once drawn open a popup from
 *                             the window's centre, larger than the screen, that
 *                             may be neither moved nor resized, and answer its
 *                             configure 200 px larger still, in cyan; with grab,
 *                             grab the keyboard for it with a made-up serial.
 *                             Says the popup's configure and when it is done
 *   wlprobe copy SECONDS TEXT as oversize 0, and when the keyboard first enters
 *                             the window, copy TEXT as text/plain;charset=utf-8
 *                             (wl_data_device.set_selection), and write it to
 *                             each reader; says "copied" and "sent to a reader"
 *   wlprobe paste SECONDS     as oversize 0, and say each selection it is
 *                             offered: "pasted: TEXT", or "no selection"
 *   wlprobe outputs           bind every wl_output offered, at version 4 at most,
 *                             and print what each says, a line per event:
 *                             "output ID geometry WxH mm make \"MAKE\" model
 *                             \"MODEL\"", "mode WxH [current]", "scale N",
 *                             "name \"NAME\"", "description \"TEXT\"", "done"
 *   wlprobe scale SECONDS     as oversize 0, and ask for the scale the window
 *                             is shown at (wp_fractional_scale_v1); says each
 *                             one the compositor sends, in 120ths
 *   wlprobe inhibit SECONDS   as oversize 0, and ask that the screen be kept
 *                             awake while the window is shown
 *                             (zwp_idle_inhibit_manager_v1); says when it asked
 *   wlprobe idle MS SECONDS   no window: for SECONDS, say "idled" once the
 *                             session has had no input for MS, and "resumed" at
 *                             the next, as ext_idle_notifier_v1 counts it with
 *                             inhibitors heeded, as the lock's timers are
 *
 * Exit: 0 listed, bind accepted or window held; 3 refused (wl_display.error,
 * or closed); 1 any other failure. The socket is $WAYLAND_DISPLAY, absolute
 * or under $XDG_RUNTIME_DIR.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

static int sock = -1;
static unsigned char inbuf[65536];
static size_t inlen;

static void put32(unsigned char *p, uint32_t v) { memcpy(p, &v, 4); }
static uint32_t get32(const unsigned char *p) { uint32_t v; memcpy(&v, p, 4); return v; }

static int send_msg(uint32_t object, uint16_t opcode, const unsigned char *body, size_t blen)
{
	unsigned char m[4096];
	size_t size = 8 + blen;
	if (size > sizeof m) return -1;
	put32(m, object);
	put32(m + 4, ((uint32_t)size << 16) | opcode);
	memcpy(m + 8, body, blen);
	size_t off = 0;
	while (off < size) {
		ssize_t n = write(sock, m + off, size - off);
		if (n < 0) { if (errno == EINTR) continue; return -1; }
		off += (size_t)n;
	}
	return 0;
}

static size_t put_string(unsigned char *p, const char *s)
{
	size_t len = strlen(s) + 1;
	put32(p, (uint32_t)len);
	memcpy(p + 4, s, len);
	size_t total = 4 + ((len + 3) & ~(size_t)3);
	memset(p + 4 + len, 0, total - 4 - len);
	return total;
}

/* As send_msg, with one descriptor riding along (wl_shm.create_pool). */
static int send_msg_fd(uint32_t object, uint16_t opcode, const unsigned char *body, size_t blen, int fd)
{
	unsigned char m[64];
	size_t size = 8 + blen;
	if (size > sizeof m) return -1;
	put32(m, object);
	put32(m + 4, ((uint32_t)size << 16) | opcode);
	memcpy(m + 8, body, blen);
	struct iovec iov = { m, size };
	union { struct cmsghdr h; char buf[CMSG_SPACE(sizeof(int))]; } c;
	memset(&c, 0, sizeof c);
	struct msghdr msg = { .msg_iov = &iov, .msg_iovlen = 1, .msg_control = c.buf, .msg_controllen = sizeof c.buf };
	struct cmsghdr *cm = CMSG_FIRSTHDR(&msg);
	cm->cmsg_level = SOL_SOCKET;
	cm->cmsg_type = SCM_RIGHTS;
	cm->cmsg_len = CMSG_LEN(sizeof(int));
	memcpy(CMSG_DATA(cm), &fd, sizeof(int));
	return sendmsg(sock, &msg, MSG_NOSIGNAL) == (ssize_t)size ? 0 : -1;
}

/* Descriptors that came with events, in order: a keymap's, or a reader's for a copy. */
static int fdq[8], nfds;

static int take_fd(void)
{
	if (!nfds) return -1;
	int fd = fdq[0];
	memmove(fdq, fdq + 1, (size_t)--nfds * sizeof fdq[0]);
	return fd;
}

/* One read within timeout_ms, with its descriptors: 1 read, 0 timed out, -1 EOF or error. */
static int fill(int timeout_ms)
{
	struct pollfd pfd = { sock, POLLIN, 0 };
	int r = poll(&pfd, 1, timeout_ms);
	if (r <= 0) return r;
	struct iovec iov = { inbuf + inlen, sizeof inbuf - inlen };
	union { struct cmsghdr h; char buf[CMSG_SPACE(8 * sizeof(int))]; } c;
	struct msghdr msg = { .msg_iov = &iov, .msg_iovlen = 1, .msg_control = c.buf, .msg_controllen = sizeof c.buf };
	ssize_t n = recvmsg(sock, &msg, MSG_CMSG_CLOEXEC);
	if (n <= 0) return -1;
	for (struct cmsghdr *cm = CMSG_FIRSTHDR(&msg); cm; cm = CMSG_NXTHDR(&msg, cm)) {
		if (cm->cmsg_level != SOL_SOCKET || cm->cmsg_type != SCM_RIGHTS) continue;
		for (size_t k = 0; k < (cm->cmsg_len - CMSG_LEN(0)) / sizeof(int); k++) {
			int fd;
			memcpy(&fd, CMSG_DATA(cm) + k * sizeof(int), sizeof fd);
			if (nfds < 8) fdq[nfds++] = fd; else close(fd);
		}
	}
	inlen += (size_t)n;
	return 1;
}

struct global { uint32_t name; char iface[128]; uint32_t version; };
static struct global globals[256];
static int nglobals;
static int errored;
static const char *appid = "wlprobe";

/* oversize's object ids: each new id is the next unused one (the registry is 2, its sync 3). */
enum { COMPOSITOR = 4, SHM, WM_BASE, SURFACE, XDG_SURFACE, TOPLEVEL };
static int oversize, charge, drawn, draw_failed, extra, conf_w, conf_h, closed;
/* charge keep: 1 until the pool goes, then 2; the pool, its descriptor and when it was drawn. */
static int charge_keep, keep_fd = -1;
static uint32_t charge_pool;
static time_t drawn_at;
static int askfs, conf_fs;
static int late, kb_left;                    /* fullscreen late: ask once the keyboard has left */
/* child: 1 wanted once drawn, 2 wanted once fullscreen, 3 mapped; its objects. */
static int child, cconf_w, cconf_h;
static uint32_t csurface, cxdg, ctoplevel;
/* popup: 1 wanted once drawn, 2 asked for; with grab, its keyboard grab. */
static int popup, popup_grab, pconf_x, pconf_y, pconf_w, pconf_h;
static uint32_t psurface, pxdg, ppopup;
static uint32_t next_id = TOPLEVEL + 1;
/* animate: the window's last buffer, its frame callback's id (reused once the
 * server frees it: 1 asked, 2 done, 0 freed), and the first and last frame's
 * times by the compositor's clock and by ours. */
static int animate, frames, frame_wait, last_w, last_h;
static uint32_t last_buffer, frame_cb, comp_first, comp_last;
static int64_t own_first, own_last;
static time_t anim_end;

/* copy and paste: the data device's objects, the text, and the last offer and whether it has the text. */
static int copy, paste, copied, offer_text;
static const char *copy_text;
static uint32_t ddm_id, dev_id, src_id, offer_id;
static const char text_mime[] = "text/plain;charset=utf-8";

/* outputs: the wl_output objects bound, ids out_first up to out_last. */
static int outputs;
static uint32_t out_first, out_last;

/* A string argument at p within room bytes into out, empty if it does not fit; the bytes taken. */
static size_t get_string(const unsigned char *p, size_t room, char *out, size_t size)
{
	out[0] = 0;
	if (room < 4) return room;
	uint32_t len = get32(p);
	size_t total = 4 + (((size_t)len + 3) & ~(size_t)3);
	if (total > room) return room;
	if (len) snprintf(out, size, "%.*s", (int)(len - 1), (const char *)p + 4);
	return total;
}

/* The window's colour, magenta, and a popup's, cyan: no zone's, and nothing else draws them. */
static const uint32_t window_rgb = 0xff00ff, popup_rgb = 0x00ffff;

/* A w x h buffer in rgb, attached and committed on a surface. A failure closes the probe. */
static int blit(uint32_t surface, int w, int h, uint32_t rgb)
{
	int stride = w * 4;
	size_t size = (size_t)stride * (size_t)h;
	int fd = memfd_create("wlprobe", MFD_CLOEXEC);
	if (fd < 0 || ftruncate(fd, (off_t)size) < 0) {
		printf("memfd: %s\n", strerror(errno));
		if (fd >= 0) close(fd);
		draw_failed = closed = 1;
		return -1;
	}
	if (!charge) {
		uint32_t *px = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
		if (px == MAP_FAILED) { printf("mmap: %s\n", strerror(errno)); close(fd); draw_failed = closed = 1; return -1; }
		for (size_t i = 0; i < size / 4; i++) px[i] = rgb;
		munmap(px, size);
	}
	uint32_t pool = next_id++, buffer = next_id++;
	unsigned char b[24];
	put32(b, pool);
	put32(b + 4, (uint32_t)size);
	int r = send_msg_fd(SHM, 0, b, 8, fd);     /* wl_shm.create_pool(id, fd, size) */
	if (charge_keep)
		keep_fd = fd;
	else
		close(fd);
	charge_pool = pool;
	if (r) { printf("create_pool: %s\n", strerror(errno)); draw_failed = closed = 1; return -1; }
	put32(b, buffer); put32(b + 4, 0); put32(b + 8, (uint32_t)w); put32(b + 12, (uint32_t)h);
	put32(b + 16, (uint32_t)stride); put32(b + 20, 1);
	if (send_msg(pool, 0, b, 24)) { draw_failed = closed = 1; return -1; } /* wl_shm_pool.create_buffer */
	put32(b, buffer); put32(b + 4, 0); put32(b + 8, 0);
	if (send_msg(surface, 1, b, 12)) { draw_failed = closed = 1; return -1; } /* wl_surface.attach */
	put32(b, 0); put32(b + 4, 0); put32(b + 8, (uint32_t)w); put32(b + 12, (uint32_t)h);
	if (send_msg(surface, 2, b, 16) || send_msg(surface, 6, b, 0)) { draw_failed = closed = 1; return -1; }
	if (surface == SURFACE) { last_buffer = buffer; last_w = w; last_h = h; }
	return 0;
}

/* The window's buffer again, damaged whole, with a frame callback: a client
 * that animates commits once per callback. */
static void next_frame(void)
{
	unsigned char b[16];
	if (!frame_cb) frame_cb = next_id++;
	put32(b, frame_cb);
	send_msg(SURFACE, 3, b, 4);                /* wl_surface.frame */
	put32(b, last_buffer); put32(b + 4, 0); put32(b + 8, 0);
	send_msg(SURFACE, 1, b, 12);               /* wl_surface.attach */
	put32(b, 0); put32(b + 4, 0); put32(b + 8, (uint32_t)last_w); put32(b + 12, (uint32_t)last_h);
	send_msg(SURFACE, 2, b, 16);               /* wl_surface.damage */
	send_msg(SURFACE, 6, b, 0);                /* wl_surface.commit */
	frame_wait = 1;
}

/* A frame was shown at T ms by the compositor's clock, cut to 32 bits as the
 * protocol carries it; ours is read as the event arrives. */
static void frame_done(uint32_t t)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	int64_t own = (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
	if (!frames) { comp_first = t; own_first = own; }
	comp_last = t; own_last = own;
	frames++;
	frame_wait = 2;
}

/* The window's buffer: `extra` px wider and taller than the last configure
 * asked for (a configure of 0 x 0 means the client chooses: 300 x 200). dwl
 * clips a surface only to (w - bw) x (h - bw), so the excess lies under the
 * right and bottom borders. */
static void draw(void)
{
	if (charge && drawn) return;                 /* one sparse pool for one measurement */
	int w = charge ? 1024 : (conf_w > 0 ? conf_w : 300) + extra;
	int h = charge ? 1024 : (conf_h > 0 ? conf_h : 200) + extra;
	if (blit(SURFACE, w, h, window_rgb)) return;
	drawn = 1;
	drawn_at = time(NULL);
	printf("committed %dx%d for a %dx%d configure%s%s\n", w, h, conf_w, conf_h,
		conf_fs ? " (fullscreen)" : "",
		charge ? " (unwritten shmem; sample memory.current now)" : "");
	fflush(stdout);
}

/* The pool and its buffer go and the window unmaps, while this process keeps the pool's
 * descriptor: what the compositor faulted in it stays where it was charged, unless the proxy
 * punches the range. */
static void drop_pool(void)
{
	unsigned char b[12];
	send_msg(last_buffer, 0, b, 0);            /* wl_buffer.destroy */
	send_msg(charge_pool, 1, b, 0);            /* wl_shm_pool.destroy */
	put32(b, 0); put32(b + 4, 0); put32(b + 8, 0);
	send_msg(SURFACE, 1, b, 12);               /* wl_surface.attach: no buffer */
	send_msg(SURFACE, 6, b, 0);                /* wl_surface.commit */
	printf("pool gone, descriptor %d kept (sample memory.current again)\n", keep_fd);
	fflush(stdout);
}

static void draw_child(void)
{
	int w = cconf_w > 0 ? cconf_w : 300, h = cconf_h > 0 ? cconf_h : 200;
	if (blit(csurface, w, h, window_rgb)) return;
	printf("child committed %dx%d\n", w, h);
	fflush(stdout);
}

/* A second toplevel, a child of the first. dwl draws zone 0's above a
 * fullscreen parent; a zone's would cover its parent's bar, so the
 * compositor must keep it below or end the fullscreen. */
static void open_child(void)
{
	unsigned char b[32];
	size_t n;
	csurface = next_id++; cxdg = next_id++; ctoplevel = next_id++;
	put32(b, csurface);
	send_msg(COMPOSITOR, 0, b, 4);             /* wl_compositor.create_surface */
	put32(b, cxdg); put32(b + 4, csurface);
	send_msg(WM_BASE, 2, b, 8);                /* xdg_wm_base.get_xdg_surface */
	put32(b, ctoplevel);
	send_msg(cxdg, 1, b, 4);                   /* xdg_surface.get_toplevel */
	put32(b, TOPLEVEL);
	send_msg(ctoplevel, 1, b, 4);              /* xdg_toplevel.set_parent */
	n = put_string(b, "child");
	send_msg(ctoplevel, 2, b, n);              /* xdg_toplevel.set_title */
	n = put_string(b, "wlprobe");
	send_msg(ctoplevel, 3, b, n);              /* xdg_toplevel.set_app_id */
	send_msg(csurface, 6, b, 0);               /* wl_surface.commit: ask for a configure */
	child = 3;
	puts("asked for a child");
	fflush(stdout);
}

/* cursor: the image is 2560x1600, for a 1280x800 screen, in a colour nothing
 * else draws. */
static const uint32_t cursor_rgb = 0x13f7a5;
static uint32_t seat_id, pointer_id, cursor_surf;
static uint32_t keyboard_id;                 /* every held window says where the keyboard is */
static int cursor;
/* cursor shape: the pointer's device for cursors by name. */
static int cursor_shape;
static uint32_t shape_dev;
/* scale: the window's wp_fractional_scale_v1. */
static int scale;
static uint32_t fscale_id;
/* inhibit: an idle inhibitor on the window; idle: the session's idleness, without one. */
static int inhibit;
static uint32_t idle_note;

/* On every entry, as a client does; the image is made on the first. */
static void set_cursor(uint32_t serial)
{
	int w = 2560, h = 1600, stride = w * 4, fd = -1;
	size_t size = (size_t)stride * (size_t)h;
	unsigned char b[24];
	if (!cursor_surf) {
		fd = memfd_create("wlprobe-cursor", MFD_CLOEXEC);
		if (fd < 0 || ftruncate(fd, (off_t)size) < 0) {
			printf("memfd: %s\n", strerror(errno));
			if (fd >= 0) close(fd);
			return;
		}
		uint32_t *px = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
		if (px == MAP_FAILED) { printf("mmap: %s\n", strerror(errno)); close(fd); return; }
		for (size_t i = 0; i < size / 4; i++) px[i] = cursor_rgb;
		munmap(px, size);
		cursor_surf = next_id++;
		put32(b, cursor_surf);
		send_msg(COMPOSITOR, 0, b, 4);         /* wl_compositor.create_surface */
	}
	put32(b, serial); put32(b + 4, cursor_surf); put32(b + 8, (uint32_t)(w / 2)); put32(b + 12, (uint32_t)(h / 2));
	send_msg(pointer_id, 0, b, 16);            /* wl_pointer.set_cursor */
	if (fd >= 0) {
		uint32_t pool = next_id++, buffer = next_id++;
		put32(b, pool);
		put32(b + 4, (uint32_t)size);
		int r = send_msg_fd(SHM, 0, b, 8, fd); /* wl_shm.create_pool(id, fd, size) */
		close(fd);
		if (r) { printf("create_pool: %s\n", strerror(errno)); return; }
		put32(b, buffer); put32(b + 4, 0); put32(b + 8, (uint32_t)w); put32(b + 12, (uint32_t)h);
		put32(b + 16, (uint32_t)stride); put32(b + 20, 1);
		send_msg(pool, 0, b, 24);              /* wl_shm_pool.create_buffer */
		put32(b, buffer); put32(b + 4, 0); put32(b + 8, 0);
		send_msg(cursor_surf, 1, b, 12);       /* wl_surface.attach */
		put32(b, 0); put32(b + 4, 0); put32(b + 8, (uint32_t)w); put32(b + 12, (uint32_t)h);
		send_msg(cursor_surf, 2, b, 16);       /* wl_surface.damage */
		send_msg(cursor_surf, 6, b, 0);        /* wl_surface.commit */
	}
	printf("set a %dx%d cursor, hotspot %d,%d\n", w, h, w / 2, h / 2);
	if (shape_dev) {
		put32(b, serial);
		put32(b + 4, 9);                       /* text, from the protocol's list */
		send_msg(shape_dev, 1, b, 8);          /* wp_cursor_shape_device_v1.set_shape */
		puts("asked for the text cursor by name");
	}
	fflush(stdout);
}

/* A popup of the window's, anchored at its centre and growing right and down,
 * 1600 x 1600 on a 1280x800 screen, with no adjustment allowed: drawn where
 * asked, it covers whatever lies right of and below the window's centre. */
static void open_popup(void)
{
	unsigned char b[16];
	uint32_t positioner = next_id++;
	int w = conf_w > 0 ? conf_w : 300, h = conf_h > 0 ? conf_h : 200;
	psurface = next_id++; pxdg = next_id++; ppopup = next_id++;
	put32(b, positioner);
	send_msg(WM_BASE, 1, b, 4);                /* xdg_wm_base.create_positioner */
	put32(b, 1600); put32(b + 4, 1600);
	send_msg(positioner, 1, b, 8);             /* xdg_positioner.set_size */
	put32(b, (uint32_t)(w / 2)); put32(b + 4, (uint32_t)(h / 2)); put32(b + 8, 1); put32(b + 12, 1);
	send_msg(positioner, 2, b, 16);            /* xdg_positioner.set_anchor_rect */
	put32(b, 8);
	send_msg(positioner, 4, b, 4);             /* xdg_positioner.set_gravity: bottom_right */
	put32(b, 0);
	send_msg(positioner, 5, b, 4);             /* xdg_positioner.set_constraint_adjustment: none */
	put32(b, psurface);
	send_msg(COMPOSITOR, 0, b, 4);             /* wl_compositor.create_surface */
	put32(b, pxdg); put32(b + 4, psurface);
	send_msg(WM_BASE, 2, b, 8);                /* xdg_wm_base.get_xdg_surface */
	put32(b, ppopup); put32(b + 4, XDG_SURFACE); put32(b + 8, positioner);
	send_msg(pxdg, 2, b, 12);                  /* xdg_surface.get_popup */
	if (popup_grab) {
		put32(b, seat_id); put32(b + 4, 0);
		send_msg(ppopup, 1, b, 8);             /* xdg_popup.grab, with a serial no input gave */
	}
	send_msg(psurface, 6, b, 0);               /* wl_surface.commit: ask for a configure */
	popup = 2;
	printf("asked for a popup%s\n", popup_grab ? " with a keyboard grab" : "");
	fflush(stdout);
}

static void draw_popup(void)
{
	int w = (pconf_w > 0 ? pconf_w : 1600) + 200, h = (pconf_h > 0 ? pconf_h : 1600) + 200;
	if (blit(psurface, w, h, popup_rgb)) return;
	printf("popup committed %dx%d for a %dx%d configure at %d,%d\n", w, h, pconf_w, pconf_h, pconf_x, pconf_y);
	fflush(stdout);
}

/* copy: the text set as the selection, with the serial of the keyboard's enter. */
static void copy_now(uint32_t serial)
{
	unsigned char b[64];
	size_t n;
	src_id = next_id++;
	put32(b, src_id);
	send_msg(ddm_id, 0, b, 4);                 /* wl_data_device_manager.create_data_source */
	n = put_string(b, text_mime);
	send_msg(src_id, 0, b, n);                 /* wl_data_source.offer */
	put32(b, src_id);
	put32(b + 4, serial);
	send_msg(dev_id, 1, b, 8);                 /* wl_data_device.set_selection */
	copied = 1;
	puts("copied");
	fflush(stdout);
}

/* copy: a reader's descriptor, written the text and closed. */
static void send_text(void)
{
	int fd = take_fd();
	if (fd < 0) return;
	size_t len = strlen(copy_text), off = 0;
	while (off < len) {
		ssize_t n = write(fd, copy_text + off, len - off);
		if (n <= 0) break;
		off += (size_t)n;
	}
	close(fd);
	puts("sent to a reader");
	fflush(stdout);
}

/* paste: the offered selection read through a pipe, which the copying client writes. */
static void take_selection(uint32_t offer)
{
	if (!offer) {
		puts("no selection");
		fflush(stdout);
		return;
	}
	if (offer != offer_id || !offer_text) {
		puts("a selection with no text");
		fflush(stdout);
		return;
	}
	int p[2];
	if (pipe2(p, O_CLOEXEC) < 0) return;
	unsigned char b[64];
	size_t n = put_string(b, text_mime);
	send_msg_fd(offer, 1, b, n, p[1]);         /* wl_data_offer.receive */
	close(p[1]);
	char text[256];
	size_t got = 0;
	struct pollfd pfd = { p[0], POLLIN, 0 };
	while (got < sizeof text - 1 && poll(&pfd, 1, 5000) == 1) {
		ssize_t r = read(p[0], text + got, sizeof text - 1 - got);
		if (r <= 0) break;
		got += (size_t)r;
	}
	close(p[0]);
	text[got] = 0;
	printf("pasted: %s\n", text);
	fflush(stdout);
	send_msg(offer, 2, b, 0);                  /* wl_data_offer.destroy */
}

/* Consume one message if present. Returns 1 consumed, 0 need more, -1 malformed. */
static int handle_one(void)
{
	if (inlen < 8) return 0;
	uint32_t object = get32(inbuf), word = get32(inbuf + 4);
	uint16_t size = (uint16_t)(word >> 16), opcode = (uint16_t)(word & 0xffff);
	if (size < 8 || (size & 3)) return -1;
	if (inlen < size) return 0;
	const unsigned char *body = inbuf + 8;
	if (object == 1 && opcode == 0) {
		/* wl_display.error(object_id, code, message) */
		uint32_t oid = get32(body), code = get32(body + 4);
		uint32_t len = get32(body + 8);
		printf("error object=%u code=%u message=%.*s\n", oid, code, (int)(len ? len - 1 : 0), (const char *)body + 12);
		errored = 1;
	} else if (object == 2 && opcode == 0) {
		/* wl_registry.global(name, interface, version) */
		uint32_t name = get32(body);
		uint32_t len = get32(body + 4);
		const char *iface = (const char *)body + 8;
		uint32_t version = get32(body + 8 + ((len + 3) & ~3u));
		printf("global %u %.*s %u\n", name, (int)(len ? len - 1 : 0), iface, version);
		if (nglobals < 256) {
			globals[nglobals].name = name;
			snprintf(globals[nglobals].iface, sizeof globals[nglobals].iface, "%.*s", (int)(len ? len - 1 : 0), iface);
			globals[nglobals].version = version;
			nglobals++;
		}
	} else if (object == 3 && opcode == 0) {
		printf("sync done\n");
	} else if (oversize && object == WM_BASE && opcode == 0) {
		unsigned char b[4];
		put32(b, get32(body));
		send_msg(WM_BASE, 3, b, 4);             /* ping -> xdg_wm_base.pong */
	} else if (oversize && object == TOPLEVEL && opcode == 0) {
		conf_w = (int)get32(body);             /* xdg_toplevel.configure(width, height, states) */
		conf_h = (int)get32(body + 4);
		conf_fs = 0;
		for (uint32_t k = 0, len = get32(body + 8); k + 4 <= len && 16u + k <= size - 8u; k += 4)
			if (get32(body + 12 + k) == 2) conf_fs = 1;  /* xdg_toplevel.state.fullscreen */
	} else if (oversize && object == TOPLEVEL && opcode == 1) {
		closed = 1;                             /* xdg_toplevel.close */
	} else if (oversize && object == XDG_SURFACE && opcode == 0) {
		unsigned char b[4];
		put32(b, get32(body));
		send_msg(XDG_SURFACE, 4, b, 4);         /* xdg_surface.ack_configure */
		draw();
	} else if (child && object == ctoplevel && opcode == 0) {
		cconf_w = (int)get32(body);            /* the child's own configure */
		cconf_h = (int)get32(body + 4);
	} else if (child && object == cxdg && opcode == 0) {
		unsigned char b[4];
		put32(b, get32(body));
		send_msg(cxdg, 4, b, 4);               /* xdg_surface.ack_configure */
		draw_child();
	} else if (popup && object == ppopup && opcode == 0) {
		pconf_x = (int)get32(body);            /* xdg_popup.configure(x, y, width, height) */
		pconf_y = (int)get32(body + 4);
		pconf_w = (int)get32(body + 8);
		pconf_h = (int)get32(body + 12);
	} else if (popup && object == ppopup && opcode == 1) {
		puts("popup done");                     /* xdg_popup.popup_done */
		fflush(stdout);
	} else if (popup && object == pxdg && opcode == 0) {
		unsigned char b[4];
		put32(b, get32(body));
		send_msg(pxdg, 4, b, 4);               /* xdg_surface.ack_configure */
		draw_popup();
	} else if (cursor && object == pointer_id && opcode == 0) {
		set_cursor(get32(body));                /* wl_pointer.enter(serial, surface, x, y) */
	} else if (cursor && object == pointer_id && opcode == 3) {
		/* wl_pointer.button(serial, time, button, state) */
		printf("pointer button %u %s\n", get32(body + 8), get32(body + 12) ? "pressed" : "released");
		fflush(stdout);
	} else if (cursor && opcode == 0 && (object == SURFACE || (cursor_surf && object == cursor_surf))) {
		/* wl_surface.enter(output) */
		printf("%s entered an output\n", object == SURFACE ? "the window" : "the cursor image");
		fflush(stdout);
	} else if (seat_id && object == seat_id && opcode == 0) {
		/* wl_seat.capabilities: the keyboard once there is one, as asking a seat
		 * that never had one is a protocol error (a headless compositor's). */
		if ((get32(body) & 2) && !keyboard_id) {
			unsigned char b[4];
			keyboard_id = next_id++;
			put32(b, keyboard_id);
			send_msg(seat_id, 1, b, 4);    /* wl_seat.get_keyboard */
		}
	} else if (keyboard_id && object == keyboard_id && opcode == 0) {
		int fd = take_fd();                     /* wl_keyboard.keymap: not needed */
		if (fd >= 0) close(fd);
	} else if (keyboard_id && object == keyboard_id && (opcode == 1 || opcode == 2)) {
		uint32_t s = get32(body + 4);          /* wl_keyboard.enter|leave(serial, surface, ...) */
		if (opcode == 2 && s == SURFACE) kb_left = 1;
		printf("keyboard %s %s\n", opcode == 1 ? "entered" : "left",
			s == SURFACE ? "the window" : (csurface && s == csurface) ? "the child"
			: (psurface && s == psurface) ? "the popup" : "another surface");
		fflush(stdout);
		if (copy && !copied && opcode == 1 && s == SURFACE)
			copy_now(get32(body));
	} else if (copy && src_id && object == src_id && opcode == 1) {
		send_text();                            /* wl_data_source.send(mime_type, fd) */
	} else if (copy && src_id && object == src_id && opcode == 2) {
		puts("copy cancelled");                 /* wl_data_source.cancelled */
		fflush(stdout);
	} else if (paste && dev_id && object == dev_id && opcode == 0) {
		offer_id = get32(body);                 /* wl_data_device.data_offer(id) */
		offer_text = 0;
	} else if (paste && offer_id && object == offer_id && opcode == 0) {
		uint32_t len = get32(body);             /* wl_data_offer.offer(mime_type) */
		if (len == sizeof text_mime && len + 12u <= size && !memcmp(body + 4, text_mime, len))
			offer_text = 1;
	} else if (paste && dev_id && object == dev_id && opcode == 5) {
		take_selection(get32(body));            /* wl_data_device.selection(id) */
	} else if (animate && frame_cb && object == frame_cb && opcode == 0) {
		frame_done(get32(body));                /* wl_callback.done(time) */
	} else if (animate && object == 1 && opcode == 1) {
		/* wl_display.delete_id: the callback's id is free for the next frame */
		if (get32(body) == frame_cb && frame_wait == 2) {
			frame_wait = 0;
			if (time(NULL) < anim_end) next_frame();
		}
	} else if (outputs && object >= out_first && object < out_last) {
		/* wl_output: what the client is told of each monitor */
		char a[128], m[128];
		size_t room = (size_t)size - 8, at;
		if (opcode == 0 && room >= 20) {      /* geometry(x, y, mm w, mm h, subpixel, make, model, transform) */
			at = 20 + get_string(body + 20, room - 20, a, sizeof a);
			get_string(body + at, room > at ? room - at : 0, m, sizeof m);
			printf("output %u geometry %dx%d mm make \"%s\" model \"%s\"\n", object,
				(int)get32(body + 8), (int)get32(body + 12), a, m);
		} else if (opcode == 1 && room >= 16) { /* mode(flags, width, height, refresh) */
			printf("output %u mode %ux%u%s\n", object, get32(body + 4), get32(body + 8), get32(body) & 1 ? " current" : "");
		} else if (opcode == 2) {
			printf("output %u done\n", object);
		} else if (opcode == 3 && room >= 4) {
			printf("output %u scale %d\n", object, (int)get32(body));
		} else if (opcode == 4 || opcode == 5) {
			get_string(body, room, a, sizeof a);
			printf("output %u %s \"%s\"\n", object, opcode == 4 ? "name" : "description", a);
		}
		fflush(stdout);
	} else if (scale && object == fscale_id && opcode == 0) {
		/* wp_fractional_scale_v1.preferred_scale(scale), in 120ths */
		printf("preferred scale %u/120\n", get32(body));
		fflush(stdout);
	} else if (idle_note && object == idle_note && opcode <= 1) {
		puts(opcode == 0 ? "idled" : "resumed"); /* ext_idle_notification_v1.idled|resumed */
		fflush(stdout);
	} else if (!oversize) {
		printf("event object=%u opcode=%u size=%u\n", object, opcode, size);
	}
	memmove(inbuf, inbuf + size, inlen - size);
	inlen -= size;
	return 1;
}

static int drain(int timeout_ms)
{
	for (;;) {
		int c = handle_one();
		if (c < 0) { printf("malformed message from the server\n"); return -1; }
		if (c == 1) continue;
		int r = fill(timeout_ms);
		if (r < 0) return -1;   /* EOF */
		if (r == 0) return 0;   /* quiet */
	}
}

static int bind_global(const char *iface, uint32_t id)
{
	uint32_t name = 0;
	for (int i = 0; i < nglobals; i++) if (!strcmp(globals[i].iface, iface)) name = globals[i].name;
	if (!name) { printf("no %s offered\n", iface); return -1; }
	unsigned char b[128];
	size_t n = 0;
	put32(b + n, name); n += 4;
	n += put_string(b + n, iface);
	put32(b + n, 1); n += 4;                    /* version 1 */
	put32(b + n, id); n += 4;
	return send_msg(2, 0, b, n);               /* wl_registry.bind */
}

/* Map a window and answer each configure oversized, for `seconds` or until it is closed. */
static int hold_oversize(int more, int seconds, const char *title)
{
	unsigned char b[280];                      /* a 255-byte title, its length and padding */
	size_t n;
	oversize = 1;
	extra = more;
	if (bind_global("wl_compositor", COMPOSITOR) || bind_global("wl_shm", SHM) || bind_global("xdg_wm_base", WM_BASE))
		return 1;
	put32(b, SURFACE);
	send_msg(COMPOSITOR, 0, b, 4);             /* wl_compositor.create_surface */
	put32(b, XDG_SURFACE); put32(b + 4, SURFACE);
	send_msg(WM_BASE, 2, b, 8);                /* xdg_wm_base.get_xdg_surface */
	put32(b, TOPLEVEL);
	send_msg(XDG_SURFACE, 1, b, 4);            /* xdg_surface.get_toplevel */
	n = put_string(b, title);
	send_msg(TOPLEVEL, 2, b, n);               /* xdg_toplevel.set_title */
	n = put_string(b, appid);
	send_msg(TOPLEVEL, 3, b, n);               /* xdg_toplevel.set_app_id */
	if (cursor) {
		seat_id = next_id++;
		if (bind_global("wl_seat", seat_id)) return 1;
		pointer_id = next_id++;
		put32(b, pointer_id);
		send_msg(seat_id, 0, b, 4);            /* wl_seat.get_pointer */
		/* A client that holds an output is told when a surface of its own
		 * enters it: the window when it is shown, a cursor image when the
		 * compositor takes it. */
		if (bind_global("wl_output", next_id++)) return 1;
		if (cursor_shape) {
			uint32_t mgr = next_id++;
			if (bind_global("wp_cursor_shape_manager_v1", mgr)) return 1;
			shape_dev = next_id++;
			put32(b, shape_dev);
			put32(b + 4, pointer_id);
			send_msg(mgr, 1, b, 8);                /* wp_cursor_shape_manager_v1.get_pointer */
		}
	}
	/* Where the keyboard is, as the compositor tells it: the record the chrome
	 * writes names the window it believes on top, not always the same one. The
	 * seat's capabilities ask for the keyboard (handle_one). */
	if (!seat_id) {
		seat_id = next_id++;
		if (bind_global("wl_seat", seat_id)) return 1;
	}
	if (scale) {
		uint32_t mgr = next_id++;
		if (bind_global("wp_fractional_scale_manager_v1", mgr)) return 1;
		fscale_id = next_id++;
		put32(b, fscale_id);
		put32(b + 4, SURFACE);
		send_msg(mgr, 1, b, 8);                /* wp_fractional_scale_manager_v1.get_fractional_scale */
	}
	if (inhibit) {
		uint32_t mgr = next_id++;
		if (bind_global("zwp_idle_inhibit_manager_v1", mgr)) return 1;
		put32(b, next_id++);
		put32(b + 4, SURFACE);
		send_msg(mgr, 1, b, 8);                /* zwp_idle_inhibit_manager_v1.create_inhibitor */
		puts("asked to keep the screen awake");
		fflush(stdout);
	}
	if (copy || paste) {
		ddm_id = next_id++;
		if (bind_global("wl_data_device_manager", ddm_id)) return 1;
		dev_id = next_id++;
		put32(b, dev_id);
		put32(b + 4, seat_id);
		send_msg(ddm_id, 1, b, 8);             /* wl_data_device_manager.get_data_device */
	}
	send_msg(SURFACE, 6, b, 0);                /* wl_surface.commit: ask for a configure */
	time_t end = time(NULL) + seconds;
	anim_end = end;
	while (time(NULL) < end && !closed) {
		if (drain(500) < 0) { puts(errored ? "refused" : "connection closed"); return 3; }
		/* Then each callback's freed id asks for the next frame, until anim_end. */
		if (animate && drawn && !frame_cb)
			next_frame();
		if (askfs == 1 && drawn && (!late || kb_left)) {
			put32(b, 0);                           /* no output: the compositor's choice */
			send_msg(TOPLEVEL, 11, b, 4);          /* xdg_toplevel.set_fullscreen */
			askfs = 2;
			puts("asked for fullscreen");
			fflush(stdout);
		}
		if ((child == 1 && drawn) || (child == 2 && drawn && conf_fs))
			open_child();
		if (popup == 1 && drawn)
			open_popup();
		if (charge_keep == 1 && drawn && time(NULL) >= drawn_at + 4) {
			drop_pool();
			charge_keep = 2;
		}
	}
	return draw_failed ? 1 : 0;
}

int main(int argc, char **argv)
{
	if (argc < 2 || (strcmp(argv[1], "list") && strcmp(argv[1], "bind") && strcmp(argv[1], "oversize")
	                 && strcmp(argv[1], "fullscreen") && strcmp(argv[1], "child") && strcmp(argv[1], "charge")
	                 && strcmp(argv[1], "cursor") && strcmp(argv[1], "animate") && strcmp(argv[1], "popup")
	                 && strcmp(argv[1], "copy") && strcmp(argv[1], "paste") && strcmp(argv[1], "outputs")
	                 && strcmp(argv[1], "scale")
	                 && strcmp(argv[1], "inhibit") && strcmp(argv[1], "idle"))
	    || (!strcmp(argv[1], "bind") && (argc < 3 || argc > 4)) || (!strcmp(argv[1], "oversize") && argc < 4)
	    || (!strcmp(argv[1], "oversize") && argc > 4 && strlen(argv[4]) > 255)
	    || (!strcmp(argv[1], "fullscreen") && (argc < 3 || argc > 4 || (argc == 4 && strcmp(argv[3], "late"))))
	    || (!strcmp(argv[1], "child") && (argc < 3 || argc > 4 || (argc == 4 && strcmp(argv[3], "late"))))
	    || (!strcmp(argv[1], "charge") && (argc > 3 || (argc == 3 && strcmp(argv[2], "keep"))))
	    || (!strcmp(argv[1], "cursor") && (argc < 3 || argc > 4 || (argc == 4 && strcmp(argv[3], "shape"))))
	    || (!strcmp(argv[1], "animate") && argc != 3)
	    || (!strcmp(argv[1], "popup") && (argc < 3 || argc > 4 || (argc == 4 && strcmp(argv[3], "grab"))))
	    || (!strcmp(argv[1], "copy") && (argc != 4 || strlen(argv[3]) > 200))
	    || (!strcmp(argv[1], "paste") && argc != 3) || (!strcmp(argv[1], "outputs") && argc != 2)
	    || (!strcmp(argv[1], "scale") && argc != 3)
	    || (!strcmp(argv[1], "inhibit") && argc != 3)
	    || (!strcmp(argv[1], "idle") && argc != 4)) {
		fprintf(stderr, "usage: wlprobe list | bind INTERFACE [NAME] | oversize EXTRA SECONDS [TITLE] | fullscreen SECONDS [late] | child SECONDS [late] | charge [keep] | cursor SECONDS [shape] | animate SECONDS | popup SECONDS [grab] | copy SECONDS TEXT | paste SECONDS | outputs | scale SECONDS | inhibit SECONDS | idle MS SECONDS\n");
		return 2;
	}
	const char *own_id = getenv("WLPROBE_APP_ID");
	if (own_id && *own_id) {
		if (strlen(own_id) > 255) { fprintf(stderr, "wlprobe: WLPROBE_APP_ID is over 255 bytes\n"); return 2; }
		appid = own_id;
	}
	const char *disp = getenv("WAYLAND_DISPLAY");
	const char *rt = getenv("XDG_RUNTIME_DIR");
	char path[256];
	int plen;
	if (!disp || !*disp) disp = "wayland-0";
	if (disp[0] == '/') plen = snprintf(path, sizeof path, "%s", disp);
	else if (rt && *rt) plen = snprintf(path, sizeof path, "%s/%s", rt, disp);
	else { fprintf(stderr, "wlprobe: WAYLAND_DISPLAY is relative and XDG_RUNTIME_DIR is unset\n"); return 1; }

	struct sockaddr_un sa; memset(&sa, 0, sizeof sa); sa.sun_family = AF_UNIX;
	/* Cut short, the path would name another socket: refused, as libwayland refuses it. */
	if (plen < 0 || (size_t)plen >= sizeof sa.sun_path) {
		fprintf(stderr, "wlprobe: the socket path is over %zu bytes\n", sizeof sa.sun_path - 1);
		return 1;
	}
	memcpy(sa.sun_path, path, (size_t)plen + 1);
	sock = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (connect(sock, (struct sockaddr *)&sa, sizeof sa) < 0) { fprintf(stderr, "wlprobe: connect %s: %s\n", path, strerror(errno)); return 1; }
	printf("connected %s\n", path);

	unsigned char body[16];
	put32(body, 2);
	if (send_msg(1, 1, body, 4)) return 1;       /* wl_display.get_registry -> 2 */
	put32(body, 3);
	if (send_msg(1, 0, body, 4)) return 1;       /* wl_display.sync -> callback 3 */
	int r = drain(3000);
	if (r < 0 && !errored) { printf("closed before the registry was listed\n"); return 1; }
	printf("globals %d\n", nglobals);

	if (!strcmp(argv[1], "list")) return errored ? 3 : 0;
	if (!strcmp(argv[1], "outputs")) {
		/* Every one bound, then a sync: what they say comes before its answer. */
		unsigned char b[128];
		outputs = 1;
		/* The first new id is 4, after the registry and its sync: one that skips is refused. */
		next_id = COMPOSITOR;
		out_first = next_id;
		for (int i = 0; i < nglobals; i++) {
			if (strcmp(globals[i].iface, "wl_output")) continue;
			size_t n = 0;
			put32(b + n, globals[i].name); n += 4;
			n += put_string(b + n, "wl_output");
			put32(b + n, globals[i].version < 4 ? globals[i].version : 4); n += 4;
			put32(b + n, next_id++); n += 4;
			if (send_msg(2, 0, b, n)) return 1;       /* wl_registry.bind */
		}
		out_last = next_id;
		put32(body, next_id++);
		if (send_msg(1, 0, body, 4)) return 1;       /* wl_display.sync */
		if (drain(2000) < 0 && !errored) { printf("closed while the outputs spoke\n"); return 1; }
		printf("outputs %u\n", out_last - out_first);
		return errored ? 3 : 0;
	}
	if (!strcmp(argv[1], "oversize")) return hold_oversize(atoi(argv[2]), atoi(argv[3]), argc > 4 ? argv[4] : "oversize");
	if (!strcmp(argv[1], "fullscreen")) { askfs = 1; late = argc == 4; return hold_oversize(0, atoi(argv[2]), "fullscreen"); }
	if (!strcmp(argv[1], "child")) { child = argc == 4 ? 2 : 1; return hold_oversize(0, atoi(argv[2]), "child-parent"); }
	if (!strcmp(argv[1], "charge")) { charge = 1; charge_keep = argc == 3; return hold_oversize(0, 10, "shm-charge"); }
	if (!strcmp(argv[1], "cursor")) { cursor = 1; cursor_shape = argc == 4; return hold_oversize(0, atoi(argv[2]), "cursor"); }
	if (!strcmp(argv[1], "popup")) { popup = 1; popup_grab = argc == 4; return hold_oversize(0, atoi(argv[2]), "popup"); }
	if (!strcmp(argv[1], "copy")) {
		/* A reader that hangs up early is told by write's return, not a signal. */
		signal(SIGPIPE, SIG_IGN);
		copy = 1;
		copy_text = argv[3];
		return hold_oversize(0, atoi(argv[2]), "copy");
	}
	if (!strcmp(argv[1], "paste")) { paste = 1; return hold_oversize(0, atoi(argv[2]), "paste"); }
	if (!strcmp(argv[1], "scale")) { scale = 1; return hold_oversize(0, atoi(argv[2]), "scale"); }
	if (!strcmp(argv[1], "inhibit")) { inhibit = 1; return hold_oversize(0, atoi(argv[2]), "inhibit"); }
	if (!strcmp(argv[1], "idle")) {
		unsigned char b[12];
		idle_note = 6;
		if (bind_global("ext_idle_notifier_v1", 4) || bind_global("wl_seat", 5)) return 1;
		put32(b, idle_note);
		put32(b + 4, (uint32_t)strtoul(argv[2], NULL, 10));
		put32(b + 8, 5);
		send_msg(4, 1, b, 12);                  /* ext_idle_notifier_v1.get_idle_notification */
		printf("watching for %s ms without input\n", argv[2]);
		fflush(stdout);
		time_t end = time(NULL) + atoi(argv[3]);
		while (time(NULL) < end)
			if (drain(500) < 0) { puts(errored ? "refused" : "connection closed"); return 3; }
		return errored ? 3 : 0;
	}
	if (!strcmp(argv[1], "animate")) {
		animate = 1;
		int held = hold_oversize(0, atoi(argv[2]), "animate");
		/* Ours cut to 32 bits like the compositor's: their difference, signed, is the gap. */
		printf("animated: %d frames; the compositor's frame times ran %u ms and this process's "
		       "monotonic clock %lld ms; the compositor's clock is %d ms from this process's\n",
		       frames, comp_last - comp_first, (long long)(own_last - own_first),
		       (int32_t)(comp_last - (uint32_t)own_last));
		return held ? held : frames ? 0 : 1;
	}

	/* A hidden global's name is unknown to a filtered client: NAME gives it, from another
	 * client's list, or 1 is guessed; refused either way. */
	const char *want = argv[2];
	uint32_t name = argc > 3 ? (uint32_t)strtoul(argv[3], NULL, 10) : 1, version = 1;
	for (int i = 0; i < nglobals; i++) if (!strcmp(globals[i].iface, want)) { name = globals[i].name; version = globals[i].version; }
	unsigned char b[512]; size_t n = 0;
	put32(b + n, name); n += 4;
	n += put_string(b + n, want);
	put32(b + n, version); n += 4;
	put32(b + n, 4); n += 4;                     /* new_id 4 */
	printf("bind %s name=%u version=%u -> object 4\n", want, name, version);
	if (send_msg(2, 0, b, n)) return 1;
	put32(body, 5);
	send_msg(1, 0, body, 4);                    /* sync -> 5, to see whether we are still connected */
	errored = 0;
	r = drain(3000);
	if (errored) { printf("bind refused: the server sent wl_display.error and closed\n"); return 3; }
	if (r < 0) { printf("connection closed without an error message\n"); return 3; }
	printf("bind accepted: the connection is still open\n");
	return 0;
}
