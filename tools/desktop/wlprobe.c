/* wlprobe: list the Wayland globals a client is offered, and try to bind one.
 * A raw-socket client without libwayland (wire format: compositor/wlproxy's
 * wire.rs). In a zone it shows what the zone's proxy lets through; in zone 0,
 * the compositor's full set.
 *
 *   wlprobe list              print "global <name> <interface> <version>" per global
 *   wlprobe bind INTERFACE    list, then bind INTERFACE by its offered name
 *                             (name 1 if not offered) and print what came back
 *   wlprobe oversize EXTRA SECONDS [TITLE]
 *                             map a window and answer every configure with a
 *                             buffer EXTRA px wider and taller than asked, in a
 *                             colour no zone has; stay SECONDS, titled TITLE
 *                             ("oversize" by default, at most 255 bytes)
 *   wlprobe fullscreen SECONDS
 *                             as oversize 0, and once drawn ask for fullscreen;
 *                             a commit says when its configure was fullscreen
 *   wlprobe child SECONDS [late]
 *                             as oversize 0, and once drawn map a second window
 *                             that is a child of the first; with late, only
 *                             once the first's configure was fullscreen
 *   Every held window prints "keyboard entered|left the window|the child"
 *   as wl_keyboard reports it: where the keys go, not what a record says.
 *   wlprobe charge            map one unwritten 4 MiB shmem buffer for 10 s;
 *                             compare zone and compositor cgroup memory.current
 *   wlprobe cursor SECONDS    as oversize 0, and when the pointer enters, set a
 *                             cursor image twice the screen's size, hotspot in
 *                             its middle: drawn, it covers the whole screen.
 *                             Says when the window, and when the cursor image,
 *                             enters an output: the second only if the
 *                             compositor took the image
 *
 * Exit: 0 listed, bind accepted or window held; 3 refused (wl_display.error,
 * or closed); 1 any other failure. The socket is $WAYLAND_DISPLAY, absolute
 * or under $XDG_RUNTIME_DIR.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <poll.h>
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

/* One read within timeout_ms: 1 read, 0 timed out, -1 EOF or error. */
static int fill(int timeout_ms)
{
	struct pollfd pfd = { sock, POLLIN, 0 };
	int r = poll(&pfd, 1, timeout_ms);
	if (r <= 0) return r;
	ssize_t n = read(sock, inbuf + inlen, sizeof inbuf - inlen);
	if (n <= 0) return -1;
	inlen += (size_t)n;
	return 1;
}

struct global { uint32_t name; char iface[128]; uint32_t version; };
static struct global globals[256];
static int nglobals;
static int errored;

/* oversize: the window's objects, by the ids this client gives them. A new
 * id must be the next unused one (the registry is 2, its sync 3). */
enum { COMPOSITOR = 4, SHM, WM_BASE, SURFACE, XDG_SURFACE, TOPLEVEL };
static int oversize, charge, drawn, draw_failed, extra, conf_w, conf_h, closed;
static int askfs, conf_fs;
/* child: 1 wanted once drawn, 2 wanted once fullscreen, 3 mapped; its objects. */
static int child, cconf_w, cconf_h;
static uint32_t csurface, cxdg, ctoplevel;
static uint32_t next_id = TOPLEVEL + 1;

/* A w x h buffer in magenta, which is no zone's colour, attached and
 * committed on a surface. A failure closes the probe. */
static int blit(uint32_t surface, int w, int h)
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
		for (size_t i = 0; i < size / 4; i++) px[i] = 0x00ff00ff;
		munmap(px, size);
	}
	uint32_t pool = next_id++, buffer = next_id++;
	unsigned char b[24];
	put32(b, pool);
	put32(b + 4, (uint32_t)size);
	int r = send_msg_fd(SHM, 0, b, 8, fd);     /* wl_shm.create_pool(id, fd, size) */
	close(fd);
	if (r) { printf("create_pool: %s\n", strerror(errno)); draw_failed = closed = 1; return -1; }
	put32(b, buffer); put32(b + 4, 0); put32(b + 8, (uint32_t)w); put32(b + 12, (uint32_t)h);
	put32(b + 16, (uint32_t)stride); put32(b + 20, 1);
	if (send_msg(pool, 0, b, 24)) { draw_failed = closed = 1; return -1; } /* wl_shm_pool.create_buffer */
	put32(b, buffer); put32(b + 4, 0); put32(b + 8, 0);
	if (send_msg(surface, 1, b, 12)) { draw_failed = closed = 1; return -1; } /* wl_surface.attach */
	put32(b, 0); put32(b + 4, 0); put32(b + 8, (uint32_t)w); put32(b + 12, (uint32_t)h);
	if (send_msg(surface, 2, b, 16) || send_msg(surface, 6, b, 0)) { draw_failed = closed = 1; return -1; }
	return 0;
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
	if (blit(SURFACE, w, h)) return;
	drawn = 1;
	printf("committed %dx%d for a %dx%d configure%s%s\n", w, h, conf_w, conf_h,
		conf_fs ? " (fullscreen)" : "",
		charge ? " (unwritten shmem; sample memory.current now)" : "");
	fflush(stdout);
}

static void draw_child(void)
{
	int w = cconf_w > 0 ? cconf_w : 300, h = cconf_h > 0 ? cconf_h : 200;
	if (blit(csurface, w, h)) return;
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
	fflush(stdout);
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
	} else if (cursor && object == pointer_id && opcode == 0) {
		set_cursor(get32(body));                /* wl_pointer.enter(serial, surface, x, y) */
	} else if (cursor && opcode == 0 && (object == SURFACE || (cursor_surf && object == cursor_surf))) {
		/* wl_surface.enter(output) */
		printf("%s entered an output\n", object == SURFACE ? "the window" : "the cursor image");
		fflush(stdout);
	} else if (keyboard_id && object == keyboard_id && (opcode == 1 || opcode == 2)) {
		uint32_t s = get32(body + 4);          /* wl_keyboard.enter|leave(serial, surface, ...) */
		printf("keyboard %s %s\n", opcode == 1 ? "entered" : "left",
			s == SURFACE ? "the window" : (csurface && s == csurface) ? "the child" : "another surface");
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

/* Map one window and answer each configure with an oversized buffer until
 * `seconds` pass or the compositor closes it. */
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
	n = put_string(b, "wlprobe");
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
	}
	/* Where the keyboard is, as the compositor tells it: the record the chrome
	 * writes names the window it believes on top, not always the same one. */
	if (!seat_id) {
		seat_id = next_id++;
		if (bind_global("wl_seat", seat_id)) return 1;
	}
	keyboard_id = next_id++;
	put32(b, keyboard_id);
	send_msg(seat_id, 1, b, 4);                /* wl_seat.get_keyboard */
	send_msg(SURFACE, 6, b, 0);                /* wl_surface.commit: ask for a configure */
	time_t end = time(NULL) + seconds;
	while (time(NULL) < end && !closed) {
		if (drain(500) < 0) { puts(errored ? "refused" : "connection closed"); return 3; }
		if (askfs == 1 && drawn) {
			put32(b, 0);                           /* no output: the compositor's choice */
			send_msg(TOPLEVEL, 11, b, 4);          /* xdg_toplevel.set_fullscreen */
			askfs = 2;
			puts("asked for fullscreen");
			fflush(stdout);
		}
		if ((child == 1 && drawn) || (child == 2 && drawn && conf_fs))
			open_child();
	}
	return draw_failed ? 1 : 0;
}

int main(int argc, char **argv)
{
	if (argc < 2 || (strcmp(argv[1], "list") && strcmp(argv[1], "bind") && strcmp(argv[1], "oversize")
	                 && strcmp(argv[1], "fullscreen") && strcmp(argv[1], "child") && strcmp(argv[1], "charge")
	                 && strcmp(argv[1], "cursor"))
	    || (!strcmp(argv[1], "bind") && argc < 3) || (!strcmp(argv[1], "oversize") && argc < 4)
	    || (!strcmp(argv[1], "oversize") && argc > 4 && strlen(argv[4]) > 255)
	    || (!strcmp(argv[1], "fullscreen") && argc != 3)
	    || (!strcmp(argv[1], "child") && (argc < 3 || argc > 4 || (argc == 4 && strcmp(argv[3], "late"))))
	    || (!strcmp(argv[1], "charge") && argc != 2)
	    || (!strcmp(argv[1], "cursor") && argc != 3)) {
		fprintf(stderr, "usage: wlprobe list | bind INTERFACE | oversize EXTRA SECONDS [TITLE] | fullscreen SECONDS | child SECONDS [late] | charge | cursor SECONDS\n");
		return 2;
	}
	const char *disp = getenv("WAYLAND_DISPLAY");
	const char *rt = getenv("XDG_RUNTIME_DIR");
	char path[256];
	if (!disp || !*disp) disp = "wayland-0";
	if (disp[0] == '/') snprintf(path, sizeof path, "%s", disp);
	else if (rt && *rt) snprintf(path, sizeof path, "%s/%s", rt, disp);
	else { fprintf(stderr, "wlprobe: WAYLAND_DISPLAY is relative and XDG_RUNTIME_DIR is unset\n"); return 1; }

	sock = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	struct sockaddr_un sa; memset(&sa, 0, sizeof sa); sa.sun_family = AF_UNIX;
	snprintf(sa.sun_path, sizeof sa.sun_path, "%s", path);
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
	if (!strcmp(argv[1], "oversize")) return hold_oversize(atoi(argv[2]), atoi(argv[3]), argc > 4 ? argv[4] : "oversize");
	if (!strcmp(argv[1], "fullscreen")) { askfs = 1; return hold_oversize(0, atoi(argv[2]), "fullscreen"); }
	if (!strcmp(argv[1], "child")) { child = argc == 4 ? 2 : 1; return hold_oversize(0, atoi(argv[2]), "child-parent"); }
	if (!strcmp(argv[1], "charge")) { charge = 1; return hold_oversize(0, 10, "shm-charge"); }
	if (!strcmp(argv[1], "cursor")) { cursor = 1; return hold_oversize(0, atoi(argv[2]), "cursor"); }

	/* A filtered client cannot know a hidden global's name, so guess 1; the
	 * proxy must refuse either way. */
	const char *want = argv[2];
	uint32_t name = 1, version = 1;
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
