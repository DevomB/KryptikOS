/* kryptik-lock: lock the session until the login password is typed (docs/design/laptop.md).
 *
 *   kryptik-lock
 *   kryptik-lock --suspend         lock, then have the launch daemon suspend the machine
 *   kryptik-lock --idle SECONDS [--blank SECONDS]
 *                                  lock each time the session has had no input that long, and
 *                                  turn the screens off that much later (60 s; 0 never)
 *
 * Through ext-session-lock-v1 the compositor shows nothing but this program's surfaces, one
 * per output, and gives them the keyboard. The lock runs in a child, started again if a
 * signal kills it, as the session stays locked without one. What is typed goes to the launch
 * daemon, which answers: this process never reads a password hash. The daemon also says what
 * unlocks: the login password, or once a suspend has dropped the state partition's key, that
 * partition's passphrase, which the label shows (LOCKED, STATE PASSPHRASE). It is asked at
 * the start, at the first key of each entry and before each answer is sent, and what was
 * typed under a label that no longer holds is dropped, so neither secret reaches the other's
 * check. It says "kryptik-lock: locked", "kryptik-lock: refused: WHY" and
 * "kryptik-lock: unlocked" on stderr, the session log.
 * With --idle it waits on the compositor's idle notification (ext-idle-notify-v1), which no
 * zone can bind, and runs itself as the lock when it comes, until the session ends.
 * Exit: 0 unlocked; 1 the compositor would not lock, or there is no display; 2 usage.
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
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <wayland-client.h>
#include <xkbcommon/xkbcommon.h>
#include "ext-idle-notify-v1-client-protocol.h"
#include "ext-session-lock-v1-client-protocol.h"
#include "wlr-output-power-management-unstable-v1-client-protocol.h"

/* Reached without starting a program: while the state partition is suspended, a program's
 * loader would look in /etc, whose upper layer is on that partition. */
#define LAUNCH_SOCKET "/run/kryptik-launch/launch.sock"

/* dwl's root colour behind, a grey no zone has for the marks, and a red for a refusal. */
static const uint32_t bg = 0x101418, ink = 0xe6e6e6, warn = 0xd04040;

/* The words the lock shows, 5x7, bit 4 leftmost: dwl's zone bar font. */
static const struct { char c; unsigned char rows[7]; } font[] = {
	{'A', {0x0e, 0x11, 0x11, 0x11, 0x1f, 0x11, 0x11}},
	{'C', {0x0e, 0x11, 0x10, 0x10, 0x10, 0x11, 0x0e}},
	{'D', {0x1c, 0x12, 0x11, 0x11, 0x11, 0x12, 0x1c}},
	{'E', {0x1f, 0x10, 0x10, 0x1e, 0x10, 0x10, 0x1f}},
	{'G', {0x0e, 0x11, 0x10, 0x17, 0x11, 0x11, 0x0f}},
	{'H', {0x11, 0x11, 0x11, 0x1f, 0x11, 0x11, 0x11}},
	{'I', {0x0e, 0x04, 0x04, 0x04, 0x04, 0x04, 0x0e}},
	{'K', {0x11, 0x12, 0x14, 0x18, 0x14, 0x12, 0x11}},
	{'L', {0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x1f}},
	{'N', {0x11, 0x11, 0x19, 0x15, 0x13, 0x11, 0x11}},
	{'O', {0x0e, 0x11, 0x11, 0x11, 0x11, 0x11, 0x0e}},
	{'P', {0x1e, 0x11, 0x11, 0x1e, 0x10, 0x10, 0x10}},
	{'R', {0x1e, 0x11, 0x11, 0x1e, 0x14, 0x12, 0x11}},
	{'S', {0x0f, 0x10, 0x10, 0x0e, 0x01, 0x01, 0x1e}},
	{'T', {0x1f, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04}},
	{'W', {0x11, 0x11, 0x11, 0x15, 0x15, 0x15, 0x0a}},
	{'0', {0x0e, 0x11, 0x13, 0x15, 0x19, 0x11, 0x0e}},
	{'1', {0x04, 0x0c, 0x04, 0x04, 0x04, 0x04, 0x0e}},
	{'2', {0x0e, 0x11, 0x01, 0x02, 0x04, 0x08, 0x1f}},
	{'3', {0x1f, 0x02, 0x04, 0x02, 0x01, 0x11, 0x0e}},
	{'4', {0x02, 0x06, 0x0a, 0x12, 0x1f, 0x02, 0x02}},
	{'5', {0x1f, 0x10, 0x1e, 0x01, 0x01, 0x11, 0x0e}},
	{'6', {0x06, 0x08, 0x10, 0x1e, 0x11, 0x11, 0x0e}},
	{'7', {0x1f, 0x01, 0x02, 0x04, 0x08, 0x08, 0x08}},
	{'8', {0x0e, 0x11, 0x11, 0x0e, 0x11, 0x11, 0x0e}},
	{'9', {0x0e, 0x11, 0x11, 0x0f, 0x01, 0x02, 0x0c}},
};

struct output {
	struct wl_list link;
	uint32_t name;
	struct wl_output *wl;
	struct wl_surface *surface;
	struct ext_session_lock_surface_v1 *lock_surface;
	int w, h;
};

static struct wl_display *display;
static struct wl_compositor *compositor;
static struct wl_shm *shm;
static struct wl_seat *seat;
static struct wl_keyboard *keyboard;
static struct ext_session_lock_manager_v1 *manager;
static struct ext_session_lock_v1 *lock;
static struct zwlr_output_power_manager_v1 *powermgr;
static struct wl_list outputs;
static struct xkb_context *xkb;
static struct xkb_keymap *keymap;
static struct xkb_state *xstate;
static int locked, done, unlocked;
static char typed[256];
static size_t ntyped;
static char status[24] = "LOCKED";
static int refused;
/* What unlocks, and the label for it. */
enum { LOGIN, STATE };
static int kind = LOGIN;
/* --suspend: asked once locked, then the connection that answers when the machine woke and
 * when it was asked. */
static int suspend_wanted, asleep = -1;
static struct timespec asked;

static void say(const char *what)
{
	fprintf(stderr, "kryptik-lock: %s\n", what);
}

static void show_kind(void)
{
	snprintf(status, sizeof status, "%s", kind == STATE ? "STATE PASSPHRASE" : "LOCKED");
	refused = 0;
}

/* A w x h rectangle at x, y on a bw x bh picture, cut to the picture. */
static void fill(uint32_t *px, int bw, int bh, int x, int y, int w, int h, uint32_t rgb)
{
	for (int j = y < 0 ? 0 : y; j < y + h && j < bh; j++)
		for (int i = x < 0 ? 0 : x; i < x + w && i < bw; i++)
			px[j * bw + i] = rgb;
}

/* The status word, centred above the middle, s px to a font pixel. */
static void text(uint32_t *px, int w, int h, int s, const char *word, uint32_t rgb)
{
	int len = (int)strlen(word), x = (w - (6 * len - 1) * s) / 2, y = h / 2 - 12 * s;
	for (int k = 0; k < len; k++, x += 6 * s)
		for (size_t g = 0; g < sizeof font / sizeof font[0]; g++)
			if (font[g].c == word[k])
				for (int r = 0; r < 7; r++)
					for (int b = 0; b < 5; b++)
						if (font[g].rows[r] & (0x10 >> b))
							fill(px, w, h, x + b * s, y + r * s, s, s, rgb);
}

static void buffer_release(void *data, struct wl_buffer *buffer)
{
	(void)data;
	wl_buffer_destroy(buffer);
}

static const struct wl_buffer_listener buffer_listener = { .release = buffer_release };

/* One output's picture: the status word and a mark for each character typed, nothing else. */
static void draw(struct output *o)
{
	if (!o->lock_surface || o->w <= 0 || o->h <= 0)
		return;
	int stride = o->w * 4, s = o->h / 160 > 2 ? o->h / 160 : 2;
	size_t size = (size_t)stride * (size_t)o->h;
	int fd = memfd_create("kryptik-lock", MFD_CLOEXEC);
	if (fd < 0 || ftruncate(fd, (off_t)size) < 0) {
		if (fd >= 0)
			close(fd);
		return;
	}
	uint32_t *px = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (px == MAP_FAILED) {
		close(fd);
		return;
	}
	fill(px, o->w, o->h, 0, 0, o->w, o->h, bg);
	text(px, o->w, o->h, s, status, refused ? warn : ink);
	int shown = ntyped < 32 ? (int)ntyped : 32, dot = 2 * s;
	int x = (o->w - shown * 2 * dot) / 2, y = o->h / 2 + 2 * s;
	for (int i = 0; i < shown; i++)
		fill(px, o->w, o->h, x + i * 2 * dot, y, dot, dot, ink);
	munmap(px, size);
	struct wl_shm_pool *pool = wl_shm_create_pool(shm, fd, (int32_t)size);
	struct wl_buffer *buffer = wl_shm_pool_create_buffer(pool, 0, o->w, o->h, stride, WL_SHM_FORMAT_XRGB8888);
	wl_shm_pool_destroy(pool);
	close(fd);
	wl_buffer_add_listener(buffer, &buffer_listener, NULL);
	wl_surface_attach(o->surface, buffer, 0, 0);
	wl_surface_damage_buffer(o->surface, 0, 0, o->w, o->h);
	wl_surface_commit(o->surface);
}

static void redraw(void)
{
	struct output *o;
	wl_list_for_each(o, &outputs, link)
		draw(o);
}

static void lock_surface_configure(void *data, struct ext_session_lock_surface_v1 *ls,
		uint32_t serial, uint32_t w, uint32_t h)
{
	struct output *o = data;
	o->w = (int)w;
	o->h = (int)h;
	ext_session_lock_surface_v1_ack_configure(ls, serial);
	draw(o);
}

static const struct ext_session_lock_surface_v1_listener lock_surface_listener = {
	.configure = lock_surface_configure,
};

/* Every output gets a surface of the lock's own, the ones that appear later as well. */
static void cover(struct output *o)
{
	if (!lock || o->lock_surface)
		return;
	o->surface = wl_compositor_create_surface(compositor);
	o->lock_surface = ext_session_lock_v1_get_lock_surface(lock, o->surface, o->wl);
	ext_session_lock_surface_v1_add_listener(o->lock_surface, &lock_surface_listener, o);
}

static int request(const char *text, int fd);

static void lock_locked(void *data, struct ext_session_lock_v1 *l)
{
	(void)data; (void)l;
	locked = 1;
	say("locked");
	/* Only a locked session is suspended; the answer comes once the machine has woken. */
	if (suspend_wanted) {
		clock_gettime(CLOCK_MONOTONIC, &asked);
		asleep = request("suspend\n", -1);
		say(asleep < 0 ? "suspend: the launch daemon cannot be reached" : "suspending");
	}
}

static void lock_finished(void *data, struct ext_session_lock_v1 *l)
{
	(void)data; (void)l;
	say(locked ? "the compositor ended the lock" : "the compositor would not lock");
	done = 1;
}

static const struct ext_session_lock_v1_listener lock_listener = {
	.locked = lock_locked,
	.finished = lock_finished,
};

/* One request to the launch daemon, with `fd` beside its first bytes when >= 0: the connection
 * with its writing side shut, or -1 if the daemon cannot be reached. */
static int request(const char *text, int fd)
{
	struct sockaddr_un sa = { .sun_family = AF_UNIX };
	strncpy(sa.sun_path, LAUNCH_SOCKET, sizeof sa.sun_path - 1);
	int s = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (s < 0)
		return -1;
	if (connect(s, (struct sockaddr *)&sa, sizeof sa) < 0) {
		close(s);
		return -1;
	}
	struct iovec iov = { .iov_base = (void *)text, .iov_len = strlen(text) };
	struct msghdr msg = { .msg_iov = &iov, .msg_iovlen = 1 };
	union { char buf[CMSG_SPACE(sizeof(int))]; struct cmsghdr align; } u;
	if (fd >= 0) {
		memset(&u, 0, sizeof u);
		msg.msg_control = u.buf;
		msg.msg_controllen = sizeof u.buf;
		struct cmsghdr *c = CMSG_FIRSTHDR(&msg);
		c->cmsg_level = SOL_SOCKET;
		c->cmsg_type = SCM_RIGHTS;
		c->cmsg_len = CMSG_LEN(sizeof(int));
		memcpy(CMSG_DATA(c), &fd, sizeof(int));
	}
	if (sendmsg(s, &msg, MSG_NOSIGNAL) != (ssize_t)iov.iov_len) {
		close(s);
		return -1;
	}
	shutdown(s, SHUT_WR);
	return s;
}

/* The daemon's answer on `s`, which is closed: its first line in `why`, and true if that is
 * "ok". While it is awaited the lock reads no events, so one that does not come is given up
 * on: the compositor's buffer of keys for the lock would fill, and end its connection. */
static int answer(int s, char *why, size_t n)
{
	size_t got = 0;
	for (;;) {
		struct pollfd p = { .fd = s, .events = POLLIN };
		int r = poll(&p, 1, 15000);
		if (r < 0 && errno == EINTR)
			continue;
		if (r <= 0) {
			got = 0;
			break;
		}
		ssize_t k = read(s, why + got, n - 1 - got);
		if (k < 0 && errno == EINTR)
			continue;
		if (k <= 0)
			break;
		got += (size_t)k;
		if (got == n - 1)
			break;
	}
	close(s);
	why[got] = 0;
	why[strcspn(why, "\n")] = 0;
	if (!got)
		snprintf(why, n, "no answer from the launch daemon");
	return !strncmp(why, "ok", 2) && (why[2] == 0 || why[2] == ' ');
}

/* What unlocks now, as the daemon says, or -1 if it cannot say. */
static int kind_now(void)
{
	char why[64];
	int s = request("unlock-kind\n", -1);
	if (s < 0 || !answer(s, why, sizeof why))
		return -1;
	return !strcmp(why, "ok state") ? STATE : !strcmp(why, "ok login") ? LOGIN : -1;
}

/* When the label last changed; keys typed within a second of it are dropped. */
static struct timespec relabeled;

/* A label that no longer says what unlocks: what was typed under it is dropped, as it was the
 * other secret, and the right question is shown. True if the label changed. */
static int relabel(int now)
{
	if (now < 0 || now == kind)
		return 0;
	explicit_bzero(typed, sizeof typed);
	ntyped = 0;
	kind = now;
	show_kind();
	clock_gettime(CLOCK_MONOTONIC, &relabeled);
	say(kind == STATE ? "the state partition is suspended: its passphrase unlocks"
	                  : "the state partition is back: the login password unlocks");
	return 1;
}

/* Someone typing on as the label changes is still typing the other secret: for a second, what
 * they type goes nowhere, so its end does not reach the new label's check. */
static int just_relabeled(void)
{
	struct timespec now;
	clock_gettime(CLOCK_MONOTONIC, &now);
	return relabeled.tv_sec && (now.tv_sec - relabeled.tv_sec) * 1000 + (now.tv_nsec - relabeled.tv_nsec) / 1000000 < 1000;
}

/* What was typed, to the check for the label shown: the login password in check-password's
 * body, or the state partition's passphrase in a pipe beside resume-state, the descriptor it
 * takes. True if it was taken; the daemon's words go to `why` otherwise. */
static int give(char *why, size_t n)
{
	int s;
	if (kind == STATE) {
		int p[2];
		if (pipe2(p, O_CLOEXEC) < 0) {
			snprintf(why, n, "pipe: %s", strerror(errno));
			return 0;
		}
		/* Far less than a pipe holds, so the write cannot wait on the reader. */
		int full = write(p[1], typed, ntyped) == (ssize_t)ntyped;
		close(p[1]);
		s = full ? request("resume-state\n", p[0]) : -1;
		close(p[0]);
	} else {
		char req[sizeof typed + 32];
		snprintf(req, sizeof req, "check-password\npassword %s\nend\n", typed);
		s = request(req, -1);
		explicit_bzero(req, sizeof req);
	}
	if (s < 0) {
		snprintf(why, n, "the launch daemon cannot be reached");
		return 0;
	}
	return answer(s, why, n);
}

static void submit(void)
{
	char why[256] = "";
	if (relabel(kind_now()))
		return;
	int ok = give(why, sizeof why);
	explicit_bzero(typed, sizeof typed);
	ntyped = 0;
	if (ok) {
		unlocked = 1;
		return;
	}
	char line[300];
	snprintf(line, sizeof line, "refused: %s", why);
	say(line);
	/* The daemon's own words: "error: suspended: ..." or "error: not suspended: ..." when what
	 * unlocks changed between the question and the answer, "error: wait N s" while a wrong one
	 * is paused for. */
	if (!strncmp(why, "error: suspended:", 17) || !strncmp(why, "error: not suspended:", 21)) {
		relabel(kind_now());
		return;
	}
	const char *w = strstr(why, "wait ");
	if (w)
		snprintf(status, sizeof status, "WAIT %d", atoi(w + 5));
	else
		snprintf(status, sizeof status, "WRONG");
	refused = 1;
}

/* How long the daemon may take to suspend the machine and, once it woke, to say so, counted
 * on the monotonic clock, which stops while the machine sleeps. */
#define SUSPEND_ANSWER_MS 60000

static int suspend_left(void)
{
	struct timespec now;
	clock_gettime(CLOCK_MONOTONIC, &now);
	long ms = (now.tv_sec - asked.tv_sec) * 1000 + (now.tv_nsec - asked.tv_nsec) / 1000000;
	return ms >= SUSPEND_ANSWER_MS ? 0 : (int)(SUSPEND_ANSWER_MS - ms);
}

/* The suspend --suspend asked for has ended: the machine woke, the daemon refused, or no
 * answer came in time. */
static void woke(int answered)
{
	char why[256] = "no answer from the launch daemon", line[300];
	if (answered)
		answer(asleep, why, sizeof why);
	else
		close(asleep);
	asleep = -1;
	snprintf(line, sizeof line, "suspend: %s", why);
	say(line);
	relabel(kind_now());
	redraw();
}

static void keyboard_keymap(void *data, struct wl_keyboard *kb, uint32_t format, int32_t fd, uint32_t size)
{
	(void)data; (void)kb;
	if (format != WL_KEYBOARD_KEYMAP_FORMAT_XKB_V1) {
		close(fd);
		return;
	}
	char *map = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
	close(fd);
	if (map == MAP_FAILED)
		return;
	struct xkb_keymap *k = xkb_keymap_new_from_string(xkb, map, XKB_KEYMAP_FORMAT_TEXT_V1, XKB_KEYMAP_COMPILE_NO_FLAGS);
	munmap(map, size);
	if (!k)
		return;
	xkb_state_unref(xstate);
	xkb_keymap_unref(keymap);
	keymap = k;
	xstate = xkb_state_new(keymap);
}

static void keyboard_enter(void *data, struct wl_keyboard *kb, uint32_t serial, struct wl_surface *s, struct wl_array *keys)
{
	(void)data; (void)kb; (void)serial; (void)s; (void)keys;
}

static void keyboard_leave(void *data, struct wl_keyboard *kb, uint32_t serial, struct wl_surface *s)
{
	(void)data; (void)kb; (void)serial; (void)s;
}

static void keyboard_key(void *data, struct wl_keyboard *kb, uint32_t serial, uint32_t time, uint32_t key, uint32_t state)
{
	(void)data; (void)kb; (void)serial; (void)time;
	if (state != WL_KEYBOARD_KEY_STATE_PRESSED || !xstate || unlocked || just_relabeled())
		return;
	xkb_keycode_t code = key + 8;
	xkb_keysym_t sym = xkb_state_key_get_one_sym(xstate, code);
	if (sym == XKB_KEY_Return || sym == XKB_KEY_KP_Enter) {
		/* Nothing is checked while the suspend asked for is under way: an unlock in that
		 * moment would let the machine sleep, and wake, unlocked. */
		if (ntyped && asleep < 0)
			submit();
	} else if (sym == XKB_KEY_BackSpace) {
		while (ntyped && (typed[ntyped - 1] & 0xc0) == 0x80)
			typed[--ntyped] = 0;
		if (ntyped)
			typed[--ntyped] = 0;
	} else if (sym == XKB_KEY_Escape) {
		explicit_bzero(typed, sizeof typed);
		ntyped = 0;
	} else {
		char buf[8];
		int n = xkb_state_key_get_utf8(xstate, code, buf, sizeof buf);
		/* The first character of an entry asks what unlocks, so nothing is typed under a
		 * label that no longer holds; one that finds it changed is dropped with it. */
		if (n > 0 && !ntyped && relabel(kind_now()))
			n = 0;
		if (n > 0 && n < (int)sizeof buf && (unsigned char)buf[0] >= 0x20 && buf[0] != 0x7f && ntyped + (size_t)n < sizeof typed) {
			memcpy(typed + ntyped, buf, (size_t)n);
			ntyped += (size_t)n;
		}
		explicit_bzero(buf, sizeof buf);
		if (refused && !strncmp(status, "WRONG", 5))
			show_kind();
	}
	redraw();
}

static void keyboard_modifiers(void *data, struct wl_keyboard *kb, uint32_t serial,
		uint32_t depressed, uint32_t latched, uint32_t locked_mods, uint32_t group)
{
	(void)data; (void)kb; (void)serial;
	if (xstate)
		xkb_state_update_mask(xstate, depressed, latched, locked_mods, 0, 0, group);
}

static void keyboard_repeat(void *data, struct wl_keyboard *kb, int32_t rate, int32_t delay)
{
	(void)data; (void)kb; (void)rate; (void)delay;
}

static const struct wl_keyboard_listener keyboard_listener = {
	.keymap = keyboard_keymap,
	.enter = keyboard_enter,
	.leave = keyboard_leave,
	.key = keyboard_key,
	.modifiers = keyboard_modifiers,
	.repeat_info = keyboard_repeat,
};

static void seat_capabilities(void *data, struct wl_seat *s, uint32_t caps)
{
	(void)data;
	if ((caps & WL_SEAT_CAPABILITY_KEYBOARD) && !keyboard) {
		keyboard = wl_seat_get_keyboard(s);
		wl_keyboard_add_listener(keyboard, &keyboard_listener, NULL);
	}
}

static void seat_name(void *data, struct wl_seat *s, const char *name)
{
	(void)data; (void)s; (void)name;
}

static const struct wl_seat_listener seat_listener = {
	.capabilities = seat_capabilities,
	.name = seat_name,
};

static void global(void *data, struct wl_registry *r, uint32_t name, const char *iface, uint32_t version)
{
	(void)data;
	if (!strcmp(iface, wl_compositor_interface.name)) {
		compositor = wl_registry_bind(r, name, &wl_compositor_interface, 4);
	} else if (!strcmp(iface, wl_shm_interface.name)) {
		shm = wl_registry_bind(r, name, &wl_shm_interface, 1);
	} else if (!strcmp(iface, wl_seat_interface.name) && !seat) {
		seat = wl_registry_bind(r, name, &wl_seat_interface, version < 5 ? version : 5);
		wl_seat_add_listener(seat, &seat_listener, NULL);
	} else if (!strcmp(iface, ext_session_lock_manager_v1_interface.name)) {
		manager = wl_registry_bind(r, name, &ext_session_lock_manager_v1_interface, 1);
	} else if (!strcmp(iface, zwlr_output_power_manager_v1_interface.name)) {
		powermgr = wl_registry_bind(r, name, &zwlr_output_power_manager_v1_interface, 1);
	} else if (!strcmp(iface, wl_output_interface.name)) {
		struct output *o = calloc(1, sizeof *o);
		if (!o)
			return;
		o->name = name;
		o->wl = wl_registry_bind(r, name, &wl_output_interface, 1);
		wl_list_insert(&outputs, &o->link);
		cover(o);
	}
}

static void global_remove(void *data, struct wl_registry *r, uint32_t name)
{
	(void)data; (void)r;
	struct output *o, *tmp;
	wl_list_for_each_safe(o, tmp, &outputs, link) {
		if (o->name != name)
			continue;
		if (o->lock_surface)
			ext_session_lock_surface_v1_destroy(o->lock_surface);
		if (o->surface)
			wl_surface_destroy(o->surface);
		wl_output_destroy(o->wl);
		wl_list_remove(&o->link);
		free(o);
	}
}

static const struct wl_registry_listener registry_listener = {
	.global = global,
	.global_remove = global_remove,
};

/* One lock, from asking the compositor to the password taken. */
static int lock_session(void)
{
	wl_list_init(&outputs);
	xkb = xkb_context_new(XKB_CONTEXT_NO_FLAGS);
	display = wl_display_connect(NULL);
	if (!display || !xkb) {
		say("no Wayland display to lock");
		return 1;
	}
	struct wl_registry *registry = wl_display_get_registry(display);
	wl_registry_add_listener(registry, &registry_listener, NULL);
	wl_display_roundtrip(display);
	if (!compositor || !shm || !seat || !manager) {
		say("the compositor offers no session lock");
		return 1;
	}
	relabel(kind_now());
	lock = ext_session_lock_manager_v1_lock(manager);
	ext_session_lock_v1_add_listener(lock, &lock_listener, NULL);
	struct output *o;
	wl_list_for_each(o, &outputs, link)
		cover(o);
	/* The display's events, and with --suspend the daemon's answer once the machine woke. */
	int fd = wl_display_get_fd(display), gone = 0;
	while (!gone && !done && !unlocked) {
		if (wl_display_prepare_read(display) != 0) {
			gone = wl_display_dispatch_pending(display) < 0;
			continue;
		}
		wl_display_flush(display);
		struct pollfd p[2] = { { .fd = fd, .events = POLLIN }, { .fd = asleep, .events = POLLIN } };
		int r = poll(p, asleep >= 0 ? 2 : 1, asleep >= 0 ? suspend_left() : -1);
		if (r < 0) {
			wl_display_cancel_read(display);
			gone = errno != EINTR;
			continue;
		}
		if (p[0].revents)
			gone = wl_display_read_events(display) < 0;
		else
			wl_display_cancel_read(display);
		gone = gone || wl_display_dispatch_pending(display) < 0;
		if (asleep >= 0 && (r == 0 || p[1].revents))
			woke(r > 0);
	}
	if (unlocked) {
		ext_session_lock_v1_unlock_and_destroy(lock);
		/* Screens the idle watcher turned off come on with the unlock, should it be gone:
		 * the compositor gives one client each screen's power, so while the watcher holds
		 * them these requests fail, and the watcher's own resumed turns them on. */
		wl_list_for_each(o, &outputs, link) {
			if (!powermgr)
				break;
			struct zwlr_output_power_v1 *p = zwlr_output_power_manager_v1_get_output_power(powermgr, o->wl);
			zwlr_output_power_v1_set_mode(p, ZWLR_OUTPUT_POWER_V1_MODE_ON);
			zwlr_output_power_v1_destroy(p);
		}
		/* An unlock the compositor may not have read is a lost lock: the next one asks
		 * again should it have been read after all. */
		if (wl_display_roundtrip(display) < 0)
			return 3;
		say("unlocked");
		return 0;
	}
	explicit_bzero(typed, sizeof typed);
	if (done)
		return 1;
	say("the display went away");
	/* The session stays locked without its lock: one that lost the display while locked
	 * runs again, and finds no display if the compositor itself has gone. */
	return locked ? 3 : 1;
}

static struct ext_idle_notifier_v1 *notifier;
static int idled, blanking;

/* The screens --idle turns off once the lock has been up a while, each with its power control. */
struct screen {
	struct wl_list link;
	uint32_t name;
	struct wl_output *wl;
	struct zwlr_output_power_v1 *power;
};
static struct wl_list screens = { &screens, &screens };

/* What the compositor did with a screen's power, in its own words. */
static void power_mode(void *data, struct zwlr_output_power_v1 *p, uint32_t mode)
{
	(void)p;
	struct screen *sc = data;
	fprintf(stderr, "kryptik-lock: screen %u power %s\n", sc->name, mode == ZWLR_OUTPUT_POWER_V1_MODE_ON ? "on" : "off");
}

/* The compositor gives one client each screen's power: another has it, or the screen went. */
static void power_failed(void *data, struct zwlr_output_power_v1 *p)
{
	struct screen *sc = data;
	fprintf(stderr, "kryptik-lock: screen %u: its power is not this program's to turn off\n", sc->name);
	zwlr_output_power_v1_destroy(p);
	sc->power = NULL;
}

static const struct zwlr_output_power_v1_listener power_listener = {
	.mode = power_mode,
	.failed = power_failed,
};

static void take_power(struct screen *sc)
{
	sc->power = zwlr_output_power_manager_v1_get_output_power(powermgr, sc->wl);
	zwlr_output_power_v1_add_listener(sc->power, &power_listener, sc);
}

static void watch_global(void *data, struct wl_registry *r, uint32_t name, const char *iface, uint32_t version)
{
	(void)data;
	if (!strcmp(iface, wl_seat_interface.name) && !seat) {
		seat = wl_registry_bind(r, name, &wl_seat_interface, 1);
	} else if (!strcmp(iface, ext_idle_notifier_v1_interface.name) && version >= 2) {
		notifier = wl_registry_bind(r, name, &ext_idle_notifier_v1_interface, 2);
	} else if (!strcmp(iface, zwlr_output_power_manager_v1_interface.name)) {
		powermgr = wl_registry_bind(r, name, &zwlr_output_power_manager_v1_interface, 1);
	} else if (!strcmp(iface, wl_output_interface.name)) {
		struct screen *sc = calloc(1, sizeof *sc);
		if (!sc)
			return;
		sc->name = name;
		sc->wl = wl_registry_bind(r, name, &wl_output_interface, 1);
		wl_list_insert(&screens, &sc->link);
		/* Only a watcher that blanks takes the screens' power, which then is no one else's. */
		if (blanking && powermgr)
			take_power(sc);
	}
}

static void watch_global_remove(void *data, struct wl_registry *r, uint32_t name)
{
	(void)data; (void)r;
	struct screen *sc, *tmp;
	wl_list_for_each_safe(sc, tmp, &screens, link) {
		if (sc->name != name)
			continue;
		if (sc->power)
			zwlr_output_power_v1_destroy(sc->power);
		wl_output_destroy(sc->wl);
		wl_list_remove(&sc->link);
		free(sc);
	}
}

static const struct wl_registry_listener watch_registry_listener = {
	.global = watch_global,
	.global_remove = watch_global_remove,
};

static void idle_idled(void *data, struct ext_idle_notification_v1 *n)
{
	(void)data; (void)n;
	idled = 1;
}

static void idle_resumed(void *data, struct ext_idle_notification_v1 *n)
{
	(void)data; (void)n;
}

static const struct ext_idle_notification_v1_listener idle_listener = {
	.idled = idle_idled,
	.resumed = idle_resumed,
};

/* Every screen off, or on again. */
static void screens_power(uint32_t mode)
{
	struct screen *sc;
	wl_list_for_each(sc, &screens, link)
		if (sc->power)
			zwlr_output_power_v1_set_mode(sc->power, mode);
	say(mode == ZWLR_OUTPUT_POWER_V1_MODE_ON ? "screens on" : "screens off");
}

static void blank_idled(void *data, struct ext_idle_notification_v1 *n)
{
	(void)data; (void)n;
	screens_power(ZWLR_OUTPUT_POWER_V1_MODE_OFF);
}

static void blank_resumed(void *data, struct ext_idle_notification_v1 *n)
{
	(void)data; (void)n;
	screens_power(ZWLR_OUTPUT_POWER_V1_MODE_ON);
}

static const struct ext_idle_notification_v1_listener blank_listener = {
	.idled = blank_idled,
	.resumed = blank_resumed,
};

/* --idle: a lock of its own each time the session has been idle `secs`, and the screens off
 * `blank` later, while the session lasts. No keyboard is bound, so no key reaches it. */
static int watch_idle(long secs, long blank)
{
	display = wl_display_connect(NULL);
	if (!display) {
		say("no Wayland display to watch");
		return 1;
	}
	blanking = blank > 0;
	struct wl_registry *registry = wl_display_get_registry(display);
	wl_registry_add_listener(registry, &watch_registry_listener, NULL);
	wl_display_roundtrip(display);
	if (!seat || !notifier) {
		say("the compositor offers no idle notification that counts input alone");
		return 1;
	}
	/* Input alone counts, not idle inhibitors: what may hold the screen awake, a video in a
	 * zone say, must never hold the session unlocked. */
	struct ext_idle_notification_v1 *n = ext_idle_notifier_v1_get_input_idle_notification(notifier, (uint32_t)secs * 1000, seat);
	ext_idle_notification_v1_add_listener(n, &idle_listener, NULL);
	/* The screens go off `blank` after the lock, and on again at the first input, which the
	 * lock also takes. */
	if (blank > 0 && !powermgr)
		say("the compositor cannot turn screens off");
	if (blank > 0 && powermgr) {
		struct screen *sc;
		wl_list_for_each(sc, &screens, link)
			if (!sc->power)
				take_power(sc);
		struct ext_idle_notification_v1 *b =
			ext_idle_notifier_v1_get_input_idle_notification(notifier, (uint32_t)(secs + blank) * 1000, seat);
		ext_idle_notification_v1_add_listener(b, &blank_listener, NULL);
	}
	pid_t locker = 0;
	while (wl_display_dispatch(display) != -1) {
		if (!idled)
			continue;
		idled = 0;
		/* While its lock is up the session idles too, with nobody at the keyboard. */
		if (locker > 0 && waitpid(locker, NULL, WNOHANG) == 0)
			continue;
		fprintf(stderr, "kryptik-lock: no input for %ld s, locking\n", secs);
		locker = fork();
		if (locker == 0) {
			execl("/proc/self/exe", "kryptik-lock", (char *)NULL);
			_exit(127);
		}
	}
	say("the display went away");
	return 1;
}

/* A count of seconds up to a week, so the compositor's milliseconds fit 32 bits; or -1. */
static long seconds(const char *s)
{
	char *end;
	long v = strtol(s, &end, 10);
	return *s && !*end && v >= 0 && v <= 7 * 24 * 3600 ? v : -1;
}

int main(int argc, char **argv)
{
	if ((argc == 3 || (argc == 5 && !strcmp(argv[3], "--blank"))) && !strcmp(argv[1], "--idle")) {
		long secs = seconds(argv[2]), blank = argc == 5 ? seconds(argv[4]) : 60;
		if (secs > 0 && blank >= 0 && secs + blank <= 7 * 24 * 3600) {
			signal(SIGPIPE, SIG_IGN);
			return watch_idle(secs, blank);
		}
	}
	suspend_wanted = argc == 2 && !strcmp(argv[1], "--suspend");
	if (argc != 1 && !suspend_wanted) {
		fputs("usage: kryptik-lock [--suspend | --idle SECONDS [--blank SECONDS]]   (locks the session\n"
		      "       until the login password is typed; with --suspend, then suspends the machine;\n"
		      "       with --idle, each time the session has had no input that long, and the screens\n"
		      "       go off --blank later, 60 s unless given, 0 never)\n", stderr);
		return 2;
	}
	/* A refused pipe write is told by write's return, not a signal. */
	signal(SIGPIPE, SIG_IGN);
	/* The compositor keeps a session locked when its lock dies and takes no keys while
	 * locked, so nothing else could unlock it: a lock a signal killed, or one that lost
	 * the display while locked, locks again, and asks for no second suspend. */
	for (;; suspend_wanted = 0) {
		pid_t pid = fork();
		if (pid <= 0)
			return lock_session();
		int st;
		while (waitpid(pid, &st, 0) < 0)
			if (errno != EINTR)
				return 1;
		if (WIFSIGNALED(st))
			fprintf(stderr, "kryptik-lock: the lock died of signal %d; locking again\n", WTERMSIG(st));
		else if (WEXITSTATUS(st) == 3)
			fputs("kryptik-lock: the lock lost the display while locked; locking again\n", stderr);
		else
			return WEXITSTATUS(st);
		sleep(1);
	}
}
