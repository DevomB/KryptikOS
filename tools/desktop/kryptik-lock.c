/* kryptik-lock: lock the session until the login password is typed (docs/design/laptop.md).
 *
 *   kryptik-lock
 *   kryptik-lock --suspend         lock, then have the launch daemon suspend the machine; with
 *                                  a lock up already, have that one do it
 *   kryptik-lock --idle SECONDS [--blank SECONDS] [--sleep SECONDS]
 *                                  lock each time the session has had no input that long, and
 *                                  after the lock turn the screens off that much later (60 s;
 *                                  0 never) and have the machine sleep (never unless given)
 *
 * A lock that is up writes its supervisor's pid to $XDG_RUNTIME_DIR/kryptik/lock.pid, and
 * SIGUSR1 to that process has it ask for the machine's sleep, as the power key pressed while
 * locked does: dwl runs no binding then, and dwl's power key and lid otherwise run --suspend.
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
 * zone can bind and which a zone's hold on the screen pauses, as dwl counts one
 * (docs/design/laptop.md), and runs itself as the lock when it comes, until the session ends.
 * Exit: 0 unlocked; 1 the compositor would not lock, or there is no display; 2 usage.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/pidfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
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
	{'B', {0x1e, 0x11, 0x11, 0x1e, 0x11, 0x11, 0x1e}},
	{'C', {0x0e, 0x11, 0x10, 0x10, 0x10, 0x11, 0x0e}},
	{'D', {0x1c, 0x12, 0x11, 0x11, 0x11, 0x12, 0x1c}},
	{'E', {0x1f, 0x10, 0x10, 0x1e, 0x10, 0x10, 0x1f}},
	{'F', {0x1f, 0x10, 0x10, 0x1e, 0x10, 0x10, 0x10}},
	{'G', {0x0e, 0x11, 0x10, 0x17, 0x11, 0x11, 0x0f}},
	{'H', {0x11, 0x11, 0x11, 0x1f, 0x11, 0x11, 0x11}},
	{'I', {0x0e, 0x04, 0x04, 0x04, 0x04, 0x04, 0x0e}},
	{'J', {0x07, 0x02, 0x02, 0x02, 0x02, 0x12, 0x0c}},
	{'K', {0x11, 0x12, 0x14, 0x18, 0x14, 0x12, 0x11}},
	{'L', {0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x1f}},
	{'M', {0x11, 0x1b, 0x15, 0x15, 0x11, 0x11, 0x11}},
	{'N', {0x11, 0x11, 0x19, 0x15, 0x13, 0x11, 0x11}},
	{'O', {0x0e, 0x11, 0x11, 0x11, 0x11, 0x11, 0x0e}},
	{'P', {0x1e, 0x11, 0x11, 0x1e, 0x10, 0x10, 0x10}},
	{'Q', {0x0e, 0x11, 0x11, 0x11, 0x15, 0x12, 0x0d}},
	{'R', {0x1e, 0x11, 0x11, 0x1e, 0x14, 0x12, 0x11}},
	{'S', {0x0f, 0x10, 0x10, 0x0e, 0x01, 0x01, 0x1e}},
	{'T', {0x1f, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04}},
	{'U', {0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x0e}},
	{'V', {0x11, 0x11, 0x11, 0x11, 0x11, 0x0a, 0x04}},
	{'W', {0x11, 0x11, 0x11, 0x15, 0x15, 0x15, 0x0a}},
	{'X', {0x11, 0x11, 0x0a, 0x04, 0x0a, 0x11, 0x11}},
	{'Y', {0x11, 0x11, 0x0a, 0x04, 0x04, 0x04, 0x04}},
	{'Z', {0x1f, 0x01, 0x02, 0x04, 0x08, 0x10, 0x1f}},
	{'-', {0x00, 0x00, 0x00, 0x1f, 0x00, 0x00, 0x00}},
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
/* The session's layouts by name, as kryptik-session lists them (KRYPTIK_LAYOUTS), and the one in
 * force: with several, the lock names it, since a password typed in the other fails. */
static char layouts[4][33];
static int nlayouts, layout_now = -1;
static int refused;
/* What unlocks, and the label for it. */
enum { LOGIN, STATE };
static int kind = LOGIN;
/* --suspend: asked once locked, then the connection that answers when the machine woke and
 * when it was asked. */
static int suspend_wanted, asleep = -1;
static struct timespec asked, woke_at;
/* $XDG_RUNTIME_DIR/kryptik/lock.pid while a lock is up, and the process it names. */
static char pidfile[PATH_MAX];
static pid_t supervisor;
/* A "suspend now" (SIGUSR1): the supervisor passes it on to the lock it runs, and the lock's
 * handler writes to a pipe its poll loop watches, so none falls between a check and a poll. */
static volatile sig_atomic_t child;
static int wake_fd[2] = { -1, -1 };
static sigset_t usr1;

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

/* A word centred across at height y, s px to a font pixel. */
static void text(uint32_t *px, int w, int h, int s, int y, const char *word, uint32_t rgb)
{
	int len = (int)strlen(word), x = (w - (6 * len - 1) * s) / 2;
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
	/* The status word above the middle, the marks below it, and the layout under them. */
	text(px, o->w, o->h, s, o->h / 2 - 12 * s, status, refused ? warn : ink);
	int shown = ntyped < 32 ? (int)ntyped : 32, dot = 2 * s;
	int x = (o->w - shown * 2 * dot) / 2, y = o->h / 2 + 2 * s;
	for (int i = 0; i < shown; i++)
		fill(px, o->w, o->h, x + i * 2 * dot, y, dot, dot, ink);
	if (nlayouts > 1 && layout_now >= 0)
		text(px, o->w, o->h, s, y + dot + 6 * s, layouts[layout_now], ink);
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
static int answer(int s, char *why, size_t n);

/* Ask for the machine's sleep. Only a locked session is suspended, so before the compositor has
 * locked it is remembered for then; the answer comes once the machine has woken. */
static void suspend_now(void)
{
	/* The press that woke the machine reaches the input layer as a power key on some
	 * hardware, and would put it straight back to sleep: none is heeded for 10 s after a
	 * wake, counted on the clock that counts the sleep. */
	struct timespec now;
	clock_gettime(CLOCK_BOOTTIME, &now);
	if (woke_at.tv_sec && now.tv_sec - woke_at.tv_sec < 10) {
		say("held off a suspend: the machine woke less than 10 s ago");
		return;
	}
	if (!locked) {
		suspend_wanted = 1;
		return;
	}
	if (asleep >= 0)
		return;
	clock_gettime(CLOCK_MONOTONIC, &asked);
	asleep = request("suspend\n", -1);
	say(asleep < 0 ? "suspend: the launch daemon cannot be reached" : "suspending");
}

/* Where a lock that is up says who to ask to suspend: its supervisor, which outlives the lock
 * child it runs again. Written once the compositor has locked, so a lock it refused, the
 * second of two, writes nothing over the first's. */
static void write_pidfile(void)
{
	if (!pidfile[0])
		return;
	int fd = open(pidfile, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0600);
	if (fd < 0)
		return;
	dprintf(fd, "%d\n", (int)supervisor);
	close(fd);
}

/* No zone watches the room while the user is away: the camera goes back as the screen locks. */
static void camera_back(void)
{
	char why[96], line[160];
	int s = request("camera-revoke\n", -1);
	if (s < 0 || !answer(s, why, sizeof why)) {
		snprintf(line, sizeof line, "the camera was not taken back: %s", s < 0 ? "no launch daemon" : why);
	} else if (strcmp(why, "ok none") == 0) {
		return;
	} else {
		char *zone = why + 3, *stayed = strstr(zone, " stayed");
		if (stayed)
			*stayed = 0;
		snprintf(line, sizeof line, "the camera was taken back from zone %s%s", zone,
			 stayed ? "; its driver stays loaded" : "");
	}
	say(line);
}

static void lock_locked(void *data, struct ext_session_lock_v1 *l)
{
	(void)data; (void)l;
	locked = 1;
	say("locked");
	write_pidfile();
	camera_back();
	if (suspend_wanted)
		suspend_now();
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
	if (!strcmp(why, "ok woke"))
		clock_gettime(CLOCK_BOOTTIME, &woke_at);
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
	/* The power key: dwl runs only the volume and brightness keys while locked, so the lock
	 * has the machine sleep. */
	if (sym == XKB_KEY_XF86PowerOff) {
		suspend_now();
		return;
	}
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
	if (!xstate)
		return;
	xkb_state_update_mask(xstate, depressed, latched, locked_mods, 0, 0, group);
	xkb_layout_index_t now = xkb_state_serialize_layout(xstate, XKB_STATE_LAYOUT_EFFECTIVE);
	if (nlayouts > 1 && now < (xkb_layout_index_t)nlayouts && (int)now != layout_now) {
		layout_now = (int)now;
		fprintf(stderr, "kryptik-lock: layout %s\n", layouts[layout_now]);
		redraw();
	}
}

/* KRYPTIK_LAYOUTS, the session's layout names, in capitals for the lock's font; a name that is
 * not one of the table's shape ends the list there. */
static void read_layouts(void)
{
	const char *list = getenv("KRYPTIK_LAYOUTS");
	char copy[160], *save = NULL;
	if (!list || strlen(list) >= sizeof copy)
		return;
	strcpy(copy, list);
	for (char *n = strtok_r(copy, " ", &save); n && nlayouts < 4; n = strtok_r(NULL, " ", &save)) {
		if (strlen(n) >= sizeof layouts[0] || strspn(n, "abcdefghijklmnopqrstuvwxyz0123456789-") != strlen(n))
			break;
		for (size_t i = 0; n[i]; i++)
			layouts[nlayouts][i] = (char)(n[i] >= 'a' && n[i] <= 'z' ? n[i] - 'a' + 'A' : n[i]);
		nlayouts++;
	}
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

static void on_suspend_signal(int sig)
{
	(void)sig;
	int saved = errno;
	ssize_t w = write(wake_fd[1], "s", 1);
	(void)w;
	errno = saved;
}

/* One lock, from asking the compositor to the password taken. */
static int lock_session(void)
{
	wl_list_init(&outputs);
	if (pipe2(wake_fd, O_CLOEXEC | O_NONBLOCK) == 0) {
		struct sigaction sa = { .sa_handler = on_suspend_signal };
		sigemptyset(&sa.sa_mask);
		sigaction(SIGUSR1, &sa, NULL);
	}
	sigprocmask(SIG_UNBLOCK, &usr1, NULL);
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
	/* The display's events, a "suspend now", and once asked the daemon's answer when the
	 * machine woke. */
	int fd = wl_display_get_fd(display), gone = 0;
	while (!gone && !done && !unlocked) {
		if (wl_display_prepare_read(display) != 0) {
			gone = wl_display_dispatch_pending(display) < 0;
			continue;
		}
		wl_display_flush(display);
		struct pollfd p[3] = {
			{ .fd = fd, .events = POLLIN },
			{ .fd = wake_fd[0], .events = POLLIN },
			{ .fd = asleep, .events = POLLIN },
		};
		int r = poll(p, asleep >= 0 ? 3 : 2, asleep >= 0 ? suspend_left() : -1);
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
		if (p[1].revents) {
			char b[16];
			while (read(wake_fd[0], b, sizeof b) > 0)
				;
			suspend_now();
		}
		if (asleep >= 0 && (r == 0 || p[2].revents))
			woke(r > 0);
	}
	if (unlocked) {
		if (pidfile[0])
			unlink(pidfile);
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
	(void)version;
	if (!strcmp(iface, wl_seat_interface.name) && !seat) {
		seat = wl_registry_bind(r, name, &wl_seat_interface, 1);
	} else if (!strcmp(iface, ext_idle_notifier_v1_interface.name)) {
		notifier = wl_registry_bind(r, name, &ext_idle_notifier_v1_interface, 1);
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

/* The lock the watcher started last, while it runs. */
static pid_t locker;

static void nap_idled(void *data, struct ext_idle_notification_v1 *n)
{
	(void)data; (void)n;
	if (locker > 0 && waitpid(locker, NULL, WNOHANG) == 0 && kill(locker, SIGUSR1) == 0)
		say("idle since the lock: asking it to suspend");
}

static void nap_resumed(void *data, struct ext_idle_notification_v1 *n)
{
	(void)data; (void)n;
}

static const struct ext_idle_notification_v1_listener nap_listener = {
	.idled = nap_idled,
	.resumed = nap_resumed,
};

/* --idle: a lock of its own each time the session has been idle `secs`, and after it the
 * screens off `blank` later and the machine asleep `nap` later, while the session lasts. No
 * keyboard is bound, so no key reaches it. */
static int watch_idle(long secs, long blank, long nap)
{
	/* A "suspend now" is for the lock: the watcher, and the lock it starts until that sets its
	 * own handler, pass over one meant for it. */
	signal(SIGUSR1, SIG_IGN);
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
		say("the compositor offers no idle notification");
		return 1;
	}
	/* Idle inhibitors count as dwl counts them: a hold a zone's file allows, while its window is
	 * shown and has the keyboard, for four hours from the last key or button press
	 * (docs/design/laptop.md). A zone 0 program's inhibitor holds nothing. */
	struct ext_idle_notification_v1 *n = ext_idle_notifier_v1_get_idle_notification(notifier, (uint32_t)secs * 1000, seat);
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
			ext_idle_notifier_v1_get_idle_notification(notifier, (uint32_t)(secs + blank) * 1000, seat);
		ext_idle_notification_v1_add_listener(b, &blank_listener, NULL);
	}
	/* Asleep `nap` after the lock: the lock this watcher started is asked to have the machine
	 * sleep, as the power key would. */
	if (nap > 0) {
		struct ext_idle_notification_v1 *z =
			ext_idle_notifier_v1_get_idle_notification(notifier, (uint32_t)(secs + nap) * 1000, seat);
		ext_idle_notification_v1_add_listener(z, &nap_listener, NULL);
	}
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

/* A lock that is up, as its pid file says, held by a pidfd, or -1. The file must be this user's
 * own and no one else's to read, and the process this same program, run by this user; it is
 * checked once its pidfd is open, so the process checked is the one a signal reaches, never
 * another that took its number. */
static int lock_up(void)
{
	char buf[32], path[64], exe[PATH_MAX], self[PATH_MAX];
	struct stat st;
	if (!pidfile[0])
		return -1;
	int fd = open(pidfile, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
	if (fd < 0)
		return -1;
	ssize_t n = -1;
	if (fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && st.st_uid == getuid() && !(st.st_mode & 077))
		n = read(fd, buf, sizeof buf - 1);
	close(fd);
	if (n <= 0)
		return -1;
	buf[n] = 0;
	long pid = strtol(buf, NULL, 10);
	if (pid <= 1)
		return -1;
	int pfd = pidfd_open((pid_t)pid, 0);
	if (pfd < 0)
		return -1;
	snprintf(path, sizeof path, "/proc/%ld", pid);
	ssize_t a = -1, b = -1;
	if (stat(path, &st) == 0 && st.st_uid == getuid()) {
		snprintf(path, sizeof path, "/proc/%ld/exe", pid);
		a = readlink(path, exe, sizeof exe);
		b = readlink("/proc/self/exe", self, sizeof self);
	}
	if (a <= 0 || a != b || memcmp(exe, self, (size_t)a)) {
		close(pfd);
		return -1;
	}
	return pfd;
}

static void forward(int sig)
{
	(void)sig;
	if (child > 0)
		kill(child, SIGUSR1);
}

int main(int argc, char **argv)
{
	/* --idle SECONDS, then --blank SECONDS (60 s unless given) and --sleep SECONDS (never
	 * unless given), each after the lock; a week at most, so the compositor's milliseconds fit. */
	if (argc >= 3 && argc % 2 == 1 && !strcmp(argv[1], "--idle")) {
		long secs = seconds(argv[2]), blank = 60, nap = 0;
		int ok = secs > 0;
		for (int i = 3; ok && i + 1 < argc; i += 2) {
			if (!strcmp(argv[i], "--blank"))
				ok = (blank = seconds(argv[i + 1])) >= 0;
			else if (!strcmp(argv[i], "--sleep"))
				ok = (nap = seconds(argv[i + 1])) >= 0;
			else
				ok = 0;
		}
		if (ok && secs + blank <= 7 * 24 * 3600 && secs + nap <= 7 * 24 * 3600) {
			signal(SIGPIPE, SIG_IGN);
			return watch_idle(secs, blank, nap);
		}
	}
	suspend_wanted = argc == 2 && !strcmp(argv[1], "--suspend");
	read_layouts();
	if (argc != 1 && !suspend_wanted) {
		fputs("usage: kryptik-lock [--suspend | --idle SECONDS [--blank SECONDS] [--sleep SECONDS]]\n"
		      "       (locks the session until the login password is typed; with --suspend, then\n"
		      "       suspends the machine, or has the lock that is up do so; with --idle, each time\n"
		      "       the session has had no input that long, and after the lock the screens go off\n"
		      "       --blank later, 60 s unless given, 0 never, and the machine sleeps --sleep later,\n"
		      "       never unless given)\n", stderr);
		return 2;
	}
	const char *rt = getenv("XDG_RUNTIME_DIR");
	if (rt && rt[0] == '/')
		snprintf(pidfile, sizeof pidfile, "%s/kryptik/lock.pid", rt);
	/* A second lock would be refused while one is up: that one is asked instead. */
	if (suspend_wanted) {
		int up = lock_up();
		if (up >= 0) {
			int sent = pidfd_send_signal(up, SIGUSR1, NULL, 0) == 0;
			close(up);
			if (sent) {
				say("asked the lock that is up to suspend");
				return 0;
			}
		}
	}
	/* A refused pipe write is told by write's return, not a signal. */
	signal(SIGPIPE, SIG_IGN);
	supervisor = getpid();
	sigemptyset(&usr1);
	sigaddset(&usr1, SIGUSR1);
	struct sigaction sa = { .sa_handler = forward, .sa_flags = SA_RESTART };
	sigemptyset(&sa.sa_mask);
	sigaction(SIGUSR1, &sa, NULL);
	/* The compositor keeps a session locked when its lock dies and takes no keys while
	 * locked, so nothing else could unlock it: a lock a signal killed, or one that lost
	 * the display while locked, locks again, and asks for no second suspend. A "suspend
	 * now" waits while a lock starts: before its pipe exists, there is nowhere for it. */
	for (;; suspend_wanted = 0) {
		sigprocmask(SIG_BLOCK, &usr1, NULL);
		pid_t pid = fork();
		if (pid <= 0) {
			child = 0;
			return lock_session();
		}
		child = pid;
		sigprocmask(SIG_UNBLOCK, &usr1, NULL);
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
