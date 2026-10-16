/* kryptik-launch: start a program in a zone, as a client of kryptikd's launch daemon (a
 * root-owned socket open to group kryptik); the compositor's keys and the chrome's menu run only this.
 *
 *   kryptik-launch [--ask | --passphrase-fd N] [--no-display] ZONE -- COMMAND [ARG...]
 *   kryptik-launch --stop ZONE
 *   kryptik-launch --info ZONE          encrypted yes|no, running yes|no, the USB stick it holds
 *   kryptik-launch --runtime-dir        print the session's XDG_RUNTIME_DIR, creating it
 *   kryptik-launch --desktop -- COMMAND [ARG...]   the desktop: dwl as the daemon starts it,
 *                                      without group kryptik and under the desktop's memory
 *                                      bound, and COMMAND (the chrome) on dwl's status
 *   kryptik-launch --clipboard-move FROM TO   the zone 0 gesture: move what FROM's windows copied
 *                                      to TO's, or FROM's broker payload when they copied nothing
 *   kryptik-launch --wifi-list          the net zone's Wi-Fi SSIDs, one per line
 *   kryptik-launch --wifi-scan          the networks in range, as the net zone hears them
 *   kryptik-launch --wifi-add SSID      add one or replace its passphrase (one line on stdin)
 *   kryptik-launch --wifi-add-open SSID add one as an open network, with no passphrase
 *                                       (either with --hidden: one that hides its name)
 *   kryptik-launch --wifi-forget SSID   remove one
 *   kryptik-launch --update status|fetch|forget|apply   show, fetch, drop or install a release
 *   kryptik-launch --update auto on|off   fetch each release as it is announced, or when asked
 *   kryptik-launch --sticks             the USB stick partitions a zone may be given: NAME WHAT a line
 *   kryptik-launch --stick-grant ZONE PART ro|rw   give ZONE the partition, to read or to write too
 *   kryptik-launch --stick-eject ZONE   take ZONE's back
 *   kryptik-launch --camera-grant ZONE  give ZONE the camera until it is taken back, the zone
 *                                       stops or the screen locks
 *   kryptik-launch --camera-revoke      take it back; prints the zone that had it, if any
 *   kryptik-launch --check-password    whether the line on stdin is the login password: the
 *                                      screen lock asks, and the daemon pauses after a wrong one
 *
 * A display goes through the zone's own proxy, which the daemon starts as a user of its own and
 * binds into the zone at /run/kryptik/wayland-0: a zone never sees the compositor's own socket.
 * The proxy reaches dwl through dwl's socket for that zone, which offers only what the proxy
 * passes on and is how dwl knows the zone of each window.
 * --ask reads an encrypted zone's passphrase on the controlling terminal, or hands over to
 * kryptik-chrome --prompt; it travels as a descriptor, never in argv or environ.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#define LAUNCH_SOCKET "/run/kryptik-launch/launch.sock"
#define CHROME_BIN "/usr/bin/kryptik-chrome"
#define DWL_BIN "/usr/bin/dwl"

static void die(const char *fmt, ...) __attribute__((format(printf, 1, 2), noreturn));
static void die(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	fputs("kryptik-launch: ", stderr);
	vfprintf(stderr, fmt, ap);
	fputc('\n', stderr);
	va_end(ap);
	exit(1);
}

static int ident_ok(const char *s)
{
	size_t n = strlen(s);
	if (n == 0 || n > 32)
		return 0;
	for (; *s; s++)
		if (!((*s >= 'a' && *s <= 'z') || (*s >= 'A' && *s <= 'Z') || (*s >= '0' && *s <= '9') || *s == '-' || *s == '_'))
			return 0;
	return 1;
}

/* Send one request (and fd, if >= 0); return the whole reply, malloc'ed. */
static char *talk(const char *text, int fd)
{
	struct sockaddr_un sa;
	int s = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (s < 0)
		die("socket: %s", strerror(errno));
	memset(&sa, 0, sizeof sa);
	sa.sun_family = AF_UNIX;
	strncpy(sa.sun_path, LAUNCH_SOCKET, sizeof sa.sun_path - 1);
	if (connect(s, (struct sockaddr *)&sa, sizeof sa) < 0)
		die("%s: %s (is kryptikd serve running, and are you in group kryptik?)", LAUNCH_SOCKET, strerror(errno));

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
	ssize_t n = sendmsg(s, &msg, 0);
	if (n < 0)
		die("sendmsg: %s", strerror(errno));
	if ((size_t)n != strlen(text))
		die("short send");
	shutdown(s, SHUT_WR);

	size_t cap = 4096, len = 0;
	char *reply = malloc(cap);
	if (!reply)
		die("out of memory");
	for (;;) {
		if (len + 1 >= cap) {
			cap *= 2;
			reply = realloc(reply, cap);
			if (!reply)
				die("out of memory");
		}
		n = read(s, reply + len, cap - len - 1);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			die("read: %s", strerror(errno));
		}
		if (n == 0)
			break;
		len += (size_t)n;
	}
	reply[len] = 0;
	close(s);
	return reply;
}

static volatile sig_atomic_t caught;
static void on_signal(int sig) { caught = sig; }

static const int quiet_sigs[] = { SIGINT, SIGQUIT, SIGTERM, SIGHUP };
static struct sigaction quiet_old[4];
static struct termios quiet_saved;

/* Echo off on a terminal, before any prompt so what was typed ahead is kept.
 * Until quiet_end the signals that would leave it silent only end the read. */
static void quiet_start(int fd)
{
	struct sigaction sa = { .sa_handler = on_signal };
	sigemptyset(&sa.sa_mask);
	for (int i = 0; i < 4; i++)
		sigaction(quiet_sigs[i], &sa, &quiet_old[i]);
	tcgetattr(fd, &quiet_saved);
	struct termios raw = quiet_saved;
	raw.c_lflag &= ~(tcflag_t)ECHO;
	tcsetattr(fd, TCSANOW, &raw);
}

/* Echo back on, a newline to out, then any signal caught meanwhile. */
static void quiet_end(int fd, int out)
{
	tcsetattr(fd, TCSANOW, &quiet_saved);
	dprintf(out, "\n");
	for (int i = 0; i < 4; i++)
		sigaction(quiet_sigs[i], &quiet_old[i], NULL);
	if (caught)
		raise(caught);
}

/* Read a passphrase from the open terminal into a memfd; returns the fd. */
static int passphrase_from_tty(int tty, const char *zone)
{
	quiet_start(tty);
	dprintf(tty, "passphrase for zone %s: ", zone);
	char buf[512];
	ssize_t n = caught ? -1 : read(tty, buf, sizeof buf - 1);
	quiet_end(tty, tty);
	close(tty);
	if (n <= 0)
		die("no passphrase");
	while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r'))
		n--;
	if (n == 0)
		die("empty passphrase");
	int fd = memfd_create("kryptik-passphrase", MFD_CLOEXEC);
	if (fd < 0)
		die("memfd_create: %s", strerror(errno));
	if (write(fd, buf, (size_t)n) != n)
		die("memfd write");
	explicit_bzero(buf, sizeof buf);
	lseek(fd, 0, SEEK_SET);
	return fd;
}

/* Whether the zone is on an encrypted volume, and whether that volume waits for its passphrase
 * since the machine slept. */
static void zone_volume(const char *zone, int *encrypted, int *waiting)
{
	char req[128];
	snprintf(req, sizeof req, "info %s\n", zone);
	char *r = talk(req, -1);
	if (strncmp(r, "error", 5) == 0)
		die("%s", r);
	*encrypted = strstr(r, "encrypted yes") != NULL;
	*waiting = strstr(r, "waiting yes") != NULL;
	free(r);
}

/* The passphrase on pass_fd gives a waiting zone's volume its key, and the zone goes on. */
static int resume_zone(const char *zone, int pass_fd)
{
	char req[128];
	snprintf(req, sizeof req, "resume-zone %s\n", zone);
	char *r = talk(req, pass_fd);
	close(pass_fd);
	int ok = strncmp(r, "ok", 2) == 0;
	if (ok)
		printf("zone %s has its volume's key again and goes on where it was\n", zone);
	else
		fprintf(stderr, "kryptik-launch: zone %s: %s", zone, r);
	free(r);
	return ok ? 0 : 1;
}

static void usage(void)
{
	fputs("usage: kryptik-launch [--ask | --passphrase-fd N] [--no-display] ZONE -- COMMAND [ARG...]\n"
	      "       kryptik-launch --stop ZONE\n"
	      "       kryptik-launch [--passphrase-fd N] --resume ZONE   (its volume's key, after a sleep)\n"
	      "       kryptik-launch --info ZONE\n"
	      "       kryptik-launch --runtime-dir\n"
	      "       kryptik-launch --desktop -- COMMAND [ARG...]\n"
	      "       kryptik-launch --clipboard-move FROM TO\n"
	      "       kryptik-launch --wifi-list | --wifi-scan | --wifi-add SSID [--hidden] | --wifi-add-open SSID [--hidden] | --wifi-forget SSID\n"
	      "                      (--wifi-add reads the passphrase from standard input)\n"
	      "       kryptik-launch --update status|fetch|forget|apply | --update auto on|off\n"
	      "       kryptik-launch --sticks | --stick-grant ZONE PARTITION ro|rw | --stick-eject ZONE\n"
	      "       kryptik-launch --camera-grant ZONE | --camera-revoke\n"
	      "       kryptik-launch --check-password   (the password on standard input)\n", stderr);
	exit(2);
}

/* A descriptor number, all of the argument. */
static int fd_arg(const char *s)
{
	char *end;
	errno = 0;
	long v = strtol(s, &end, 10);
	if (errno || end == s || *end || v < 0 || v > INT_MAX)
		usage();
	return (int)v;
}

/* One secret line from stdin: prompted with echo off on a terminal, silent
 * from a pipe (the kryptik command pipes it). Trailing newlines dropped. */
static void secret_from_stdin(const char *prompt, char *buf, size_t size)
{
	int tty = isatty(0);
	if (tty) {
		quiet_start(0);
		fputs(prompt, stderr);
		fflush(stderr);
	}
	char *got = caught ? NULL : fgets(buf, (int)size, stdin);
	if (tty)
		quiet_end(0, 2);
	if (!got)
		die("no passphrase on standard input");
	size_t n = strlen(buf);
	if (n == size - 1 && buf[n - 1] != '\n')
		die("passphrase too long");
	while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r'))
		buf[--n] = 0;
	if (n == 0)
		die("empty passphrase");
}

/* The daemon's wifi verbs (kryptikd's wifi.rs); the passphrase goes in the request body. */
static int wifi_main(int argc, char **argv)
{
	const char *mode = argv[1];
	if (strcmp(mode, "--wifi-list") == 0) {
		if (argc != 2)
			usage();
		char *r = talk("wifi-list\n", -1);
		if (strncmp(r, "error", 5) == 0) {
			fputs(r, stderr);
			return 1;
		}
		/* `network <ssid>` lines, then `end`: print the names alone. */
		for (char *p = r; *p; ) {
			char *nl = strchr(p, '\n');
			size_t n = nl ? (size_t)(nl - p) : strlen(p);
			if (n > 8 && strncmp(p, "network ", 8) == 0) {
				fwrite(p + 8, 1, n - 8, stdout);
				fputc('\n', stdout);
			}
			p += n + (nl ? 1 : 0);
		}
		return 0;
	}
	/* An `ok` line and the daemon's lines, or one `error:` line; the net zone takes seconds. */
	if (strcmp(mode, "--wifi-scan") == 0) {
		if (argc != 2)
			usage();
		char *r = talk("wifi-scan\n", -1);
		int ok = strncmp(r, "ok\n", 3) == 0;
		fputs(ok ? r + 3 : r, ok ? stdout : stderr);
		return ok ? 0 : 1;
	}
	int add = strcmp(mode, "--wifi-add") == 0, add_open = strcmp(mode, "--wifi-add-open") == 0;
	int hidden = argc == 4 && (add || add_open) && strcmp(argv[3], "--hidden") == 0;
	if (argc != 3 + hidden || (!add && !add_open && strcmp(mode, "--wifi-forget") != 0))
		usage();
	const char *ssid = argv[2];
	if (!*ssid || strlen(ssid) > 32 || strchr(ssid, '\n'))
		die("an SSID is 1 to 32 bytes without a newline");
	char pass[256] = "";
	if (add) {
		char prompt[64];
		snprintf(prompt, sizeof prompt, "passphrase for %s: ", ssid);
		secret_from_stdin(prompt, pass, sizeof pass);
	}
	char req[512];
	if (add)
		snprintf(req, sizeof req, "wifi-add\nssid %s\npsk %s\n%send\n", ssid, pass, hidden ? "hidden\n" : "");
	else if (add_open)
		snprintf(req, sizeof req, "wifi-add\nssid %s\nopen\n%send\n", ssid, hidden ? "hidden\n" : "");
	else
		snprintf(req, sizeof req, "wifi-forget\nssid %s\nend\n", ssid);
	char *r = talk(req, -1);
	explicit_bzero(pass, sizeof pass);
	explicit_bzero(req, sizeof req);
	int ok = strncmp(r, "ok", 2) == 0;
	fputs(r, ok ? stdout : stderr);
	return ok ? 0 : 1;
}

/* The daemon's update verbs (kryptikd's update.rs): an `ok` line and text, or one `error:` line;
 * `apply` answers once kryptik-update has written the slot. */
static int update_main(int argc, char **argv)
{
	int automatic = argc == 4 && strcmp(argv[2], "auto") == 0 && (strcmp(argv[3], "on") == 0 || strcmp(argv[3], "off") == 0);
	if (!automatic && (argc != 3 || (strcmp(argv[2], "status") != 0 && strcmp(argv[2], "fetch") != 0 &&
	                                 strcmp(argv[2], "forget") != 0 && strcmp(argv[2], "apply") != 0)))
		usage();
	char req[32];
	if (automatic)
		snprintf(req, sizeof req, "update-auto %s\n", argv[3]);
	else
		snprintf(req, sizeof req, "update-%s\n", argv[2]);
	char *r = talk(req, -1);
	int ok = strncmp(r, "ok\n", 3) == 0;
	fputs(ok ? r + 3 : r, ok ? stdout : stderr);
	return ok ? 0 : 1;
}

/* The chrome's stick window: what may be given, the giving, the taking back. */
static int stick_main(int argc, char **argv)
{
	char req[160] = "";
	if (argc == 2 && strcmp(argv[1], "--sticks") == 0)
		snprintf(req, sizeof req, "sticks\n");
	else if (argc == 5 && strcmp(argv[1], "--stick-grant") == 0 && ident_ok(argv[2]) && ident_ok(argv[3]) &&
		 (strcmp(argv[4], "ro") == 0 || strcmp(argv[4], "rw") == 0))
		snprintf(req, sizeof req, "stick-grant %s %s %s\n", argv[2], argv[3], argv[4]);
	else if (argc == 3 && strcmp(argv[1], "--stick-eject") == 0 && ident_ok(argv[2]))
		snprintf(req, sizeof req, "stick-eject %s\n", argv[2]);
	else
		usage();
	char *r = talk(req, -1);
	int ok = strncmp(r, "error", 5) != 0;
	if (!ok)
		fputs(r, stderr);
	else if (strncmp(r, "ok ", 3) == 0)
		fputs(r + 3, stdout);
	else if (strcmp(argv[1], "--sticks") == 0) {
		/* NAME WHAT lines, then end. */
		size_t n = strlen(r);
		if (n >= 4 && strcmp(r + n - 4, "end\n") == 0 && (n == 4 || r[n - 5] == '\n'))
			r[n - 4] = 0;
		fputs(r, stdout);
	}
	free(r);
	return ok ? 0 : 1;
}

/* The chrome's camera gestures: give it to a zone, or take it back. */
static int camera_main(int argc, char **argv)
{
	char req[64] = "";
	if (argc == 3 && strcmp(argv[1], "--camera-grant") == 0 && ident_ok(argv[2]))
		snprintf(req, sizeof req, "camera-grant %s\n", argv[2]);
	else if (argc == 2 && strcmp(argv[1], "--camera-revoke") == 0)
		snprintf(req, sizeof req, "camera-revoke\n");
	else
		usage();
	char *r = talk(req, -1);
	int ok = strncmp(r, "ok ", 3) == 0;
	fputs(ok ? r + 3 : r, ok ? stdout : stderr);
	free(r);
	return ok ? 0 : 1;
}

/* The screen lock's question, the password in the request's body. Exit 0 if it is the login
 * password; 1, with the daemon's reason, if not or not yet. */
static int password_main(int argc)
{
	if (argc != 2)
		usage();
	char pass[512], req[600];
	secret_from_stdin("password: ", pass, sizeof pass);
	snprintf(req, sizeof req, "check-password\npassword %s\nend\n", pass);
	explicit_bzero(pass, sizeof pass);
	char *r = talk(req, -1);
	explicit_bzero(req, sizeof req);
	int ok = strcmp(r, "ok\n") == 0;
	if (!ok)
		fputs(r, stderr);
	free(r);
	return ok ? 0 : 1;
}

/* One request to a zone's proxy on the move gesture's socket (kryptik-wlproxy's control.rs),
 * which the launch daemon made for this user beside the proxy's own, `body` after its line:
 * the answer's line in `line`, and the bytes an "ok GEN TYPE N" answer announces in *data.
 * -1 when the zone has no proxy to ask. */
static int ask_proxy(const char *zone, const char *head, const unsigned char *body, size_t blen,
		     char *line, size_t lsize, unsigned char **data, size_t *dlen)
{
	struct sockaddr_un sa = { .sun_family = AF_UNIX };
	*data = NULL;
	*dlen = 0;
	line[0] = 0;
	if (snprintf(sa.sun_path, sizeof sa.sun_path, "/run/kryptik-proxy/%u/%s.control", (unsigned)getuid(), zone) >= (int)sizeof sa.sun_path)
		return -1;
	int s = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (s < 0)
		return -1;
	/* The proxy keeps its own 2 s; this keeps a wedged one from holding the gesture. */
	struct timeval tv = { .tv_sec = 5 };
	setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
	setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
	if (connect(s, (struct sockaddr *)&sa, sizeof sa) < 0) {
		close(s);
		return -1;
	}
	size_t hlen = strlen(head), off = 0;
	int sent = 1;
	while (sent && off < hlen + blen) {
		/* A proxy that hangs up early ends the request, not this process. */
		ssize_t n = off < hlen ? send(s, head + off, hlen - off, MSG_NOSIGNAL)
				       : send(s, body + (off - hlen), hlen + blen - off, MSG_NOSIGNAL);
		if (n <= 0)
			sent = 0;
		else
			off += (size_t)n;
	}
	shutdown(s, SHUT_WR);
	/* The line a byte at a time, as what follows it is the payload. */
	size_t n = 0;
	char c;
	while (n + 1 < lsize && read(s, &c, 1) == 1 && c != '\n')
		line[n++] = c;
	line[n] = 0;
	unsigned long long gen;
	char type[64];
	size_t len;
	if (!sent) {
		snprintf(line, lsize, "error: the request could not be sent");
	} else if (sscanf(line, "ok %llu %63s %zu", &gen, type, &len) == 3 && len <= 1 << 20) {
		unsigned char *buf = malloc(len ? len : 1);
		size_t got = 0;
		while (buf && got < len) {
			ssize_t r = read(s, buf + got, len - got);
			if (r <= 0)
				break;
			got += (size_t)r;
		}
		if (buf && got == len) {
			*data = buf;
			*dlen = len;
		} else {
			if (buf)
				explicit_bzero(buf, got);
			free(buf);
			snprintf(line, lsize, "error: the answer was cut short");
		}
	}
	close(s);
	return 0;
}

/* The zone 0 move gesture: what FROM's windows copied goes to TO's. FROM's proxy is asked for
 * it, TO's is given it, and FROM's selection is cleared once TO holds it, if nothing was copied
 * there since; only the proxies' lines are printed, never what moved. With nothing copied in
 * FROM's windows, or no windows, FROM's broker payload moves, as it always has. */
static int clipboard_move(const char *from, const char *to)
{
	char line[160], said[160], type[64], head[128];
	unsigned char *data, *none;
	size_t len, nlen;
	unsigned long long gen;
	if (strcmp(from, to) == 0) {
		fprintf(stderr, "nothing moved: %s's clipboard is %s's already\n", from, to);
		return 1;
	}
	if (ask_proxy(from, "take\n", NULL, 0, line, sizeof line, &data, &len) < 0 || strcmp(line, "empty") == 0) {
		char req[160];
		snprintf(req, sizeof req, "clipboard-move %s %s\n", from, to);
		char *r = talk(req, -1);
		fputs(r, strncmp(r, "ok", 2) == 0 ? stdout : stderr);
		return strncmp(r, "ok", 2) == 0 ? 0 : 1;
	}
	if (!data || sscanf(line, "ok %llu %63s", &gen, type) != 2) {
		fprintf(stderr, "nothing moved: %s's windows: %s\n", from, line[0] ? line : "no answer");
		free(data);
		return 1;
	}
	snprintf(head, sizeof head, "give %s %zu\n", type, len);
	int r = ask_proxy(to, head, data, len, said, sizeof said, &none, &nlen);
	explicit_bzero(data, len);
	free(data);
	free(none);
	if (r < 0 || strcmp(said, "ok") != 0) {
		fprintf(stderr, "nothing moved: %s\n", r < 0 ? "the receiving zone has no windows to paste in" : said);
		return 1;
	}
	snprintf(head, sizeof head, "clear %llu\n", gen);
	r = ask_proxy(from, head, NULL, 0, said, sizeof said, &none, &nlen);
	free(none);
	if (r < 0 || strcmp(said, "ok") != 0) {
		printf("copied %zu bytes of %s from %s's windows to %s's; %s still holds it (%s)\n", len, type, from, to, from,
		       r < 0 ? "its proxy is gone" : said);
		return 0;
	}
	printf("moved %zu bytes of %s from %s's windows to %s's\n", len, type, from, to);
	return 0;
}

/* What the session hands dwl of its environment: the keymap kb_export_desktop set. The daemon
 * gives dwl the rest. */
static const char *const desktop_env[] = {
	"XKB_DEFAULT_RULES", "XKB_DEFAULT_MODEL", "XKB_DEFAULT_LAYOUT", "XKB_DEFAULT_VARIANT",
	"XKB_DEFAULT_OPTIONS", "KRYPTIK_LAYOUTS",
};

/* Ask the daemon for dwl, handing it FDS: the spawner's socket, dwl's status and the log. BUF gets
 * the whole answer, `started PID` at once and the last line when dwl has ended. 1 when dwl
 * started, 0 when it did not, and BUF then says why; every failure is said there, none ends this
 * process. */
static int ask_desktop(const char *req, const int fds[3], char *buf, size_t size)
{
	union { char buf[CMSG_SPACE(3 * sizeof(int))]; struct cmsghdr align; } u;
	struct iovec iov = { .iov_base = (void *)req, .iov_len = strlen(req) };
	struct msghdr msg = { .msg_iov = &iov, .msg_iovlen = 1, .msg_control = u.buf, .msg_controllen = sizeof u.buf };
	struct sockaddr_un sa;
	struct cmsghdr *c;
	size_t len = 0;
	int started = 0, s = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);

	if (s < 0) {
		snprintf(buf, size, "socket: %s\n", strerror(errno));
		return 0;
	}
	memset(&sa, 0, sizeof sa);
	sa.sun_family = AF_UNIX;
	strncpy(sa.sun_path, LAUNCH_SOCKET, sizeof sa.sun_path - 1);
	memset(&u, 0, sizeof u);
	c = CMSG_FIRSTHDR(&msg);
	c->cmsg_level = SOL_SOCKET;
	c->cmsg_type = SCM_RIGHTS;
	c->cmsg_len = CMSG_LEN(3 * sizeof(int));
	memcpy(CMSG_DATA(c), fds, 3 * sizeof(int));
	if (connect(s, (struct sockaddr *)&sa, sizeof sa) < 0 || sendmsg(s, &msg, 0) != (ssize_t)strlen(req)) {
		snprintf(buf, size, "%s: %s\n", LAUNCH_SOCKET, strerror(errno));
		close(s);
		return 0;
	}
	shutdown(s, SHUT_WR);
	while (len + 1 < size) {
		ssize_t n = read(s, buf + len, size - 1 - len);
		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0)
			break;
		len += (size_t)n;
		buf[len] = 0;
		if (!started && strncmp(buf, "started ", 8) == 0 && strchr(buf, '\n')) {
			started = 1;
			fprintf(stderr, "kryptik-launch: the daemon starts dwl as pid %.*s, without group kryptik\n",
				(int)(strchr(buf, '\n') - buf - 8), buf + 8);
		}
	}
	close(s);
	buf[len] = 0;
	if (len == 0)
		snprintf(buf, size, "no answer from the launch daemon\n");
	/* A child that could not become dwl is a start that did not happen. */
	return started && !strstr(buf, "error: dwl did not start");
}

/* The session's last step (compositor separation): dwl runs as the launch daemon starts it, in the
 * desktop's cgroup with this login's groups less kryptik, so it reaches neither the daemon nor the
 * mixer's control socket. What needs the group stays with the session: the spawner, dwl's own
 * binary serving the keys' commands from dwl's table (-X), which starts COMMAND, the chrome, on
 * dwl's status once dwl names its display. If the daemon does not start dwl, this process becomes
 * dwl, with the group, and says so. The login ends with dwl. */
static int desktop_main(int argc, char **argv)
{
	int sv[2], st[2], i, k = 0;
	char req[4096], said[1024], **sargv, *last, *p;
	size_t len = 0;
	pid_t spawner;

	if (argc < 4 || strcmp(argv[2], "--") != 0)
		usage();
	if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sv) < 0 || pipe2(st, O_CLOEXEC) < 0)
		die("the desktop's socket and pipe: %s", strerror(errno));
	if (!(sargv = calloc((size_t)argc + 4, sizeof *sargv)))
		die("out of memory");
	sargv[k++] = DWL_BIN;
	sargv[k++] = "-X";
	sargv[k++] = "3";
	sargv[k++] = "--";
	for (i = 3; i < argc; i++)
		sargv[k++] = argv[i];
	if ((spawner = fork()) < 0)
		die("fork: %s", strerror(errno));
	if (spawner == 0) {
		/* 3: the spawner's end of dwl's socket; 4: dwl's status, for COMMAND. Copied above 9
		 * first, so placing one cannot overwrite the other. */
		int a = fcntl(sv[0], F_DUPFD_CLOEXEC, 10), b = fcntl(st[0], F_DUPFD_CLOEXEC, 10);
		if (a < 0 || b < 0 || dup2(a, 3) < 0 || dup2(b, 4) < 0)
			_exit(127);
		execv(DWL_BIN, sargv);
		fprintf(stderr, "kryptik-launch: cannot run %s: %s\n", DWL_BIN, strerror(errno));
		_exit(127);
	}
	close(sv[0]);
	close(st[0]);

	#define PUT(...) do { \
		int n_ = snprintf(req + len, sizeof req - len, __VA_ARGS__); \
		if (n_ < 0 || (size_t)n_ >= sizeof req - len) \
			die("the desktop's request is too long"); \
		len += (size_t)n_; \
	} while (0)
	PUT("desktop\n");
	for (i = 0; i < (int)(sizeof desktop_env / sizeof *desktop_env); i++) {
		const char *v = getenv(desktop_env[i]);
		if (v && !strchr(v, '\n'))
			PUT("env %s=%s\n", desktop_env[i], v);
	}
	PUT("end\n");
	#undef PUT

	int fds[3] = { sv[1], st[1], STDERR_FILENO };
	if (ask_desktop(req, fds, said, sizeof said)) {
		for (last = p = said; *p; p++)
			if (*p == '\n' && p[1])
				last = p + 1;
		fprintf(stderr, "kryptik-launch: the desktop ended: %s",
			strncmp(last, "started ", 8) == 0 ? "the launch daemon is gone\n" : last);
		/* The spawner, told by its socket, ends the chrome, then itself. */
		close(sv[1]);
		close(st[1]);
		while (waitpid(spawner, NULL, 0) < 0 && errno == EINTR)
			;
		return 0;
	}
	fprintf(stderr, "kryptik-launch: dwl starts with group kryptik, in the session's process: %s", said);
	int a = fcntl(sv[1], F_DUPFD_CLOEXEC, 10);
	if (a < 0 || dup2(a, 3) < 0 || dup2(st[1], STDOUT_FILENO) < 0)
		die("dwl's descriptors: %s", strerror(errno));
	execl(DWL_BIN, DWL_BIN, "-S", "3", (char *)NULL);
	die("cannot run %s: %s", DWL_BIN, strerror(errno));
}

int main(int argc, char **argv)
{
	int ask = 0, no_display = 0, pass_fd = -1, sep = -1;
	const char *zone = NULL, *mode = "run";
	int i;
	if (argc >= 2 && strncmp(argv[1], "--wifi-", 7) == 0)
		return wifi_main(argc, argv);
	if (argc >= 2 && strcmp(argv[1], "--update") == 0)
		return update_main(argc, argv);
	if (argc >= 2 && strcmp(argv[1], "--check-password") == 0)
		return password_main(argc);
	if (argc >= 2 && strncmp(argv[1], "--stick", 7) == 0)
		return stick_main(argc, argv);
	if (argc >= 2 && strncmp(argv[1], "--camera-", 9) == 0)
		return camera_main(argc, argv);
	if (argc >= 2 && strcmp(argv[1], "--desktop") == 0)
		return desktop_main(argc, argv);
	if (argc == 4 && strcmp(argv[1], "--clipboard-move") == 0) {
		if (!ident_ok(argv[2]) || !ident_ok(argv[3]))
			usage();
		return clipboard_move(argv[2], argv[3]);
	}
	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--") == 0) { sep = i; break; }
		else if (strcmp(argv[i], "--ask") == 0) ask = 1;
		else if (strcmp(argv[i], "--no-display") == 0) no_display = 1;
		else if (strcmp(argv[i], "--passphrase-fd") == 0 && i + 1 < argc) pass_fd = fd_arg(argv[++i]);
		else if (strcmp(argv[i], "--stop") == 0) mode = "stop";
		else if (strcmp(argv[i], "--info") == 0) mode = "info";
		else if (strcmp(argv[i], "--resume") == 0) mode = "resume";
		else if (strcmp(argv[i], "--runtime-dir") == 0) mode = "runtime";
		else if (argv[i][0] == '-') usage();
		else if (!zone) zone = argv[i];
		else usage();
	}
	if (strcmp(mode, "runtime") == 0) {
		char *r = talk("runtime\n", -1);
		if (strncmp(r, "ok ", 3) != 0)
			die("%s", r);
		char *nl = strchr(r, '\n');
		if (nl) *nl = 0;
		puts(r + 3);
		return 0;
	}
	if (!zone || !ident_ok(zone))
		usage();
	if (strcmp(mode, "stop") == 0) {
		char req[128];
		snprintf(req, sizeof req, "stop %s\n", zone);
		char *r = talk(req, -1);
		fputs(r, strncmp(r, "ok", 2) == 0 ? stdout : stderr);
		return strncmp(r, "ok", 2) == 0 ? 0 : 1;
	}
	if (strcmp(mode, "resume") == 0) {
		if (pass_fd < 0) {
			int tty = isatty(0) ? open("/dev/tty", O_RDWR | O_CLOEXEC) : -1;
			if (tty < 0)
				die("--resume reads the passphrase on a terminal, or from --passphrase-fd N");
			pass_fd = passphrase_from_tty(tty, zone);
		}
		return resume_zone(zone, pass_fd);
	}
	if (strcmp(mode, "info") == 0) {
		char req[128];
		snprintf(req, sizeof req, "info %s\n", zone);
		char *r = talk(req, -1);
		fputs(r, strncmp(r, "error", 5) == 0 ? stderr : stdout);
		return strncmp(r, "error", 5) == 0 ? 1 : 0;
	}
	if (sep < 0 || sep + 1 >= argc)
		usage();
	char **cmd = argv + sep + 1;
	int ncmd = argc - sep - 1;

	int encrypted = 0, waiting = 0;
	if (ask || pass_fd >= 0)
		zone_volume(zone, &encrypted, &waiting);
	if (ask && pass_fd < 0 && encrypted) {
		if (waiting)
			fprintf(stderr, "zone %s waits for its volume's passphrase since the machine slept\n", zone);
		/* A terminal on stdin is not enough: dwl's spawn keeps the
		 * session's stdin but calls setsid(), so /dev/tty will not open. */
		int tty = isatty(0) ? open("/dev/tty", O_RDWR | O_CLOEXEC) : -1;
		if (tty >= 0) {
			pass_fd = passphrase_from_tty(tty, zone);
		} else {
			/* The trusted chrome prompts and calls back with --passphrase-fd. */
			char **nargv = calloc((size_t)ncmd + 8, sizeof *nargv);
			if (!nargv)
				die("out of memory");
			int k = 0;
			nargv[k++] = CHROME_BIN;
			nargv[k++] = "--prompt";
			nargv[k++] = (char *)zone;
			if (no_display) nargv[k++] = "--no-display";
			nargv[k++] = "--";
			for (i = 0; i < ncmd; i++) nargv[k++] = cmd[i];
			nargv[k] = NULL;
			execv(CHROME_BIN, nargv);
			die("cannot run %s: %s", CHROME_BIN, strerror(errno));
		}
	}

	/* The zone runs already, frozen: the passphrase gives it its volume back, and it goes on
	 * where it was rather than starting again. */
	if (waiting)
		return resume_zone(zone, pass_fd);

	/* Every string is counted; 1024 covers the fixed words. */
	size_t cap = 1024 + strlen(zone);
	for (i = 0; i < ncmd; i++)
		cap += strlen(cmd[i]) + 8;
	char *req = malloc(cap);
	if (!req)
		die("out of memory");
	/* snprintf returns the length it wanted: unchecked, len would run past the buffer. */
	size_t len = 0;
	#define PUT(...) do { \
		int n_ = snprintf(req + len, cap - len, __VA_ARGS__); \
		if (n_ < 0 || (size_t)n_ >= cap - len) \
			die("request too long"); \
		len += (size_t)n_; \
	} while (0)
	PUT("run %s%s%s\n", zone, no_display ? "" : " wayland", pass_fd >= 0 ? " pass=fd" : "");
	for (i = 0; i < ncmd; i++) {
		if (strchr(cmd[i], '\n'))
			die("argument %d contains a newline", i);
		PUT("arg %s\n", cmd[i]);
	}
	PUT("end\n");
	#undef PUT

	char *r = talk(req, pass_fd);
	if (pass_fd >= 0)
		close(pass_fd);
	fprintf(stderr, "kryptik-launch: zone %s: %s", zone, r);
	return strncmp(r, "ok ", 3) == 0 ? 0 : 1;
}
