/* kryptik-launch: start a program inside a zone from the desktop session.
 *
 * The session runs as an ordinary user and cannot create zones. It can ask
 * zone 0 to: kryptikd's launch daemon listens on a root-owned socket that
 * members of group `kryptik` may connect to (kryptikd serve). This program
 * is the client side of that conversation, and the only thing the
 * compositor's keybindings and the chrome's menu ever run.
 *
 *   kryptik-launch [--ask | --passphrase-fd N] [--no-display] ZONE -- COMMAND [ARG...]
 *   kryptik-launch --stop ZONE
 *   kryptik-launch --info ZONE          encrypted yes|no, running yes|no
 *   kryptik-launch --runtime-dir        print the session's XDG_RUNTIME_DIR, creating it
 *
 * With a display, the zone's Wayland proxy (kryptik-wlproxy) is started
 * first if it is not already running, listening at
 * $XDG_RUNTIME_DIR/kryptik/ZONE/wayland-0 and connected to the session's
 * compositor; that socket is what the daemon binds into the zone. The zone
 * never sees the compositor's own socket.
 *
 * --ask: if the zone is encrypted, collect the passphrase - on the terminal
 * when there is one, otherwise by handing over to the trusted chrome
 * (kryptik-chrome --prompt), which draws the prompt and calls back here
 * with --passphrase-fd. The passphrase travels as a descriptor over
 * SCM_RIGHTS and is never on a command line or in the environment.
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
#include <sys/un.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#define LAUNCH_SOCKET "/run/kryptik-launch/launch.sock"
#define PROXY_BIN "/usr/bin/kryptik-wlproxy"
#define CHROME_BIN "/usr/bin/kryptik-chrome"

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

/* One request to the daemon: send text (and one descriptor, if fd >= 0),
 * read the whole reply. Returns the reply, malloc'ed. */
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

static int pid_is_proxy(pid_t pid)
{
	char path[64], buf[256];
	if (pid <= 0 || kill(pid, 0) != 0)
		return 0;
	snprintf(path, sizeof path, "/proc/%d/cmdline", (int)pid);
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return 0;
	ssize_t n = read(fd, buf, sizeof buf - 1);
	close(fd);
	if (n <= 0)
		return 0;
	buf[n] = 0;
	return strstr(buf, "kryptik-wlproxy") != NULL;
}

/* Make sure the zone's proxy is up; return the socket path (static). */
static const char *ensure_proxy(const char *zone)
{
	static char sock[PATH_MAX];
	char dir[PATH_MAX], pidfile[PATH_MAX], logfile[PATH_MAX], upstream[PATH_MAX];
	const char *rt = getenv("XDG_RUNTIME_DIR");
	const char *disp = getenv("WAYLAND_DISPLAY");
	if (!rt || !*rt)
		die("XDG_RUNTIME_DIR is not set; use --no-display for a zone without a window");
	if (!disp || !*disp)
		disp = "wayland-0";
	if (disp[0] == '/')
		snprintf(upstream, sizeof upstream, "%s", disp);
	else
		snprintf(upstream, sizeof upstream, "%s/%s", rt, disp);
	snprintf(dir, sizeof dir, "%s/kryptik", rt);
	mkdir(dir, 0700);
	snprintf(dir, sizeof dir, "%s/kryptik/%s", rt, zone);
	if (mkdir(dir, 0700) < 0 && errno != EEXIST)
		die("%s: %s", dir, strerror(errno));
	snprintf(sock, sizeof sock, "%s/wayland-0", dir);
	snprintf(pidfile, sizeof pidfile, "%s/proxy.pid", dir);
	snprintf(logfile, sizeof logfile, "%s/proxy.log", dir);

	FILE *f = fopen(pidfile, "r");
	if (f) {
		int pid = 0;
		if (fscanf(f, "%d", &pid) == 1 && pid_is_proxy(pid)) {
			fclose(f);
			return sock;
		}
		fclose(f);
	}
	struct stat st;
	if (stat(upstream, &st) != 0 || !S_ISSOCK(st.st_mode))
		die("no compositor at %s", upstream);

	pid_t pid = fork();
	if (pid < 0)
		die("fork: %s", strerror(errno));
	if (pid == 0) {
		setsid();
		int null = open("/dev/null", O_RDONLY);
		int log = open(logfile, O_WRONLY | O_CREAT | O_APPEND, 0600);
		if (null >= 0) dup2(null, 0);
		if (log >= 0) { dup2(log, 1); dup2(log, 2); }
		execl(PROXY_BIN, "kryptik-wlproxy", "--zone", zone, "--listen", sock, "--upstream", upstream,
		      "--max-clients", "32", (char *)NULL);
		_exit(127);
	}
	f = fopen(pidfile, "w");
	if (f) {
		fprintf(f, "%d\n", (int)pid);
		fclose(f);
	}
	/* Wait for the listener, briefly. */
	for (int i = 0; i < 60; i++) {
		if (stat(sock, &st) == 0 && S_ISSOCK(st.st_mode))
			return sock;
		int status;
		if (waitpid(pid, &status, WNOHANG) == pid)
			die("kryptik-wlproxy exited before listening (see %s)", logfile);
		struct timespec ts = { 0, 50 * 1000 * 1000 };
		nanosleep(&ts, NULL);
	}
	die("kryptik-wlproxy did not start listening on %s (see %s)", sock, logfile);
}

/* Read a passphrase from the terminal into a memfd; returns the fd. */
static int passphrase_from_tty(const char *zone)
{
	int tty = open("/dev/tty", O_RDWR | O_CLOEXEC);
	if (tty < 0)
		die("no terminal to ask on: %s", strerror(errno));
	struct termios old, raw;
	tcgetattr(tty, &old);
	raw = old;
	raw.c_lflag &= ~(tcflag_t)ECHO;
	dprintf(tty, "passphrase for zone %s: ", zone);
	tcsetattr(tty, TCSAFLUSH, &raw);
	char buf[512];
	ssize_t n = read(tty, buf, sizeof buf - 1);
	tcsetattr(tty, TCSAFLUSH, &old);
	dprintf(tty, "\n");
	close(tty);
	if (n <= 0)
		die("no passphrase");
	while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r'))
		n--;
	if (n == 0)
		die("empty passphrase");
	int fd = memfd_create("kryptik-passphrase", 0);
	if (fd < 0)
		die("memfd_create: %s", strerror(errno));
	if (write(fd, buf, (size_t)n) != n)
		die("memfd write");
	memset(buf, 0, sizeof buf);
	lseek(fd, 0, SEEK_SET);
	return fd;
}

static int zone_is_encrypted(const char *zone)
{
	char req[128];
	snprintf(req, sizeof req, "info %s\n", zone);
	char *r = talk(req, -1);
	if (strncmp(r, "error", 5) == 0)
		die("%s", r);
	int enc = strstr(r, "encrypted yes") != NULL;
	free(r);
	return enc;
}

static void usage(void)
{
	fputs("usage: kryptik-launch [--ask | --passphrase-fd N] [--no-display] ZONE -- COMMAND [ARG...]\n"
	      "       kryptik-launch --stop ZONE\n"
	      "       kryptik-launch --info ZONE\n"
	      "       kryptik-launch --runtime-dir\n", stderr);
	exit(2);
}

int main(int argc, char **argv)
{
	int ask = 0, no_display = 0, pass_fd = -1, sep = -1;
	const char *zone = NULL, *mode = "run";
	int i;
	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--") == 0) { sep = i; break; }
		else if (strcmp(argv[i], "--ask") == 0) ask = 1;
		else if (strcmp(argv[i], "--no-display") == 0) no_display = 1;
		else if (strcmp(argv[i], "--passphrase-fd") == 0 && i + 1 < argc) pass_fd = atoi(argv[++i]);
		else if (strcmp(argv[i], "--stop") == 0) mode = "stop";
		else if (strcmp(argv[i], "--info") == 0) mode = "info";
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

	if (ask && pass_fd < 0 && zone_is_encrypted(zone)) {
		if (isatty(0)) {
			pass_fd = passphrase_from_tty(zone);
		} else {
			/* Hand over to the trusted chrome, which calls back with
			 * --passphrase-fd. Same zone, same command, same display choice. */
			char **nargv = calloc((size_t)ncmd + 8, sizeof *nargv);
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

	const char *wl = no_display ? NULL : ensure_proxy(zone);

	/* Build the request. */
	size_t cap = 1024;
	for (i = 0; i < ncmd; i++)
		cap += strlen(cmd[i]) + 8;
	char *req = malloc(cap);
	if (!req)
		die("out of memory");
	int len = snprintf(req, cap, "run %s%s%s%s\n", zone, wl ? " wayland=" : "", wl ? wl : "", pass_fd >= 0 ? " pass=fd" : "");
	for (i = 0; i < ncmd; i++) {
		if (strchr(cmd[i], '\n'))
			die("argument %d contains a newline", i);
		len += snprintf(req + len, cap - (size_t)len, "arg %s\n", cmd[i]);
	}
	len += snprintf(req + len, cap - (size_t)len, "end\n");

	char *r = talk(req, pass_fd);
	if (pass_fd >= 0)
		close(pass_fd);
	if (strncmp(r, "ok ", 3) == 0) {
		fprintf(stderr, "kryptik-launch: zone %s: %s", zone, r);
		return 0;
	}
	fprintf(stderr, "kryptik-launch: zone %s: %s", zone, r);
	return 1;
}
