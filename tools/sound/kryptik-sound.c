/* kryptik-sound: zone 0's mixer (docs/design/laptop.md).
 *
 *   kryptik-sound ZONES            mix for the zones ZONES lists, a line each, "NAME UID", as
 *                                  `kryptikd sound zones` writes it
 *   kryptik-sound --control LINE   say LINE on the control socket and print the answer
 *
 * It runs as a user of its own whose group, audio, opens the card; never as root. Each zone
 * plays through a socket of its own, /run/kryptik-sound/zones/NAME/socket, in a directory
 * kryptikd binds into the zone at /run/kryptik/sound. The peer must be the uid the zone's root
 * maps to, which the kernel asserts (SO_PEERCRED) and the zone cannot choose. A zone records
 * only while the user has granted it the microphone, through the control socket,
 * /run/kryptik-sound/control/socket, which only group kryptik reaches: the session's.
 *
 * A zone's wire: one line, "play" or "record", answered "ok" or "error: WHY" on a line, then
 * raw interleaved frames, 48 kHz, two channels, signed 16-bit little-endian, and nothing else is
 * parsed: a zone that sends noise plays noise in its own stream. Control: one line a connection,
 * answered "ok", "error: WHY", or for status a line each and "end":
 *   status | volume [ZONE] 0..100 | mute [ZONE] on|off | grant ZONE | revoke [ZONE]
 * volume and mute without a zone are the master's. revoke ZONE, which kryptikd says when a zone
 * stops, ends that zone's grant alone.
 */
#define _GNU_SOURCE
#include <alsa/asoundlib.h>
#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#define RUN_DIR "/run/kryptik-sound"
#define CONTROL_PATH RUN_DIR "/control/socket"
#define RATE 48000
#define CHANNELS 2
#define FRAME 4                         /* bytes: two s16le samples */
#define PERIOD 480                      /* frames: 10 ms */
#define RING (PERIOD * 8 * FRAME)       /* bytes a stream may hold ahead: 80 ms */
#define MAX_ZONES 32
#define MAX_CONNS 64
#define PER_ZONE 8                      /* streams one zone may hold, so it cannot take them all */
#define CONTROL_SLOTS 8                 /* kept for control: the grant, revoke and the keys */
#define HELLO_MS 2000                   /* a connection must say what it is within this */
#define IDLE_MS 5000                    /* the card is closed after this with nothing to play */

enum kind { HELLO, PLAY, RECORD, CONTROL };

struct zone {
	char name[33];
	uid_t uid;
	int listen;
	int volume;                         /* 0..100 */
	int muted;
	long long refused_at;               /* the last refusal logged, and those since unlogged */
	int refused_since;
};

struct conn {
	int fd;
	enum kind kind;
	int zone;                           /* -1 for control */
	char line[128];
	size_t nline;
	long long since;
	unsigned char *ring;                /* PLAY: bytes to mix; RECORD: bytes to send */
	size_t head, len;
	int hup;                            /* PLAY: the zone hung up; what it sent still plays */
};

static struct zone zones[MAX_ZONES];
static int nzones;
static struct conn conns[MAX_CONNS];
static int granted = -1;                /* the zone that may record, or -1 */
static int master = 70, master_muted;
static snd_pcm_t *out, *in;
static long long last_play;

static void say(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void say(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	fputs("kryptik-sound: ", stderr);
	vfprintf(stderr, fmt, ap);
	fputc('\n', stderr);
	va_end(ap);
}

static long long now_ms(void)
{
	struct timespec t;
	clock_gettime(CLOCK_MONOTONIC, &t);
	return (long long)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

static int unix_addr(struct sockaddr_un *sa, const char *path)
{
	*sa = (struct sockaddr_un){ .sun_family = AF_UNIX };
	if (strlen(path) >= sizeof sa->sun_path)
		return -1;
	strcpy(sa->sun_path, path);
	return 0;
}

/* A listening socket at path, mode `mode`, in place of whatever was there. */
static int listen_at(const char *path, mode_t mode)
{
	struct sockaddr_un sa;
	if (unix_addr(&sa, path) < 0)
		return -1;
	int s = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
	if (s < 0)
		return -1;
	unlink(path);
	if (bind(s, (struct sockaddr *)&sa, sizeof sa) < 0 || chmod(path, mode) < 0 || listen(s, 8) < 0) {
		close(s);
		return -1;
	}
	return s;
}

/* Each zone's socket, in the directory the service made for it as root: the mixer cannot
 * replace the directory kryptikd binds into the zone, only the socket in it. */
static int read_zones(const char *file)
{
	FILE *f = fopen(file, "re");
	if (!f) {
		say("%s: %s", file, strerror(errno));
		return -1;
	}
	char name[64];
	unsigned long uid;
	while (nzones < MAX_ZONES && fscanf(f, "%63s %lu", name, &uid) == 2) {
		struct zone *z = &zones[nzones];
		if (strlen(name) > 32 || strspn(name, "abcdefghijklmnopqrstuvwxyz0123456789-_") != strlen(name)
		    || uid == 0 || uid > UINT32_MAX) {
			say("%s: refusing the line for %s", file, name);
			continue;
		}
		char sock[PATH_MAX];
		snprintf(sock, sizeof sock, "%s/zones/%s/socket", RUN_DIR, name);
		if ((z->listen = listen_at(sock, 0666)) < 0) {
			say("zone %s: no socket at %s: %s", name, sock, strerror(errno));
			continue;
		}
		snprintf(z->name, sizeof z->name, "%s", name);
		z->uid = (uid_t)uid;
		z->volume = 100;
		nzones++;
	}
	fclose(f);
	return 0;
}

static struct conn *new_conn(int fd, enum kind kind, int zone)
{
	for (int i = 0; i < MAX_CONNS; i++)
		if (!conns[i].fd) {
			conns[i] = (struct conn){ .fd = fd, .kind = kind, .zone = zone, .since = now_ms() };
			return &conns[i];
		}
	return NULL;
}

static void end_conn(struct conn *c)
{
	if (c->fd > 0)
		close(c->fd);
	free(c->ring);
	*c = (struct conn){ 0 };
}

/* Streams of one zone or, with -1, of all of them. */
static int streams_of(int zone)
{
	int n = 0;
	for (int i = 0; i < MAX_CONNS; i++)
		n += conns[i].fd && conns[i].kind != CONTROL && (zone < 0 || conns[i].zone == zone);
	return n;
}

/* A refused peer, logged once a minute a zone with the count since, so a zone's root or
 * nobody connecting in a loop cannot fill zone 0's log. */
static void refused(struct zone *z, unsigned uid)
{
	long long now = now_ms();
	if (z->refused_at && now - z->refused_at < 60000) {
		z->refused_since++;
		return;
	}
	if (z->refused_since)
		say("zone %s: refused a peer that is not the zone (uid %u), and %d more in the minute before",
		    z->name, uid, z->refused_since);
	else
		say("zone %s: refused a peer that is not the zone (uid %u)", z->name, uid);
	z->refused_at = now;
	z->refused_since = 0;
}

static void accept_on(int listen_fd, int zone)
{
	int fd = accept4(listen_fd, NULL, NULL, SOCK_CLOEXEC | SOCK_NONBLOCK);
	if (fd < 0)
		return;
	if (zone >= 0) {
		struct ucred cr = { 0 };
		socklen_t len = sizeof cr;
		if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cr, &len) < 0 || cr.uid != zones[zone].uid) {
			refused(&zones[zone], (unsigned)cr.uid);
			close(fd);
			return;
		}
		if (streams_of(zone) >= PER_ZONE || streams_of(-1) >= MAX_CONNS - CONTROL_SLOTS) {
			close(fd);
			return;
		}
	}
	if (!new_conn(fd, zone >= 0 ? HELLO : CONTROL, zone))
		close(fd);
}

static void reply(int fd, const char *text)
{
	ssize_t w = write(fd, text, strlen(text));
	(void)w;
}

/* The card a stream goes to: a USB device first, as one plugged in is meant to be used, then
 * the first card with a device 0 that way. A card with only HDMI outputs has none. */
static int pick_card(snd_pcm_stream_t dir)
{
	int card = -1, first = -1;
	snd_ctl_card_info_t *ci;
	snd_pcm_info_t *pi;
	snd_ctl_card_info_alloca(&ci);
	snd_pcm_info_alloca(&pi);
	while (snd_card_next(&card) == 0 && card >= 0) {
		char hw[16];
		snprintf(hw, sizeof hw, "hw:%d", card);
		snd_ctl_t *ctl;
		if (snd_ctl_open(&ctl, hw, 0) < 0)
			continue;
		snd_pcm_info_set_device(pi, 0);
		snd_pcm_info_set_subdevice(pi, 0);
		snd_pcm_info_set_stream(pi, dir);
		int has = snd_ctl_pcm_info(ctl, pi) == 0;
		int usb = snd_ctl_card_info(ctl, ci) == 0 && !strcmp(snd_ctl_card_info_get_driver(ci), "USB-Audio");
		snd_ctl_close(ctl);
		if (has && usb)
			return card;
		if (has && first < 0)
			first = card;
	}
	return first;
}

static int named(snd_mixer_elem_t *e, const char *const *names)
{
	for (; *names; names++)
		if (!strcmp(snd_mixer_selem_get_name(e), *names))
			return 1;
	return 0;
}

/* The card's own controls at unity and on, so the mixer's volumes are the only ones that act:
 * a card can come up muted, and nothing else here sets it. */
static void levels(int card)
{
	static const char *const play[] = { "Master", "PCM", "Speaker", "Headphone", "Front", "Line Out", NULL };
	static const char *const rec[] = { "Capture", NULL };
	char hw[16];
	snprintf(hw, sizeof hw, "hw:%d", card);
	snd_mixer_t *m;
	if (snd_mixer_open(&m, 0) < 0)
		return;
	if (snd_mixer_attach(m, hw) < 0 || snd_mixer_selem_register(m, NULL, NULL) < 0 || snd_mixer_load(m) < 0) {
		snd_mixer_close(m);
		return;
	}
	for (snd_mixer_elem_t *e = snd_mixer_first_elem(m); e; e = snd_mixer_elem_next(e)) {
		long lo, hi;
		if (named(e, play)) {
			if (snd_mixer_selem_has_playback_switch(e))
				snd_mixer_selem_set_playback_switch_all(e, 1);
			if (snd_mixer_selem_has_playback_volume(e) && snd_mixer_selem_set_playback_dB_all(e, 0, 1) < 0
			    && snd_mixer_selem_get_playback_volume_range(e, &lo, &hi) == 0)
				snd_mixer_selem_set_playback_volume_all(e, hi);
		}
		if (named(e, rec)) {
			if (snd_mixer_selem_has_capture_switch(e))
				snd_mixer_selem_set_capture_switch_all(e, 1);
			if (snd_mixer_selem_has_capture_volume(e) && snd_mixer_selem_set_capture_dB_all(e, 0, 1) < 0
			    && snd_mixer_selem_get_capture_volume_range(e, &lo, &hi) == 0)
				snd_mixer_selem_set_capture_volume_all(e, hi);
		}
	}
	snd_mixer_close(m);
}

/* The card at the wire's format, which plughw converts to whatever the device takes. */
static snd_pcm_t *open_pcm(snd_pcm_stream_t dir)
{
	int card = pick_card(dir);
	if (card < 0)
		return NULL;
	char dev[24];
	snprintf(dev, sizeof dev, "plughw:%d,0", card);
	snd_pcm_t *p;
	int err = snd_pcm_open(&p, dev, dir, SND_PCM_NONBLOCK);
	if (err == 0 && (err = snd_pcm_set_params(p, SND_PCM_FORMAT_S16_LE, SND_PCM_ACCESS_RW_INTERLEAVED, CHANNELS,
	                                          RATE, 1, 40000)) < 0)
		snd_pcm_close(p);
	if (err < 0) {
		say("%s: %s", dev, snd_strerror(err));
		return NULL;
	}
	levels(card);
	say("%s %s", dir == SND_PCM_STREAM_PLAYBACK ? "playing on" : "recording from", dev);
	return p;
}

static int zone_named(const char *name)
{
	for (int i = 0; i < nzones; i++)
		if (!strcmp(zones[i].name, name))
			return i;
	return -1;
}

static int percent(const char *s)
{
	char *end;
	long v = strtol(s, &end, 10);
	return *s && !*end && v >= 0 && v <= 100 ? (int)v : -1;
}

static int on_off(const char *s)
{
	return !strcmp(s, "on") ? 1 : !strcmp(s, "off") ? 0 : -1;
}

static void end_records(int keep)
{
	for (int i = 0; i < MAX_CONNS; i++)
		if (conns[i].fd && conns[i].kind == RECORD && conns[i].zone != keep)
			end_conn(&conns[i]);
}

static void status(struct conn *c)
{
	char text[4096];
	size_t at = (size_t)snprintf(text, sizeof text, "master %d%s\n", master, master_muted ? " muted" : "");
	for (int i = 0; i < nzones && at < sizeof text - 80; i++) {
		int rec = 0;
		for (int j = 0; j < MAX_CONNS; j++)
			rec |= conns[j].fd && conns[j].kind == RECORD && conns[j].zone == i;
		at += (size_t)snprintf(text + at, sizeof text - at, "zone %s %d%s%s%s\n", zones[i].name, zones[i].volume,
		                        zones[i].muted ? " muted" : "", granted == i ? " granted" : "", rec ? " recording" : "");
	}
	snprintf(text + at, sizeof text - at, "end\n");
	reply(c->fd, text);
}

static void control_line(struct conn *c)
{
	char a[16] = "", b[40] = "", d[16] = "";
	int n = sscanf(c->line, "%15s %39s %15s", a, b, d), z = n >= 2 ? zone_named(b) : -1, v;
	int is_volume = !strcmp(a, "volume"), is_mute = !strcmp(a, "mute");
	int names_zone = ((!strcmp(a, "grant") || !strcmp(a, "revoke")) && n == 2) || ((is_volume || is_mute) && n == 3);
	const char *answer = "ok\n";
	if (!strcmp(a, "status") && n == 1) {
		status(c);
		answer = NULL;
	} else if (names_zone && z < 0)
		answer = "error: no zone with sound by that name\n";
	else if (is_volume && n == 2 && (v = percent(b)) >= 0)
		master = v;
	else if (is_volume && n == 3 && (v = percent(d)) >= 0)
		zones[z].volume = v;
	else if (is_mute && n == 2 && (v = on_off(b)) >= 0)
		master_muted = v;
	else if (is_mute && n == 3 && (v = on_off(d)) >= 0)
		zones[z].muted = v;
	else if (!strcmp(a, "grant") && n == 2) {
		/* One zone at a time: a grant moves, and what another zone recorded ends. */
		end_records(z);
		granted = z;
		say("the microphone is granted to %s", zones[z].name);
	} else if (!strcmp(a, "revoke") && n <= 2) {
		if (granted >= 0 && (n == 1 || z == granted)) {
			end_records(-1);
			say("the microphone is taken back from %s", zones[granted].name);
			granted = -1;
		}
	} else
		answer = "error: status | volume [ZONE] 0..100 | mute [ZONE] on|off | grant ZONE | revoke [ZONE]\n";
	if (answer)
		reply(c->fd, answer);
	end_conn(c);
}

/* What a zone says it is: play, or record while it holds the grant and no other recording runs. */
static void hello_line(struct conn *c)
{
	int recording = 0;
	for (int i = 0; i < MAX_CONNS; i++)
		recording |= conns[i].fd && conns[i].kind == RECORD;
	const char *refusal = NULL;
	if (!strcmp(c->line, "record") && granted != c->zone)
		refusal = "error: the microphone is not granted to this zone\n";
	else if (!strcmp(c->line, "record") && recording)
		refusal = "error: the microphone is in use\n";
	else if (strcmp(c->line, "play") && strcmp(c->line, "record"))
		refusal = "error: play or record\n";
	else if (!(c->ring = malloc(RING)))
		refusal = "error: out of memory\n";
	if (refusal) {
		reply(c->fd, refusal);
		end_conn(c);
		return;
	}
	c->kind = strcmp(c->line, "play") ? RECORD : PLAY;
	if (c->kind == RECORD)
		say("%s records", zones[c->zone].name);
	reply(c->fd, "ok\n");
}

/* Bytes up to a newline, the line taken without it once it ends. */
static void read_line(struct conn *c)
{
	char ch;
	ssize_t r;
	while ((r = read(c->fd, &ch, 1)) == 1) {
		if (ch == '\n') {
			c->line[c->nline] = 0;
			c->nline = 0;
			if (c->kind == CONTROL)
				control_line(c);
			else
				hello_line(c);
			return;
		}
		if (c->nline + 1 >= sizeof c->line) {
			end_conn(c);
			return;
		}
		c->line[c->nline++] = ch;
	}
	if (r == 0 || (errno != EAGAIN && errno != EINTR))
		end_conn(c);
}

/* As much of a zone's stream as its ring holds; a zone that gets ahead waits on its socket. */
static void read_play(struct conn *c)
{
	while (c->len < RING) {
		size_t tail = (c->head + c->len) % RING, room = RING - c->len;
		if (room > RING - tail)
			room = RING - tail;
		ssize_t r = read(c->fd, c->ring + tail, room);
		if (r > 0) {
			c->len += (size_t)r;
			continue;
		}
		if (r == 0 || (errno != EAGAIN && errno != EINTR)) {
			/* What it sent before it hung up still plays; the stream ends once mixed. */
			c->hup = 1;
			if (c->len < FRAME)
				end_conn(c);
		}
		return;
	}
}

static int16_t sample_at(struct conn *c, size_t i)
{
	size_t at = (c->head + i * 2) % RING;
	return (int16_t)(c->ring[at] | (c->ring[(at + 1) % RING] << 8));
}

/* Volume as amplitude, squared, so the steps sound even: 0..100 to 0..10000. */
static int64_t gain(int volume, int muted)
{
	return muted ? 0 : (int64_t)volume * volume;
}

/* One period of every stream's whole frames at its zone's volume and the master's, summed with
 * saturation; a stream short of a period plays what it has and silence after. */
static void mix(int16_t *dst)
{
	int64_t acc[PERIOD * CHANNELS] = { 0 };
	for (int i = 0; i < MAX_CONNS; i++) {
		struct conn *c = &conns[i];
		if (!c->fd || c->kind != PLAY)
			continue;
		size_t have = c->len / FRAME;
		if (have > PERIOD)
			have = PERIOD;
		int64_t g = gain(zones[c->zone].volume, zones[c->zone].muted);
		for (size_t s = 0; s < have * CHANNELS; s++)
			acc[s] += sample_at(c, s) * g;
		c->head = (c->head + have * FRAME) % RING;
		c->len -= have * FRAME;
		if (c->hup && c->len < FRAME)
			end_conn(c);
	}
	int64_t m = gain(master, master_muted);
	for (size_t s = 0; s < PERIOD * CHANNELS; s++) {
		int64_t v = acc[s] * m / 100000000;
		dst[s] = (int16_t)(v > INT16_MAX ? INT16_MAX : v < INT16_MIN ? INT16_MIN : v);
	}
}

/* Whether any stream has a frame to play: an open stream with nothing in it keeps no card on. */
static int playing(void)
{
	for (int i = 0; i < MAX_CONNS; i++)
		if (conns[i].fd && conns[i].kind == PLAY && conns[i].len >= FRAME)
			return 1;
	return 0;
}

static void close_pcm(snd_pcm_t **p)
{
	snd_pcm_drop(*p);
	snd_pcm_close(*p);
	*p = NULL;
}

/* A recovered underrun plays on; a card that went away (a USB device pulled out) is closed,
 * and the next stream picks again. */
static int recovered(snd_pcm_t **p, int err)
{
	if (snd_pcm_recover(*p, err, 1) == 0)
		return 1;
	say("the card stopped: %s", snd_strerror(err));
	close_pcm(p);
	return 0;
}

static void play_out(void)
{
	static long long next_try, next_drain;
	long long now = now_ms();
	if (playing())
		last_play = now;
	if (!out && playing() && now >= next_try && !(out = open_pcm(SND_PCM_STREAM_PLAYBACK)))
		next_try = now + 1000;
	if (!out) {
		/* Nothing to play on: the streams are taken in time and dropped, so no zone stalls. */
		if (playing() && now >= next_drain) {
			int16_t sink[PERIOD * CHANNELS];
			mix(sink);
			next_drain = now + PERIOD * 1000 / RATE;
		}
		return;
	}
	if (!playing() && now - last_play > IDLE_MS) {
		close_pcm(&out);
		return;
	}
	int16_t buf[PERIOD * CHANNELS];
	for (;;) {
		snd_pcm_sframes_t avail = snd_pcm_avail_update(out);
		if (avail < 0) {
			recovered(&out, (int)avail);
			return;
		}
		if (avail < PERIOD)
			return;
		mix(buf);
		snd_pcm_sframes_t w = snd_pcm_writei(out, buf, PERIOD);
		/* A full card takes the period later: nothing is wrong with it. */
		if (w == -EAGAIN)
			return;
		if (w < 0 && !recovered(&out, (int)w))
			return;
	}
}

/* The granted zone's recording: what the card captured, a period at a time; a zone that does
 * not keep up loses what it did not take. */
static void record_in(void)
{
	struct conn *rec = NULL;
	for (int i = 0; i < MAX_CONNS; i++)
		if (conns[i].fd && conns[i].kind == RECORD)
			rec = &conns[i];
	if (!rec) {
		if (in)
			close_pcm(&in);
		return;
	}
	if (!in) {
		if (!(in = open_pcm(SND_PCM_STREAM_CAPTURE))) {
			end_conn(rec);
			return;
		}
		snd_pcm_start(in);
	}
	/* Captured periods go into the zone's ring whole, or not at all when it is full, so what
	 * the zone reads stays aligned to frames however the socket takes it. */
	int16_t buf[PERIOD * CHANNELS];
	for (;;) {
		snd_pcm_sframes_t r = snd_pcm_readi(in, buf, PERIOD);
		if (r == -EAGAIN)
			break;
		if (r < 0) {
			if (!recovered(&in, (int)r)) {
				end_conn(rec);
				return;
			}
			snd_pcm_start(in);
			continue;
		}
		size_t bytes = (size_t)r * FRAME;
		if (rec->len + bytes > RING)
			continue;
		for (size_t i = 0; i < bytes; i++)
			rec->ring[(rec->head + rec->len + i) % RING] = ((unsigned char *)buf)[i];
		rec->len += bytes;
	}
	while (rec->len) {
		size_t run = rec->len < RING - rec->head ? rec->len : RING - rec->head;
		ssize_t w = write(rec->fd, rec->ring + rec->head, run);
		if (w <= 0) {
			if (w < 0 && errno != EAGAIN && errno != EINTR)
				end_conn(rec);
			return;
		}
		rec->head = (rec->head + (size_t)w) % RING;
		rec->len -= (size_t)w;
	}
}

/* --control: one line to the mixer, its answer to stdout; 0 for "ok" or a status. */
static int control_client(const char *line)
{
	struct sockaddr_un sa;
	int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0 || unix_addr(&sa, CONTROL_PATH) < 0 || connect(fd, (struct sockaddr *)&sa, sizeof sa) < 0) {
		fprintf(stderr, "kryptik-sound: %s: %s\n", CONTROL_PATH, strerror(errno));
		return 1;
	}
	char buf[4096];
	size_t got = 0;
	ssize_t r;
	if (dprintf(fd, "%s\n", line) < 0)
		return 1;
	while (got < sizeof buf - 1 && (r = read(fd, buf + got, sizeof buf - 1 - got)) > 0)
		got += (size_t)r;
	buf[got] = 0;
	fputs(buf, stdout);
	return !strcmp(buf, "ok\n") || (got >= 4 && !strcmp(buf + got - 4, "end\n")) ? 0 : 1;
}

int main(int argc, char **argv)
{
	if (argc == 3 && !strcmp(argv[1], "--control"))
		return control_client(argv[2]);
	if (argc != 2 || argv[1][0] == '-') {
		fputs("usage: kryptik-sound ZONES | kryptik-sound --control LINE\n", stderr);
		return 2;
	}
	if (geteuid() == 0) {
		say("refusing to run as root");
		return 2;
	}
	signal(SIGPIPE, SIG_IGN);
	if (read_zones(argv[1]) < 0)
		return 1;
	int control = listen_at(CONTROL_PATH, 0660);
	if (control < 0)
		say("no control socket at %s: %s; volume and the microphone stay as they are", CONTROL_PATH, strerror(errno));
	say("mixing for %d zone(s)", nzones);
	for (;;) {
		struct pollfd p[MAX_ZONES + 1 + MAX_CONNS + 8];
		struct conn *of[MAX_ZONES + 1 + MAX_CONNS + 8];
		int n = 0, timeout = 1000;
		for (int i = 0; i < nzones; i++)
			p[n] = (struct pollfd){ .fd = zones[i].listen, .events = POLLIN }, of[n++] = NULL;
		int control_at = n;
		if (control >= 0)
			p[n] = (struct pollfd){ .fd = control, .events = POLLIN }, of[n++] = NULL;
		long long now = now_ms();
		for (int i = 0; i < MAX_CONNS; i++) {
			struct conn *c = &conns[i];
			if (!c->fd)
				continue;
			if ((c->kind == HELLO || c->kind == CONTROL) && now - c->since > HELLO_MS) {
				end_conn(c);
				continue;
			}
			/* A stream whose ring is full is not read: its zone waits. One that hung up is
			 * not watched, only mixed until it ends. */
			if (c->hup)
				continue;
			short ev = c->kind == RECORD ? 0 : c->kind == PLAY && c->len >= RING ? 0 : POLLIN;
			p[n] = (struct pollfd){ .fd = c->fd, .events = ev }, of[n++] = c;
		}
		int conns_end = n;
		snd_pcm_t *pcms[2] = { out, in };
		for (int k = 0; k < 2; k++) {
			if (!pcms[k])
				continue;
			int m = snd_pcm_poll_descriptors(pcms[k], p + n, 4);
			for (int i = 0; i < m; i++)
				of[n + i] = NULL;
			n += m > 0 ? m : 0;
		}
		if (out || in || playing())
			timeout = 10;
		if (poll(p, (nfds_t)n, timeout) < 0 && errno != EINTR) {
			say("poll: %s", strerror(errno));
			return 1;
		}
		for (int i = 0; i < nzones; i++)
			if (p[i].revents & POLLIN)
				accept_on(zones[i].listen, i);
		if (control >= 0 && p[control_at].revents & POLLIN)
			accept_on(control, -1);
		for (int i = control_at + (control >= 0); i < conns_end; i++) {
			struct conn *c = of[i];
			if (!c || !c->fd || !p[i].revents)
				continue;
			if (c->kind == PLAY)
				read_play(c);
			else if (c->kind == HELLO || c->kind == CONTROL)
				read_line(c);
			else if (p[i].revents & (POLLHUP | POLLERR))
				end_conn(c);
		}
		play_out();
		record_in();
	}
}
