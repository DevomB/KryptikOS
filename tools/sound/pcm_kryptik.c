/* A zone's sound device for alsa-lib (docs/design/laptop.md): an external PCM plugin, built as
 * libasound_module_pcm_kryptik.so, that plays and records through zone 0's mixer at
 * /run/kryptik/sound/socket, which kryptikd binds into the zone. /usr/etc/alsa/conf.d makes it
 * the default device behind alsa-lib's plug, which converts whatever a program asks for to the
 * one format the mixer takes: 48 kHz, two channels, signed 16-bit little-endian.
 *
 * The wire: "play" or "record" on a line, the mixer's "ok" or "error: WHY" on a line back, then
 * raw frames. Recording is refused unless the user has granted the microphone to this zone.
 */
#define _GNU_SOURCE
#include <alsa/asoundlib.h>
#include <alsa/pcm_external.h>
#include <errno.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#define SOCKET_PATH "/run/kryptik/sound/socket"
/* <linux/sockios.h>'s name for what the socket has yet to send, which glibc's headers leave
 * to the terminal's. */
#ifndef SIOCOUTQ
#define SIOCOUTQ TIOCOUTQ
#endif
#define FRAME 4
/* What the socket holds ahead of the mixer, about 40 ms: the kernel doubles it, and the
 * mixer's own 80 ms come after. */
#define SEND_BUFFER 8192

typedef struct {
	snd_pcm_ioplug_t io;
	int fd;
	snd_pcm_uframes_t done;             /* frames handed over or taken, modulo the buffer */
} kryptik_t;

/* All of `len` bytes, waiting for the socket as long as it takes: a frame is never split. */
static int full(int fd, char *buf, size_t len, int writing)
{
	while (len) {
		ssize_t r = writing ? send(fd, buf, len, MSG_NOSIGNAL) : recv(fd, buf, len, 0);
		if (r < 0 && errno == EINTR)
			continue;
		if (r < 0 && errno == EAGAIN) {
			struct pollfd p = { .fd = fd, .events = writing ? POLLOUT : POLLIN };
			poll(&p, 1, -1);
			continue;
		}
		if (r <= 0)
			return -EIO;
		buf += r;
		len -= (size_t)r;
	}
	return 0;
}

static snd_pcm_sframes_t kr_transfer(snd_pcm_ioplug_t *io, const snd_pcm_channel_area_t *areas,
		snd_pcm_uframes_t offset, snd_pcm_uframes_t size)
{
	kryptik_t *k = io->private_data;
	char *buf = (char *)areas->addr + (areas->first + areas->step * offset) / 8;
	int writing = io->stream == SND_PCM_STREAM_PLAYBACK;
	/* Without blocking, as many whole frames as the socket takes now; a frame begun is
	 * finished, at most three bytes' wait. */
	if (io->nonblock) {
		ssize_t r = writing ? send(k->fd, buf, size * FRAME, MSG_DONTWAIT | MSG_NOSIGNAL)
		                    : recv(k->fd, buf, size * FRAME, MSG_DONTWAIT);
		if (r < 0)
			return errno == EAGAIN || errno == EINTR ? -EAGAIN : -EIO;
		if (r == 0)
			return -EIO;
		size_t part = (size_t)r % FRAME;
		if (part && full(k->fd, buf + r, FRAME - part, writing) < 0)
			return -EIO;
		size = ((size_t)r + FRAME - 1) / FRAME;
	} else if (full(k->fd, buf, size * FRAME, writing) < 0) {
		return -EIO;
	}
	k->done = (k->done + size) % io->buffer_size;
	return (snd_pcm_sframes_t)size;
}

/* Playback: what was handed to the mixer counts as played. Capture: what waits in the socket
 * counts as captured, up to a buffer's worth less a period, so the position never laps. */
static snd_pcm_sframes_t kr_pointer(snd_pcm_ioplug_t *io)
{
	kryptik_t *k = io->private_data;
	if (io->stream == SND_PCM_STREAM_PLAYBACK)
		return (snd_pcm_sframes_t)k->done;
	int bytes = 0;
	if (ioctl(k->fd, FIONREAD, &bytes) < 0)
		return -EIO;
	snd_pcm_uframes_t ready = (snd_pcm_uframes_t)bytes / FRAME, most = io->buffer_size - io->period_size;
	return (snd_pcm_sframes_t)((k->done + (ready < most ? ready : most)) % io->buffer_size);
}

/* Playback's delay is what still waits in the socket, capture's what waits to be read; the
 * mixer's own buffer is not counted. */
static int kr_delay(snd_pcm_ioplug_t *io, snd_pcm_sframes_t *delayp)
{
	kryptik_t *k = io->private_data;
	int bytes = 0;
	if (ioctl(k->fd, io->stream == SND_PCM_STREAM_PLAYBACK ? SIOCOUTQ : FIONREAD, &bytes) < 0)
		bytes = 0;
	*delayp = bytes / FRAME;
	return 0;
}

static int kr_start(snd_pcm_ioplug_t *io)
{
	(void)io;
	return 0;
}

static int kr_stop(snd_pcm_ioplug_t *io)
{
	(void)io;
	return 0;
}

static int kr_prepare(snd_pcm_ioplug_t *io)
{
	kryptik_t *k = io->private_data;
	k->done = 0;
	return 0;
}

static int kr_close(snd_pcm_ioplug_t *io)
{
	kryptik_t *k = io->private_data;
	close(k->fd);
	free(k);
	return 0;
}

/* The mixer's end closed, as a grant of the microphone to another zone closes a record: that
 * is an error. As alsa-lib reads the socket's poll, a hang-up is readable, so a reader would
 * wait for frames that never come, for ever and at full speed. */
static int kr_poll_revents(snd_pcm_ioplug_t *io, struct pollfd *pfd, unsigned int nfds,
		unsigned short *revents)
{
	kryptik_t *k = io->private_data;
	*revents = nfds ? pfd[0].revents : 0;
	if (*revents & (POLLERR | POLLNVAL))
		return 0;
	if (io->stream == SND_PCM_STREAM_PLAYBACK) {
		if (*revents & POLLHUP)
			*revents |= POLLERR;
		return 0;
	}
	/* Less than a frame left: the end, if the mixer hung up or a peek finds the stream over. */
	int bytes = 0;
	char c;
	if (!(*revents & (POLLIN | POLLHUP)) || ioctl(k->fd, FIONREAD, &bytes) < 0 || bytes >= FRAME)
		return 0;
	if ((*revents & POLLHUP) || recv(k->fd, &c, 1, MSG_PEEK | MSG_DONTWAIT) == 0)
		*revents |= POLLERR;
	return 0;
}

static const snd_pcm_ioplug_callback_t callbacks = {
	.start = kr_start,
	.stop = kr_stop,
	.pointer = kr_pointer,
	.transfer = kr_transfer,
	.prepare = kr_prepare,
	.delay = kr_delay,
	.close = kr_close,
	.poll_revents = kr_poll_revents,
};

/* The mixer's socket, told what this stream is; its answer, "ok" or why not. */
static int connect_mixer(snd_pcm_stream_t stream)
{
	struct sockaddr_un sa = { .sun_family = AF_UNIX };
	strcpy(sa.sun_path, SOCKET_PATH);
	int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -errno;
	if (connect(fd, (struct sockaddr *)&sa, sizeof sa) < 0) {
		int e = errno;
		close(fd);
		SNDERR("%s: %s: zone 0's mixer is not reachable", SOCKET_PATH, strerror(e));
		return -e;
	}
	int size = SEND_BUFFER;
	if (stream == SND_PCM_STREAM_PLAYBACK)
		setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &size, sizeof size);
	const char *hello = stream == SND_PCM_STREAM_PLAYBACK ? "play\n" : "record\n";
	char said[128];
	size_t n = 0;
	if (full(fd, (char *)hello, strlen(hello), 1) == 0)
		while (n < sizeof said - 1 && recv(fd, said + n, 1, 0) == 1 && said[n] != '\n')
			n++;
	said[n] = 0;
	if (strcmp(said, "ok")) {
		close(fd);
		SNDERR("zone 0's mixer: %s", n ? said : "no answer");
		return stream == SND_PCM_STREAM_CAPTURE ? -EACCES : -EIO;
	}
	return fd;
}

SND_PCM_PLUGIN_DEFINE_FUNC(kryptik)
{
	(void)root;
	snd_config_iterator_t i, next;
	snd_config_for_each(i, next, conf) {
		snd_config_t *n = snd_config_iterator_entry(i);
		const char *id;
		if (snd_config_get_id(n, &id) < 0)
			continue;
		if (!strcmp(id, "comment") || !strcmp(id, "type") || !strcmp(id, "hint"))
			continue;
		SNDERR("unknown field %s", id);
		return -EINVAL;
	}
	kryptik_t *k = calloc(1, sizeof *k);
	if (!k)
		return -ENOMEM;
	k->fd = connect_mixer(stream);
	if (k->fd < 0) {
		int e = k->fd;
		free(k);
		return e;
	}
	k->io.version = SND_PCM_IOPLUG_VERSION;
	k->io.name = "Kryptik zone sound";
	k->io.callback = &callbacks;
	k->io.private_data = k;
	k->io.poll_fd = k->fd;
	k->io.poll_events = stream == SND_PCM_STREAM_PLAYBACK ? POLLOUT : POLLIN;
	int err = snd_pcm_ioplug_create(&k->io, name, stream, mode);
	if (err < 0) {
		close(k->fd);
		free(k);
		return err;
	}
	static const unsigned int access[] = { SND_PCM_ACCESS_RW_INTERLEAVED };
	static const unsigned int format[] = { SND_PCM_FORMAT_S16_LE };
	if ((err = snd_pcm_ioplug_set_param_list(&k->io, SND_PCM_IOPLUG_HW_ACCESS, 1, access)) < 0
	    || (err = snd_pcm_ioplug_set_param_list(&k->io, SND_PCM_IOPLUG_HW_FORMAT, 1, format)) < 0
	    || (err = snd_pcm_ioplug_set_param_minmax(&k->io, SND_PCM_IOPLUG_HW_CHANNELS, 2, 2)) < 0
	    || (err = snd_pcm_ioplug_set_param_minmax(&k->io, SND_PCM_IOPLUG_HW_RATE, 48000, 48000)) < 0
	    || (err = snd_pcm_ioplug_set_param_minmax(&k->io, SND_PCM_IOPLUG_HW_PERIOD_BYTES, 256, 64 * 1024)) < 0
	    || (err = snd_pcm_ioplug_set_param_minmax(&k->io, SND_PCM_IOPLUG_HW_PERIODS, 2, 64)) < 0) {
		snd_pcm_ioplug_delete(&k->io);
		return err;
	}
	*pcmp = k->io.pcm;
	return 0;
}

SND_PCM_PLUGIN_SYMBOL(kryptik);
