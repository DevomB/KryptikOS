/* soundprobe: the sound suite's player and recorder, run in a zone through its default ALSA
 * device, which is the zone's plugin to zone 0's mixer (docs/design/laptop.md).
 *
 *   soundprobe tone HZ SECONDS    play a sine of HZ at half scale, both channels
 *   soundprobe record SECONDS     record, then say "recorded N frames, peak P"
 *   soundprobe switches CARD      in zone 0: each of card CARD's switches, "NAME playback on",
 *                                 "NAME capture off" and so on, a line each
 *
 * Exit: 0 done; 1 the device refused, with alsa-lib's words on stderr; 2 usage.
 */
#define _GNU_SOURCE
#include <alsa/asoundlib.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define RATE 48000
#define CHUNK 480

static int seconds_of(const char *s)
{
	char *end;
	long v = strtol(s, &end, 10);
	return *s && !*end && v > 0 && v <= 600 ? (int)v : -1;
}

static snd_pcm_t *open_default(snd_pcm_stream_t dir)
{
	snd_pcm_t *p;
	int err = snd_pcm_open(&p, "default", dir, 0);
	if (err < 0) {
		fprintf(stderr, "soundprobe: the default device: %s\n", snd_strerror(err));
		return NULL;
	}
	err = snd_pcm_set_params(p, SND_PCM_FORMAT_S16_LE, SND_PCM_ACCESS_RW_INTERLEAVED, 2, RATE, 1, 100000);
	if (err < 0) {
		fprintf(stderr, "soundprobe: 48 kHz s16le stereo: %s\n", snd_strerror(err));
		snd_pcm_close(p);
		return NULL;
	}
	return p;
}

static int tone(double hz, int secs)
{
	snd_pcm_t *p = open_default(SND_PCM_STREAM_PLAYBACK);
	if (!p)
		return 1;
	short buf[CHUNK * 2];
	long done = 0, total = (long)secs * RATE;
	while (done < total) {
		for (int i = 0; i < CHUNK; i++) {
			short v = (short)(16383.0 * sin(2.0 * M_PI * hz * (double)(done + i) / RATE));
			buf[2 * i] = buf[2 * i + 1] = v;
		}
		snd_pcm_sframes_t w = snd_pcm_writei(p, buf, CHUNK);
		if (w < 0 && (w = snd_pcm_recover(p, (int)w, 0)) < 0) {
			fprintf(stderr, "soundprobe: write: %s\n", snd_strerror((int)w));
			snd_pcm_close(p);
			return 1;
		}
		done += w > 0 ? w : 0;
	}
	snd_pcm_drain(p);
	snd_pcm_close(p);
	printf("played %d s of %g Hz\n", secs, hz);
	return 0;
}

static int record(int secs)
{
	snd_pcm_t *p = open_default(SND_PCM_STREAM_CAPTURE);
	if (!p)
		return 1;
	short buf[CHUNK * 2];
	long got = 0, total = (long)secs * RATE;
	int peak = 0;
	while (got < total) {
		snd_pcm_sframes_t r = snd_pcm_readi(p, buf, CHUNK);
		if (r < 0 && (r = snd_pcm_recover(p, (int)r, 0)) < 0) {
			fprintf(stderr, "soundprobe: read: %s\n", snd_strerror((int)r));
			snd_pcm_close(p);
			return 1;
		}
		for (long i = 0; i < r * 2; i++)
			if (abs(buf[i]) > peak)
				peak = abs(buf[i]);
		got += r > 0 ? r : 0;
	}
	snd_pcm_close(p);
	printf("recorded %ld frames, peak %d\n", got, peak);
	return 0;
}

static int switches(const char *card)
{
	char hw[24];
	snprintf(hw, sizeof hw, "hw:%s", card);
	snd_mixer_t *m;
	int err = snd_mixer_open(&m, 0);
	if (err == 0 && ((err = snd_mixer_attach(m, hw)) < 0 || (err = snd_mixer_selem_register(m, NULL, NULL)) < 0
	                 || (err = snd_mixer_load(m)) < 0))
		snd_mixer_close(m);
	if (err < 0) {
		fprintf(stderr, "%s: %s\n", hw, snd_strerror(err));
		return 1;
	}
	for (snd_mixer_elem_t *e = snd_mixer_first_elem(m); e; e = snd_mixer_elem_next(e)) {
		int v;
		if (snd_mixer_selem_has_playback_switch(e)
		    && snd_mixer_selem_get_playback_switch(e, SND_MIXER_SCHN_FRONT_LEFT, &v) == 0)
			printf("%s playback %s\n", snd_mixer_selem_get_name(e), v ? "on" : "off");
		if (snd_mixer_selem_has_capture_switch(e)
		    && snd_mixer_selem_get_capture_switch(e, SND_MIXER_SCHN_FRONT_LEFT, &v) == 0)
			printf("%s capture %s\n", snd_mixer_selem_get_name(e), v ? "on" : "off");
	}
	snd_mixer_close(m);
	return 0;
}

int main(int argc, char **argv)
{
	int secs;
	if (argc == 4 && !strcmp(argv[1], "tone") && atof(argv[2]) > 0 && (secs = seconds_of(argv[3])) > 0)
		return tone(atof(argv[2]), secs);
	if (argc == 3 && !strcmp(argv[1], "record") && (secs = seconds_of(argv[2])) > 0)
		return record(secs);
	if (argc == 3 && !strcmp(argv[1], "switches") && argv[2][0] && strlen(argv[2]) <= 2
	    && strspn(argv[2], "0123456789") == strlen(argv[2]))
		return switches(argv[2]);
	fputs("usage: soundprobe tone HZ SECONDS | soundprobe record SECONDS | soundprobe switches CARD\n", stderr);
	return 2;
}
