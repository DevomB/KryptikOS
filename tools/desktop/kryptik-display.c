/* kryptik-display: the session's monitors, their scale and their place (docs/design/laptop.md).
 *
 *   kryptik-display            each monitor: its name, scale, mode and place, make and model
 *   kryptik-display apply      the user's choices made once
 *   kryptik-display --watch    the same at the start and whenever a monitor comes, for as long
 *                              as the session lasts (the chrome runs it)
 *
 * The choices are lines of ~/.config/kryptik/display: NAME SCALE [X Y], NAME as listed or *
 * for any other monitor, SCALE from 0.5 to 4 and X Y where its top left corner goes. A monitor
 * no line names gets 2 if it is a built-in panel of 192 dpi or more and 1200 lines or more, as
 * GNOME gives it, and 1 otherwise: a television's EDID may give its aspect ratio as its size,
 * so only built-in panels are measured. A monitor is changed only when it is not as chosen,
 * and asked for the same thing once: what the compositor makes of it then stands.
 *
 * Through wlroots' output management, which dwl serves on its own socket alone: no zone's proxy
 * offers it. Exit: 0 listed, or made as chosen; 1 no display, or the compositor refused; 2 usage.
 */
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wayland-client.h>
#include "wlr-output-management-unstable-v1-client-protocol.h"

struct mode {
	struct wl_list link;
	struct zwlr_output_mode_v1 *wl;
	int32_t w, h, refresh;
};

struct head {
	struct wl_list link;
	struct zwlr_output_head_v1 *wl;
	char name[64], make[64], model[64];
	int32_t mm_w, mm_h, x, y;
	int enabled;
	double scale;
	struct wl_list modes;
	struct mode *current;
	/* What was last asked of it, so the same is never asked twice. */
	int asked, asked_place;
	double asked_scale;
	int32_t asked_x, asked_y;
};

struct rule {
	char name[64];
	double scale;
	int place;
	int32_t x, y;
};

static struct wl_display *display;
static struct zwlr_output_manager_v1 *manager;
static uint32_t manager_version, serial;
static struct wl_list heads;
static int done_seen, finished;
static enum { WAITING, SUCCEEDED, FAILED, CANCELLED } outcome;
static struct rule rules[32];
static int nrules;

static int same(double a, double b)
{
	return (a > b ? a - b : b - a) < 0.005;
}

static void copy(char *to, size_t size, const char *from)
{
	snprintf(to, size, "%s", from ? from : "");
}

static void mode_size(void *data, struct zwlr_output_mode_v1 *m, int32_t w, int32_t h)
{
	struct mode *mode = data;
	(void)m;
	mode->w = w;
	mode->h = h;
}

static void mode_refresh(void *data, struct zwlr_output_mode_v1 *m, int32_t refresh)
{
	struct mode *mode = data;
	(void)m;
	mode->refresh = refresh;
}

static void mode_preferred(void *data, struct zwlr_output_mode_v1 *m)
{
	(void)data; (void)m;
}

static void free_mode(struct mode *mode)
{
	wl_list_remove(&mode->link);
	if (wl_proxy_get_version((struct wl_proxy *)mode->wl) >= 3)
		zwlr_output_mode_v1_release(mode->wl);
	else
		zwlr_output_mode_v1_destroy(mode->wl);
	free(mode);
}

static void mode_finished(void *data, struct zwlr_output_mode_v1 *m)
{
	struct mode *mode = data;
	struct head *h;
	(void)m;
	wl_list_for_each(h, &heads, link)
		if (h->current == mode)
			h->current = NULL;
	free_mode(mode);
}

static const struct zwlr_output_mode_v1_listener mode_listener = {
	.size = mode_size,
	.refresh = mode_refresh,
	.preferred = mode_preferred,
	.finished = mode_finished,
};

static void head_name(void *data, struct zwlr_output_head_v1 *wl, const char *name)
{
	struct head *h = data;
	(void)wl;
	copy(h->name, sizeof h->name, name);
}

static void head_description(void *data, struct zwlr_output_head_v1 *wl, const char *description)
{
	(void)data; (void)wl; (void)description;
}

static void head_physical_size(void *data, struct zwlr_output_head_v1 *wl, int32_t w, int32_t h)
{
	struct head *head = data;
	(void)wl;
	head->mm_w = w;
	head->mm_h = h;
}

static void head_mode(void *data, struct zwlr_output_head_v1 *wl, struct zwlr_output_mode_v1 *m)
{
	struct head *h = data;
	struct mode *mode = calloc(1, sizeof *mode);
	(void)wl;
	if (!mode) {
		zwlr_output_mode_v1_destroy(m);
		return;
	}
	mode->wl = m;
	wl_list_insert(h->modes.prev, &mode->link);
	zwlr_output_mode_v1_add_listener(m, &mode_listener, mode);
}

static void head_enabled(void *data, struct zwlr_output_head_v1 *wl, int32_t enabled)
{
	struct head *h = data;
	(void)wl;
	h->enabled = enabled;
	if (!enabled)
		h->current = NULL;
}

static void head_current_mode(void *data, struct zwlr_output_head_v1 *wl, struct zwlr_output_mode_v1 *m)
{
	struct head *h = data;
	struct mode *mode;
	(void)wl;
	wl_list_for_each(mode, &h->modes, link)
		if (mode->wl == m)
			h->current = mode;
}

static void head_position(void *data, struct zwlr_output_head_v1 *wl, int32_t x, int32_t y)
{
	struct head *h = data;
	(void)wl;
	h->x = x;
	h->y = y;
}

static void head_transform(void *data, struct zwlr_output_head_v1 *wl, int32_t transform)
{
	(void)data; (void)wl; (void)transform;
}

static void head_scale(void *data, struct zwlr_output_head_v1 *wl, wl_fixed_t scale)
{
	struct head *h = data;
	(void)wl;
	h->scale = wl_fixed_to_double(scale);
}

static void head_finished(void *data, struct zwlr_output_head_v1 *wl)
{
	struct head *h = data;
	struct mode *mode, *next;
	(void)wl;
	wl_list_for_each_safe(mode, next, &h->modes, link)
		free_mode(mode);
	wl_list_remove(&h->link);
	if (wl_proxy_get_version((struct wl_proxy *)h->wl) >= 3)
		zwlr_output_head_v1_release(h->wl);
	else
		zwlr_output_head_v1_destroy(h->wl);
	free(h);
}

static void head_make(void *data, struct zwlr_output_head_v1 *wl, const char *make)
{
	struct head *h = data;
	(void)wl;
	copy(h->make, sizeof h->make, make);
}

static void head_model(void *data, struct zwlr_output_head_v1 *wl, const char *model)
{
	struct head *h = data;
	(void)wl;
	copy(h->model, sizeof h->model, model);
}

static void head_serial_number(void *data, struct zwlr_output_head_v1 *wl, const char *serial_number)
{
	(void)data; (void)wl; (void)serial_number;
}

static void head_adaptive_sync(void *data, struct zwlr_output_head_v1 *wl, uint32_t state)
{
	(void)data; (void)wl; (void)state;
}

static const struct zwlr_output_head_v1_listener head_listener = {
	.name = head_name,
	.description = head_description,
	.physical_size = head_physical_size,
	.mode = head_mode,
	.enabled = head_enabled,
	.current_mode = head_current_mode,
	.position = head_position,
	.transform = head_transform,
	.scale = head_scale,
	.finished = head_finished,
	.make = head_make,
	.model = head_model,
	.serial_number = head_serial_number,
	.adaptive_sync = head_adaptive_sync,
};

static void manager_head(void *data, struct zwlr_output_manager_v1 *m, struct zwlr_output_head_v1 *wl)
{
	struct head *h = calloc(1, sizeof *h);
	(void)data; (void)m;
	if (!h) {
		zwlr_output_head_v1_destroy(wl);
		return;
	}
	h->wl = wl;
	h->scale = 1;
	wl_list_init(&h->modes);
	wl_list_insert(heads.prev, &h->link);
	zwlr_output_head_v1_add_listener(wl, &head_listener, h);
}

static void manager_done(void *data, struct zwlr_output_manager_v1 *m, uint32_t s)
{
	(void)data; (void)m;
	serial = s;
	done_seen = 1;
}

static void manager_finished(void *data, struct zwlr_output_manager_v1 *m)
{
	(void)data; (void)m;
	finished = 1;
}

static const struct zwlr_output_manager_v1_listener manager_listener = {
	.head = manager_head,
	.done = manager_done,
	.finished = manager_finished,
};

static void config_succeeded(void *data, struct zwlr_output_configuration_v1 *c)
{
	(void)data; (void)c;
	outcome = SUCCEEDED;
}

static void config_failed(void *data, struct zwlr_output_configuration_v1 *c)
{
	(void)data; (void)c;
	outcome = FAILED;
}

static void config_cancelled(void *data, struct zwlr_output_configuration_v1 *c)
{
	(void)data; (void)c;
	outcome = CANCELLED;
}

static const struct zwlr_output_configuration_v1_listener config_listener = {
	.succeeded = config_succeeded,
	.failed = config_failed,
	.cancelled = config_cancelled,
};

static void registry_global(void *data, struct wl_registry *r, uint32_t name, const char *iface, uint32_t version)
{
	(void)data;
	if (!strcmp(iface, zwlr_output_manager_v1_interface.name) && !manager) {
		manager_version = version < 4 ? version : 4;
		manager = wl_registry_bind(r, name, &zwlr_output_manager_v1_interface, manager_version);
		zwlr_output_manager_v1_add_listener(manager, &manager_listener, NULL);
	}
}

static void registry_global_remove(void *data, struct wl_registry *r, uint32_t name)
{
	(void)data; (void)r; (void)name;
}

static const struct wl_registry_listener registry_listener = {
	.global = registry_global,
	.global_remove = registry_global_remove,
};

/* The user's lines, read again each time: one that does not parse is said once and skipped. */
static void read_rules(int quiet)
{
	char path[512], line[256];
	const char *conf = getenv("XDG_CONFIG_HOME"), *home = getenv("HOME");
	FILE *f;
	nrules = 0;
	if (conf && conf[0] == '/')
		snprintf(path, sizeof path, "%s/kryptik/display", conf);
	else if (home && home[0] == '/')
		snprintf(path, sizeof path, "%s/.config/kryptik/display", home);
	else
		return;
	if (!(f = fopen(path, "re")))
		return;
	while (fgets(line, sizeof line, f) && nrules < (int)(sizeof rules / sizeof rules[0])) {
		struct rule *r = &rules[nrules];
		char *p = line + strspn(line, " \t");
		int n;
		if (*p == '#' || *p == '\n' || !*p)
			continue;
		n = sscanf(p, "%63s %lf %d %d", r->name, &r->scale, &r->x, &r->y);
		if (n < 2 || n == 3 || !(r->scale >= 0.5 && r->scale <= 4)) {
			if (!quiet)
				fprintf(stderr, "kryptik-display: %s: not NAME SCALE [X Y], SCALE from 0.5 to 4: %s", path, p);
			continue;
		}
		r->place = n == 4 && strcmp(r->name, "*") != 0;
		nrules++;
	}
	fclose(f);
}

static int builtin(const char *name)
{
	return !strncmp(name, "eDP", 3) || !strncmp(name, "LVDS", 4) || !strncmp(name, "DSI", 3);
}

/* The scale and place chosen for a monitor: its line, else the line for *, else the default. */
static void wanted(const struct head *h, double *scale, int *place, int32_t *x, int32_t *y)
{
	const struct rule *any = NULL;
	*place = 0;
	for (int i = 0; i < nrules; i++) {
		if (!strcmp(rules[i].name, h->name)) {
			*scale = rules[i].scale;
			*place = rules[i].place;
			*x = rules[i].x;
			*y = rules[i].y;
			return;
		}
		if (!strcmp(rules[i].name, "*"))
			any = &rules[i];
	}
	if (any) {
		*scale = any->scale;
		return;
	}
	*scale = 1;
	if (builtin(h->name) && h->current && h->mm_w > 0 && h->current->w * 25.4 / h->mm_w >= 192
			&& h->current->h >= 1200)
		*scale = 2;
}

/* An enabled monitor not as chosen, whose choice has not been asked for already. */
static int to_change(const struct head *h)
{
	double s;
	int place;
	int32_t x = 0, y = 0;
	if (!h->enabled)
		return 0;
	wanted(h, &s, &place, &x, &y);
	if (same(h->scale, s) && (!place || (h->x == x && h->y == y)))
		return 0;
	return !h->asked || !same(h->asked_scale, s) || h->asked_place != place
		|| (place && (h->asked_x != x || h->asked_y != y));
}

/* One configuration with every monitor in it, as the protocol requires: each enabled one at its
 * chosen scale and, when its line gives one, place; each disabled one left so. 0 made, or
 * nothing to make; 1 refused; -1 cancelled by a monitor that came or went, to ask again. */
static int apply(void)
{
	struct zwlr_output_configuration_v1 *c;
	struct head *h;
	int changing = 0;
	wl_list_for_each(h, &heads, link)
		changing |= to_change(h);
	if (!changing)
		return 0;
	c = zwlr_output_manager_v1_create_configuration(manager, serial);
	zwlr_output_configuration_v1_add_listener(c, &config_listener, NULL);
	wl_list_for_each(h, &heads, link) {
		struct zwlr_output_configuration_head_v1 *ch;
		double s;
		int place;
		int32_t x = 0, y = 0;
		if (!h->enabled) {
			zwlr_output_configuration_v1_disable_head(c, h->wl);
			continue;
		}
		wanted(h, &s, &place, &x, &y);
		ch = zwlr_output_configuration_v1_enable_head(c, h->wl);
		zwlr_output_configuration_head_v1_set_scale(ch, wl_fixed_from_double(s));
		if (place)
			zwlr_output_configuration_head_v1_set_position(ch, x, y);
		/* The client's side of it alone: the compositor's goes with the configuration. */
		zwlr_output_configuration_head_v1_destroy(ch);
		if (!same(h->scale, s) || (place && (h->x != x || h->y != y)))
			fprintf(stderr, "kryptik-display: %s at scale %g%s\n", h->name, s, place ? ", placed as chosen" : "");
		h->asked = 1;
		h->asked_scale = s;
		h->asked_place = place;
		h->asked_x = x;
		h->asked_y = y;
	}
	outcome = WAITING;
	zwlr_output_configuration_v1_apply(c);
	while (outcome == WAITING && wl_display_dispatch(display) != -1)
		;
	zwlr_output_configuration_v1_destroy(c);
	if (outcome == FAILED)
		fprintf(stderr, "kryptik-display: the compositor refused the monitors' configuration\n");
	if (outcome == CANCELLED)
		wl_list_for_each(h, &heads, link)
			h->asked = 0;
	return outcome == SUCCEEDED ? 0 : outcome == CANCELLED ? -1 : 1;
}

static void list(void)
{
	struct head *h;
	wl_list_for_each(h, &heads, link) {
		printf("%s", h->name);
		if (!h->enabled)
			printf("  off");
		else if (h->current)
			printf("  scale %g  %dx%d@%d  at %d,%d", h->scale, h->current->w, h->current->h,
				(h->current->refresh + 500) / 1000, h->x, h->y);
		else
			printf("  scale %g  at %d,%d", h->scale, h->x, h->y);
		if (h->make[0] || h->model[0])
			printf("  %s%s%s", h->make, h->make[0] && h->model[0] ? " " : "", h->model);
		if (h->mm_w > 0 && h->mm_h > 0)
			printf(", %dx%d mm", h->mm_w, h->mm_h);
		printf("\n");
	}
}

int main(int argc, char **argv)
{
	int watch = argc == 2 && !strcmp(argv[1], "--watch"), once = argc == 2 && !strcmp(argv[1], "apply");
	struct wl_registry *registry;
	if (argc > 2 || (argc == 2 && !watch && !once)) {
		fputs("usage: kryptik-display [apply | --watch]\n"
		      "       (lists the session's monitors; apply makes the choices in\n"
		      "       ~/.config/kryptik/display, NAME SCALE [X Y] a line, * for any other\n"
		      "       monitor; --watch does so again whenever a monitor comes)\n", stderr);
		return 2;
	}
	if (!(display = wl_display_connect(NULL))) {
		fputs("kryptik-display: no Wayland display: run it in the session\n", stderr);
		return 1;
	}
	wl_list_init(&heads);
	registry = wl_display_get_registry(display);
	wl_registry_add_listener(registry, &registry_listener, NULL);
	wl_display_roundtrip(display);
	if (!manager) {
		fputs("kryptik-display: the compositor offers no output management\n", stderr);
		return 1;
	}
	/* The heads, their modes and the first done come together. */
	while (!done_seen && !finished && wl_display_dispatch(display) != -1)
		;
	if (!done_seen)
		return 1;
	if (!watch && !once) {
		list();
		return 0;
	}
	read_rules(0);
	for (;;) {
		/* The done that brought this look is spent before applying, so one that comes while
		 * the compositor answers is seen below. */
		done_seen = 0;
		int r = apply();
		if (once && r >= 0)
			return r;
		/* Watching, or cancelled: the next done, then the choices, read again, once more. */
		while (!done_seen && !finished && wl_display_dispatch(display) != -1)
			;
		if (!done_seen)
			return once ? 1 : 0;
		read_rules(1);
	}
}
