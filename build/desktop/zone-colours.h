/* Kryptik zone colours: the one table both the compositor (dwl config.h)
 * and the trusted chrome draw from, so a window border and the bar agree.
 *
 * X(zone, border, focused-border) - 0xRRGGBBAA. A window whose app_id has
 * no `kryptik.<zone>.` prefix did not come through a zone proxy and is
 * drawn with UNZONED; a prefix naming a zone not listed here gets UNKNOWN,
 * which is deliberately the loudest colour on the table.
 */
#ifndef KRYPTIK_ZONE_COLOURS_H
#define KRYPTIK_ZONE_COLOURS_H

#define KRYPTIK_ZONE_COLOURS(X) \
	X("work",      0x2f6fb3ff, 0x63a7f0ff) \
	X("personal",  0x2f8f4eff, 0x5fd382ff) \
	X("dev",       0xb8772aff, 0xf0ad55ff) \
	X("untrusted", 0xb3302fff, 0xf05a58ff) \
	X("vault",     0x6f3fb3ff, 0xa97ef0ff) \
	X("net",       0x5a5a5aff, 0x9a9a9aff)

#define KRYPTIK_UNZONED_BORDER  0xd8d8d8ff
#define KRYPTIK_UNZONED_FOCUS   0xffffffff
#define KRYPTIK_UNKNOWN_BORDER  0xff00c8ff
#define KRYPTIK_UNKNOWN_FOCUS   0xff66e0ff

#endif
