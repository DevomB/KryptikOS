/* kryptik-efiboot: the firmware-side half of the A/B trial
 * (docs/design/boot-and-updates.md).
 *
 * Writes and reads the UEFI Boot#### / BootNext / BootOrder variables through
 * efivarfs, with no library: the whole of what is needed is one load option
 * pointing at a file on the ESP, and a one-shot BootNext naming it.
 *
 *   kryptik-efiboot list                 print Boot####, BootOrder, BootNext, BootCurrent
 *   kryptik-efiboot set-next SLOT        create/refresh "Kryptik SLOT" -> \EFI\kryptik\kryptik-SLOT.efi, set BootNext
 *   kryptik-efiboot clear-next           delete BootNext
 *   kryptik-efiboot ensure SLOT          create/refresh the entry only (no BootNext)
 *   kryptik-efiboot forget               delete both slots' entries and BootNext, drop them
 *                                        from BootOrder: the firmware boots BOOTX64.EFI
 *
 * The ESP is the partition labelled kryptik-esp ON THE DISK THE ROOT CAME
 * FROM, resolved by /usr/libexec/kryptik/devices.sh (a label alone is not an
 * identity; a second disk with the same layout must be ignored, and two
 * candidates on the root disk are refused). The HD() device path node is
 * built from the partition's GPT UUID, start and size read from sysfs and
 * blkid, which is everything a firmware needs to match it.
 *
 * Entry numbers: Kryptik owns Boot00A0 for slot a and Boot00B0 for slot b.
 * Fixed numbers, so a repeated arming updates the same variable rather than
 * accumulating entries, and so `list` can show them by slot.
 */
#define _GNU_SOURCE
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

/* Overridable at compile time for tools/test-efiboot.sh, which builds this
 * against a scratch directory of stand-in variables; the installed binary
 * is built with the default. */
#ifndef EFIVARS
#define EFIVARS "/sys/firmware/efi/efivars/"
#endif
#define GLOBAL_GUID "8be4df61-93ca-11d2-aa0d-00e098032b8c"
#define EFI_VARIABLE_NON_VOLATILE 0x1
#define EFI_VARIABLE_BOOTSERVICE_ACCESS 0x2
#define EFI_VARIABLE_RUNTIME_ACCESS 0x4
#define LOAD_OPTION_ACTIVE 0x1

static int die(const char *m) { fprintf(stderr, "kryptik-efiboot: %s%s%s\n", m, errno ? ": " : "", errno ? strerror(errno) : ""); return 1; }

static int read_var(const char *name, unsigned char *buf, size_t cap, size_t *len) {
    char path[512]; snprintf(path, sizeof path, EFIVARS "%s-" GLOBAL_GUID, name);
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    ssize_t n = read(fd, buf, cap);
    close(fd);
    if (n < 4) return -1;
    memmove(buf, buf + 4, (size_t)n - 4);   /* skip the 4-byte attributes header */
    *len = (size_t)n - 4;
    return 0;
}

/* efivarfs write: attributes (u32 LE) followed by the data, in one write. A
 * variable that exists is immutable-flagged by the kernel; clear that first. */
static int write_var(const char *name, const unsigned char *data, size_t len) {
    char path[512]; snprintf(path, sizeof path, EFIVARS "%s-" GLOBAL_GUID, name);
    unsigned char *buf = malloc(len + 4);
    if (!buf) return -1;
    uint32_t attr = EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS;
    memcpy(buf, &attr, 4); memcpy(buf + 4, data, len);
    /* remove the immutable attribute if present (FS_IOC_SETFLAGS) */
    int fd = open(path, O_RDONLY);
    if (fd >= 0) {
        int flags = 0;
        if (ioctl(fd, _IOR('f', 1, long), &flags) == 0 && (flags & 0x10)) {
            flags &= ~0x10; ioctl(fd, _IOW('f', 2, long), &flags);
        }
        close(fd);
    }
    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) { free(buf); return -1; }
    ssize_t n = write(fd, buf, len + 4);
    close(fd); free(buf);
    return n == (ssize_t)(len + 4) ? 0 : -1;
}

static int delete_var(const char *name) {
    char path[512]; snprintf(path, sizeof path, EFIVARS "%s-" GLOBAL_GUID, name);
    int fd = open(path, O_RDONLY);
    if (fd >= 0) { int flags = 0; if (ioctl(fd, _IOR('f', 1, long), &flags) == 0 && (flags & 0x10)) { flags &= ~0x10; ioctl(fd, _IOW('f', 2, long), &flags); } close(fd); }
    return unlink(path) == 0 || errno == ENOENT ? 0 : -1;
}

/* --- the ESP partition, by label ------------------------------------------ */
struct part { char dev[128]; char uuid[40]; uint64_t start, size; uint32_t number; };

static int run_read(const char *cmd, char *out, size_t cap) {
    FILE *p = popen(cmd, "r"); if (!p) return -1;
    if (!fgets(out, (int)cap, p)) { pclose(p); return -1; }
    pclose(p);
    out[strcspn(out, "\n")] = 0;
    return 0;
}

static int find_esp(struct part *p) {
    char dev[128];
    if (run_read("/usr/libexec/kryptik/devices.sh part kryptik-esp 2>/dev/null", dev, sizeof dev) || !dev[0]) return -1;
    snprintf(p->dev, sizeof p->dev, "%s", dev);
    char cmd[256], out[128];
    snprintf(cmd, sizeof cmd, "blkid -s PARTUUID -o value %s 2>/dev/null", dev);
    if (run_read(cmd, out, sizeof out) || strlen(out) != 36) return -1;
    snprintf(p->uuid, sizeof p->uuid, "%s", out);
    const char *base = strrchr(dev, '/'); base = base ? base + 1 : dev;
    char path[256];
    snprintf(path, sizeof path, "/sys/class/block/%s/start", base);
    FILE *f = fopen(path, "r"); if (!f) return -1; if (fscanf(f, "%" SCNu64, &p->start) != 1) { fclose(f); return -1; } fclose(f);
    snprintf(path, sizeof path, "/sys/class/block/%s/size", base);
    f = fopen(path, "r"); if (!f) return -1; if (fscanf(f, "%" SCNu64, &p->size) != 1) { fclose(f); return -1; } fclose(f);
    snprintf(path, sizeof path, "/sys/class/block/%s/partition", base);
    f = fopen(path, "r"); if (!f) return -1; if (fscanf(f, "%" SCNu32, &p->number) != 1) { fclose(f); return -1; } fclose(f);
    return 0;
}

/* GPT partition UUID text -> the 16-byte mixed-endian form firmware uses */
static int uuid_to_bytes(const char *s, unsigned char out[16]) {
    unsigned int b[16]; int n = sscanf(s,
        "%2x%2x%2x%2x-%2x%2x-%2x%2x-%2x%2x-%2x%2x%2x%2x%2x%2x",
        &b[0],&b[1],&b[2],&b[3],&b[4],&b[5],&b[6],&b[7],&b[8],&b[9],&b[10],&b[11],&b[12],&b[13],&b[14],&b[15]);
    if (n != 16) return -1;
    /* first three groups little-endian */
    out[0]=b[3]; out[1]=b[2]; out[2]=b[1]; out[3]=b[0];
    out[4]=b[5]; out[5]=b[4]; out[6]=b[7]; out[7]=b[6];
    for (int i = 8; i < 16; i++) out[i] = b[i];
    return 0;
}

static size_t put_u16(unsigned char *p, uint16_t v) { p[0] = v & 0xff; p[1] = v >> 8; return 2; }
static size_t put_u32(unsigned char *p, uint32_t v) { for (int i = 0; i < 4; i++) p[i] = (v >> (8*i)) & 0xff; return 4; }
static size_t put_u64(unsigned char *p, uint64_t v) { for (int i = 0; i < 8; i++) p[i] = (v >> (8*i)) & 0xff; return 8; }
static size_t put_ucs2(unsigned char *p, const char *s) { size_t n = 0; for (; *s; s++) n += put_u16(p + n, (unsigned char)*s); n += put_u16(p + n, 0); return n; }

/* EFI_LOAD_OPTION: attributes, FilePathListLength, Description, FilePathList, OptionalData(none) */
static size_t build_load_option(unsigned char *buf, const struct part *esp, const char *desc, const char *file) {
    unsigned char dp[512]; size_t d = 0;
    /* HD(part, GPT, sig, start, size): type 4 (media), subtype 1, length 42 */
    dp[d++] = 0x04; dp[d++] = 0x01; d += put_u16(dp + d, 42);
    d += put_u32(dp + d, esp->number);
    d += put_u64(dp + d, esp->start);
    d += put_u64(dp + d, esp->size);
    unsigned char sig[16]; if (uuid_to_bytes(esp->uuid, sig)) return 0;
    memcpy(dp + d, sig, 16); d += 16;
    dp[d++] = 0x02;   /* MBR type: GPT */
    dp[d++] = 0x02;   /* signature type: GUID */
    /* File path: type 4 subtype 4, length = 4 + ucs2 */
    size_t flen = 4 + (strlen(file) + 1) * 2;
    dp[d++] = 0x04; dp[d++] = 0x04; d += put_u16(dp + d, (uint16_t)flen);
    d += put_ucs2(dp + d, file);
    /* end of device path */
    dp[d++] = 0x7f; dp[d++] = 0xff; d += put_u16(dp + d, 4);

    size_t n = 0;
    n += put_u32(buf + n, LOAD_OPTION_ACTIVE);
    n += put_u16(buf + n, (uint16_t)d);
    n += put_ucs2(buf + n, desc);
    memcpy(buf + n, dp, d); n += d;
    return n;
}

static int slot_num(const char *slot, char out[9]) {
    if (!strcmp(slot, "a")) { strcpy(out, "Boot00A0"); return 0; }
    if (!strcmp(slot, "b")) { strcpy(out, "Boot00B0"); return 0; }
    return -1;
}

static int ensure_entry(const char *slot) {
    char var[9]; if (slot_num(slot, var)) return die("slot must be a or b");
    struct part esp; errno = 0;
    if (find_esp(&esp)) return die("no unambiguous kryptik-esp partition on this installation's disk (devices.sh)");
    char desc[64], file[64];
    snprintf(desc, sizeof desc, "Kryptik slot %s", slot);
    snprintf(file, sizeof file, "\\EFI\\kryptik\\kryptik-%s.efi", slot);
    unsigned char buf[1024]; size_t n = build_load_option(buf, &esp, desc, file);
    if (!n) return die("could not build the load option");
    unsigned char old[1024]; size_t olen = 0;
    if (read_var(var, old, sizeof old, &olen) == 0 && olen == n && !memcmp(old, buf, n)) {
        printf("%s already points at %s\n", var, file);
    } else {
        if (write_var(var, buf, n)) return die("writing the Boot#### entry failed");
        printf("%s -> %s on %s (PARTUUID %s)\n", var, file, esp.dev, esp.uuid);
    }
    /* keep it in BootOrder (appended) so a firmware that ignores BootNext
       still offers it, without displacing the entry the machine came with;
       forget takes it out again at commit */
    unsigned char order[512]; size_t ol = 0; uint16_t num = (uint16_t)strtol(var + 4, NULL, 16);
    int present = 0;
    if (read_var("BootOrder", order, sizeof order, &ol) == 0) {
        for (size_t i = 0; i + 1 < ol; i += 2) if ((order[i] | (order[i+1] << 8)) == num) present = 1;
    } else ol = 0;
    if (!present && ol + 2 <= sizeof order) { ol += put_u16(order + ol, num); if (write_var("BootOrder", order, ol)) return die("updating BootOrder failed"); }
    return 0;
}

static int cmd_set_next(const char *slot) {
    if (ensure_entry(slot)) return 1;
    char var[9]; slot_num(slot, var);
    unsigned char v[2]; put_u16(v, (uint16_t)strtol(var + 4, NULL, 16));
    if (write_var("BootNext", v, 2)) return die("writing BootNext failed");
    printf("BootNext = %s (one boot)\n", var);
    return 0;
}

/* forget: both slots' entries and BootNext are deleted and BootOrder no
 * longer names them; the machine's other entries keep their order. The
 * firmware then boots the disk's own entry, which is BOOTX64.EFI, the
 * committed slot. boot-success runs this at commit and the recovery tool
 * after its commit: the entries exist for the trial alone. Left behind,
 * they outlived it. A firmware regenerates its own disk entry at the end
 * of BootOrder whenever the devices change, and the first Kryptik entry
 * ever armed then won over the committed slot at every cold boot after
 * that: the update suite committed slot a and the next boot was slot b. */
static int cmd_forget(void) {
    unsigned char order[512], kept[512]; size_t ol = 0, kl = 0;
    if (read_var("BootOrder", order, sizeof order, &ol)) ol = 0;
    for (size_t i = 0; i + 1 < ol; i += 2) {
        uint16_t e = (uint16_t)(order[i] | (order[i+1] << 8));
        if (e != 0x00A0 && e != 0x00B0) kl += put_u16(kept + kl, e);
    }
    if (kl != ol) {
        if (kl == 0 ? delete_var("BootOrder") : write_var("BootOrder", kept, kl)) return die("updating BootOrder failed");
    }
    if (delete_var("Boot00A0") || delete_var("Boot00B0")) return die("deleting a Boot#### entry failed");
    if (delete_var("BootNext")) return die("deleting BootNext failed");
    printf("forgotten: Kryptik's entries and BootNext; the firmware boots BOOTX64.EFI\n");
    return 0;
}

static void print_entry(const char *var) {
    unsigned char buf[2048]; size_t n = 0;
    if (read_var(var, buf, sizeof buf, &n) || n < 6) return;
    uint16_t fpl = buf[4] | (buf[5] << 8);
    printf("  %s: ", var);
    size_t i = 6;
    while (i + 1 < n) { uint16_t c = buf[i] | (buf[i+1] << 8); i += 2; if (!c) break; putchar(c < 128 && isprint(c) ? c : '?'); }
    /* file path node(s) */
    size_t end = i + fpl; int shown = 0;
    while (i + 4 <= end && i + 4 <= n) {
        unsigned t = buf[i], st = buf[i+1]; uint16_t l = buf[i+2] | (buf[i+3] << 8);
        if (l < 4) break;
        if (t == 4 && st == 4) { printf("  file="); for (size_t k = i + 4; k + 1 < i + l; k += 2) { uint16_t c = buf[k] | (buf[k+1] << 8); if (!c) break; putchar(c < 128 && isprint(c) ? c : '?'); } shown = 1; }
        if (t == 0x7f) break;
        i += l;
    }
    if (!shown) printf("  (no file path)");
    printf("  [%s]\n", (buf[0] & LOAD_OPTION_ACTIVE) ? "active" : "inactive");
}

static int cmd_list(void) {
    unsigned char buf[512]; size_t n = 0;
    if (read_var("BootCurrent", buf, sizeof buf, &n) == 0 && n >= 2) printf("BootCurrent: Boot%04X\n", buf[0] | (buf[1] << 8));
    if (read_var("BootNext", buf, sizeof buf, &n) == 0 && n >= 2) printf("BootNext:    Boot%04X\n", buf[0] | (buf[1] << 8)); else printf("BootNext:    (none)\n");
    if (read_var("BootOrder", buf, sizeof buf, &n) == 0) { printf("BootOrder:  "); for (size_t i = 0; i + 1 < n; i += 2) printf(" Boot%04X", buf[i] | (buf[i+1] << 8)); printf("\n"); }
    DIR *d = opendir(EFIVARS); if (!d) return die("efivarfs is not mounted");
    struct dirent *e; char names[64][9]; int cnt = 0;
    while ((e = readdir(d)) && cnt < 64) if (!strncmp(e->d_name, "Boot", 4) && strlen(e->d_name) > 8 && isxdigit(e->d_name[4]) && isxdigit(e->d_name[7]) && !strcmp(e->d_name + 8, "-" GLOBAL_GUID)) { memcpy(names[cnt], e->d_name, 8); names[cnt][8] = 0; cnt++; }
    closedir(d);
    for (int i = 0; i < cnt; i++) print_entry(names[i]);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: kryptik-efiboot list | set-next a|b | clear-next | ensure a|b | forget\n"); return 2; }
    if (access(EFIVARS, R_OK)) { errno = 0; return die("no efivarfs at " EFIVARS " (not a UEFI boot, or sysinit did not mount it)"); }
    if (!strcmp(argv[1], "list")) return cmd_list();
    if (!strcmp(argv[1], "set-next") && argc == 3) return cmd_set_next(argv[2]);
    if (!strcmp(argv[1], "ensure") && argc == 3) return ensure_entry(argv[2]);
    if (!strcmp(argv[1], "forget")) return cmd_forget();
    if (!strcmp(argv[1], "clear-next")) { if (delete_var("BootNext")) return die("deleting BootNext failed"); printf("BootNext cleared\n"); return 0; }
    fprintf(stderr, "kryptik-efiboot: unknown command\n"); return 2;
}
