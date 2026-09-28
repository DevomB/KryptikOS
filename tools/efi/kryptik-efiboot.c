/* kryptik-efiboot: the firmware side of the A/B trial
 * (docs/design/boot-and-updates.md). Reads and writes Boot####, BootNext and
 * BootOrder through efivarfs, with no library.
 *
 *   kryptik-efiboot list                 print Boot####, BootOrder, BootNext, BootCurrent
 *   kryptik-efiboot set-next SLOT        create/refresh "Kryptik slot SLOT" -> \EFI\kryptik\kryptik-SLOT.efi, set BootNext
 *   kryptik-efiboot clear-next           delete BootNext
 *   kryptik-efiboot ensure SLOT [ESP]    create/refresh the entry only (no BootNext); ESP names
 *                                        the partition when it is not this installation's
 *   kryptik-efiboot forget               delete Kryptik's entries, and BootNext if it names one,
 *                                        drop them from BootOrder: the firmware boots BOOTX64.EFI
 *
 * The ESP is kryptik-esp on the root's own disk, as devices.sh resolves it: a
 * second disk's is ignored, two on the root disk are refused. An entry is
 * Kryptik's when its description and its file say so, never by its number:
 * slot a's is Boot00A0 and slot b's Boot00B0 unless another system already
 * uses that number, and then the next free one. Re-arming reuses the entry.
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
#include <sys/wait.h>
#include <unistd.h>

/* tools/tests/efiboot.sh overrides these with stand-ins. */
#ifndef EFIVARS
#define EFIVARS "/sys/firmware/efi/efivars/"
#endif
#ifndef SYSBLOCK
#define SYSBLOCK "/sys/class/block/"
#endif
#ifndef DEVICES
#define DEVICES "/usr/libexec/kryptik/devices.sh"
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

static int var_exists(const char *name) {
    char path[512]; snprintf(path, sizeof path, EFIVARS "%s-" GLOBAL_GUID, name);
    return access(path, F_OK) == 0;
}

/* --- the ESP partition, by label ------------------------------------------ */
struct part { char dev[128]; char uuid[40]; uint64_t start, size; uint32_t number; };

/* The first line a program prints. No shell: the arguments are an array, so
 * nothing in them is ever parsed as a command. */
static int run_read(char *const argv[], char *out, size_t cap) {
    int fd[2];
    if (pipe(fd)) return -1;
    pid_t pid = fork();
    if (pid < 0) { close(fd[0]); close(fd[1]); return -1; }
    if (pid == 0) {
        int nul = open("/dev/null", O_WRONLY);
        dup2(fd[1], 1);
        if (nul >= 0) dup2(nul, 2);
        close(fd[0]); close(fd[1]);
        execvp(argv[0], argv);
        _exit(127);
    }
    close(fd[1]);
    FILE *p = fdopen(fd[0], "r");
    int got = p && fgets(out, (int)cap, p) != NULL;
    if (p) fclose(p); else close(fd[0]);
    int st;
    while (waitpid(pid, &st, 0) < 0 && errno == EINTR) {}
    if (!got) return -1;
    out[strcspn(out, "\n")] = 0;
    return 0;
}

/* NAMED, which must carry the kryptik-esp label (kryptik-recover names an
 * installed disk's from a medium), or else the one devices.sh finds. */
static int find_esp(struct part *p, const char *named) {
    char dev[128];
    if (named) {
        char label[64];
        char *lbl[] = { "blkid", "-s", "PARTLABEL", "-o", "value", (char *)named, NULL };
        if (strlen(named) >= sizeof dev || run_read(lbl, label, sizeof label) || strcmp(label, "kryptik-esp")) return -1;
        snprintf(dev, sizeof dev, "%s", named);
    } else {
        char *find[] = { DEVICES, "part", "kryptik-esp", NULL };
        if (run_read(find, dev, sizeof dev) || !dev[0]) return -1;
    }
    snprintf(p->dev, sizeof p->dev, "%s", dev);
    char out[128];
    char *uuid[] = { "blkid", "-s", "PARTUUID", "-o", "value", dev, NULL };
    if (run_read(uuid, out, sizeof out) || strlen(out) != 36) return -1;
    snprintf(p->uuid, sizeof p->uuid, "%.36s", out);
    const char *base = strrchr(dev, '/'); base = base ? base + 1 : dev;
    char path[512];
    snprintf(path, sizeof path, SYSBLOCK "%s/start", base);
    FILE *f = fopen(path, "r"); if (!f) return -1; if (fscanf(f, "%" SCNu64, &p->start) != 1) { fclose(f); return -1; } fclose(f);
    snprintf(path, sizeof path, SYSBLOCK "%s/size", base);
    f = fopen(path, "r"); if (!f) return -1; if (fscanf(f, "%" SCNu64, &p->size) != 1) { fclose(f); return -1; } fclose(f);
    snprintf(path, sizeof path, SYSBLOCK "%s/partition", base);
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

/* --- Kryptik's entries ----------------------------------------------------- */

/* A load option's description and the file its path names, in ASCII ('?' for
 * anything else); -1 if VAR is not there or is too short to be one. */
static int option_text(const char *var, char *desc, size_t dcap, char *file, size_t fcap, int *active) {
    unsigned char buf[2048]; size_t n = 0, d = 0, f = 0;
    if (read_var(var, buf, sizeof buf, &n) || n < 6) return -1;
    size_t i = 6;
    while (i + 1 < n) { uint16_t c = buf[i] | (buf[i+1] << 8); i += 2; if (!c) break; if (d + 1 < dcap) desc[d++] = c < 128 && isprint(c) ? (char)c : '?'; }
    desc[d] = 0;
    /* file path node(s): the first names the file */
    size_t end = i + (size_t)(buf[4] | (buf[5] << 8));
    while (i + 4 <= end && i + 4 <= n) {
        unsigned t = buf[i], st = buf[i+1]; size_t l = (size_t)(buf[i+2] | (buf[i+3] << 8));
        if (l < 4) break;
        if (t == 4 && st == 4 && !f)
            for (size_t k = i + 4; k + 1 < i + l && k + 1 < n; k += 2) { uint16_t c = buf[k] | (buf[k+1] << 8); if (!c) break; if (f + 1 < fcap) file[f++] = c < 128 && isprint(c) ? (char)c : '?'; }
        if (t == 0x7f) break;
        i += l;
    }
    file[f] = 0;
    if (active) *active = buf[0] & LOAD_OPTION_ACTIVE;
    return 0;
}

/* Is VAR Kryptik's entry for SLOT ("a" or "b", NULL for either)? Its
 * description and its file must both say so: another system may use any
 * number, Boot00A0 and Boot00B0 among them. */
static int is_ours(const char *var, const char *slot) {
    char desc[128], file[256];
    if (option_text(var, desc, sizeof desc, file, sizeof file, NULL)) return 0;
    for (const char *s = "ab"; *s; s++) {
        char want_desc[32], want_file[48];
        if (slot && *slot != *s) continue;
        snprintf(want_desc, sizeof want_desc, "Kryptik slot %c", *s);
        snprintf(want_file, sizeof want_file, "\\EFI\\kryptik\\kryptik-%c.efi", *s);
        if (!strcmp(desc, want_desc) && !strcmp(file, want_file)) return 1;
    }
    return 0;
}

/* The Boot#### variables there are, by name: at most CAP, -1 without efivarfs. */
static int boot_vars(char names[][9], int cap) {
    DIR *d = opendir(EFIVARS); if (!d) return -1;
    struct dirent *e; int cnt = 0;
    while ((e = readdir(d)) && cnt < cap) {
        const char *n = e->d_name;
        if (strlen(n) != 8 + strlen("-" GLOBAL_GUID) || strncmp(n, "Boot", 4) || strcmp(n + 8, "-" GLOBAL_GUID)) continue;
        if (!isxdigit((unsigned char)n[4]) || !isxdigit((unsigned char)n[5]) || !isxdigit((unsigned char)n[6]) || !isxdigit((unsigned char)n[7])) continue;
        memcpy(names[cnt], n, 8); names[cnt][8] = 0; cnt++;
    }
    closedir(d);
    return cnt;
}

/* Does LIST, little-endian u16s as BootOrder holds them, hold NUM? */
static int holds(const unsigned char *list, size_t len, uint16_t num) {
    for (size_t i = 0; i + 1 < len; i += 2) if ((list[i] | (list[i+1] << 8)) == num) return 1;
    return 0;
}

/* Where SLOT's entry goes: where Kryptik's entry for it already is, its own
 * number first; else its own number if that is free; else the next number
 * that no variable and no place in BootOrder uses. */
static int slot_var(const char *slot, char var[9]) {
    unsigned own = !strcmp(slot, "a") ? 0x00A0 : 0x00B0;
    snprintf(var, 9, "Boot%04X", own);
    if (is_ours(var, slot)) return 0;
    char names[256][9]; int cnt = boot_vars(names, 256);
    for (int i = 0; i < cnt; i++) if (is_ours(names[i], slot)) { memcpy(var, names[i], 9); return 0; }
    unsigned char order[512]; size_t ol = 0;
    if (read_var("BootOrder", order, sizeof order, &ol)) ol = 0;
    for (unsigned k = 0; k < 0x10000; k++) {
        uint16_t num = (uint16_t)(own + k);
        snprintf(var, 9, "Boot%04X", (unsigned)num);
        if (!var_exists(var) && (k == 0 || !holds(order, ol, num))) return 0;
    }
    return -1;
}

static int ensure_entry(const char *slot, const char *named, char var[9]) {
    if (strcmp(slot, "a") && strcmp(slot, "b")) { errno = 0; return die("slot must be a or b"); }
    struct part esp; errno = 0;
    if (find_esp(&esp, named)) {
        if (!named) return die("no unambiguous kryptik-esp partition on this installation's disk (devices.sh)");
        char m[200]; snprintf(m, sizeof m, "%.128s is not a kryptik-esp partition that can be read", named);
        return die(m);
    }
    if (slot_var(slot, var)) { errno = 0; return die("no Boot#### number is free"); }
    char own[9]; snprintf(own, sizeof own, "Boot%04X", !strcmp(slot, "a") ? 0x00A0u : 0x00B0u);
    if (strcmp(own, var) && var_exists(own)) printf("%s is another system's entry; slot %s's is %s\n", own, slot, var);
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
    /* Appended to BootOrder, so a firmware that ignores BootNext still offers
     * it without displacing the machine's own entry; forget removes it. */
    unsigned char order[512]; size_t ol = 0; uint16_t num = (uint16_t)strtol(var + 4, NULL, 16);
    if (read_var("BootOrder", order, sizeof order, &ol)) ol = 0;
    if (!holds(order, ol, num) && ol + 2 <= sizeof order) { ol += put_u16(order + ol, num); if (write_var("BootOrder", order, ol)) return die("updating BootOrder failed"); }
    return 0;
}

static int cmd_set_next(const char *slot) {
    char var[9];
    if (ensure_entry(slot, NULL, var)) return 1;
    unsigned char v[2]; put_u16(v, (uint16_t)strtol(var + 4, NULL, 16));
    if (write_var("BootNext", v, 2)) return die("writing BootNext failed");
    printf("BootNext = %s (one boot)\n", var);
    return 0;
}

/* Delete Kryptik's entries, and BootNext if it names one of them or nothing,
 * and drop them from BootOrder, so the firmware boots BOOTX64.EFI, the
 * committed slot. Run whenever a trial ends: a firmware re-adds its own disk
 * entry at the end of BootOrder, so a leftover Kryptik entry would win over
 * the committed slot at every cold boot. */
static int cmd_forget(void) {
    char names[256][9], mine[256][9]; int cnt = boot_vars(names, 256), no = 0;
    unsigned char ours[512]; size_t on = 0;
    for (int i = 0; i < cnt; i++)
        if (is_ours(names[i], NULL)) { memcpy(mine[no++], names[i], 9); on += put_u16(ours + on, (uint16_t)strtol(names[i] + 4, NULL, 16)); }
    unsigned char order[512], kept[512]; size_t ol = 0, kl = 0;
    if (read_var("BootOrder", order, sizeof order, &ol)) ol = 0;
    for (size_t i = 0; i + 1 < ol; i += 2) {
        uint16_t e = (uint16_t)(order[i] | (order[i+1] << 8));
        if (!holds(ours, on, e)) kl += put_u16(kept + kl, e);
    }
    if (kl != ol) {
        if (kl == 0 ? delete_var("BootOrder") : write_var("BootOrder", kept, kl)) return die("updating BootOrder failed");
    }
    /* Each is tried even if the one before failed. */
    int bad = 0;
    unsigned char nx[8]; size_t nl = 0;
    if (read_var("BootNext", nx, sizeof nx, &nl) == 0 && nl >= 2) {
        uint16_t e = (uint16_t)(nx[0] | (nx[1] << 8)); char nv[9]; snprintf(nv, sizeof nv, "Boot%04X", (unsigned)e);
        if ((holds(ours, on, e) || !var_exists(nv)) && delete_var("BootNext")) { die("deleting BootNext failed"); bad = 1; }
    }
    for (int i = 0; i < no; i++)
        if (delete_var(mine[i])) { char m[40]; snprintf(m, sizeof m, "deleting %s failed", mine[i]); die(m); bad = 1; }
    if (bad) return 1;
    printf("forgotten: Kryptik's entries and BootNext; the firmware boots BOOTX64.EFI\n");
    return 0;
}

static void print_entry(const char *var) {
    char desc[128], file[256]; int active = 0;
    if (option_text(var, desc, sizeof desc, file, sizeof file, &active)) return;
    printf("  %s: %s  %s%s  [%s]\n", var, desc, file[0] ? "file=" : "(no file path)", file, active ? "active" : "inactive");
}

static int cmd_list(void) {
    unsigned char buf[512]; size_t n = 0;
    if (read_var("BootCurrent", buf, sizeof buf, &n) == 0 && n >= 2) printf("BootCurrent: Boot%04X\n", buf[0] | (buf[1] << 8));
    if (read_var("BootNext", buf, sizeof buf, &n) == 0 && n >= 2) printf("BootNext:    Boot%04X\n", buf[0] | (buf[1] << 8)); else printf("BootNext:    (none)\n");
    if (read_var("BootOrder", buf, sizeof buf, &n) == 0) { printf("BootOrder:  "); for (size_t i = 0; i + 1 < n; i += 2) printf(" Boot%04X", buf[i] | (buf[i+1] << 8)); printf("\n"); }
    char names[256][9]; int cnt = boot_vars(names, 256);
    if (cnt < 0) return die("efivarfs is not mounted");
    for (int i = 0; i < cnt; i++) print_entry(names[i]);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: kryptik-efiboot list | set-next a|b | clear-next | ensure a|b [ESP] | forget\n"); return 2; }
    if (access(EFIVARS, R_OK)) { errno = 0; return die("no efivarfs at " EFIVARS " (not a UEFI boot, or sysinit did not mount it)"); }
    if (!strcmp(argv[1], "list")) return cmd_list();
    if (!strcmp(argv[1], "set-next") && argc == 3) return cmd_set_next(argv[2]);
    if (!strcmp(argv[1], "ensure") && (argc == 3 || argc == 4)) { char var[9]; return ensure_entry(argv[2], argc == 4 ? argv[3] : NULL, var); }
    if (!strcmp(argv[1], "forget")) return cmd_forget();
    if (!strcmp(argv[1], "clear-next")) { if (delete_var("BootNext")) return die("deleting BootNext failed"); printf("BootNext cleared\n"); return 0; }
    fprintf(stderr, "kryptik-efiboot: unknown command\n"); return 2;
}
