/* kryptik-probe: a zone that names the probe image runs this from the image's /usr; it says where. It
   also locks its memory, a call outside the zone filter's base set, so the image needs a policy line. */
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

int main(void)
{
    char path[PATH_MAX];
    ssize_t n = readlink("/proc/self/exe", path, sizeof path - 1);

    if (n < 0) {
        perror("kryptik-probe: /proc/self/exe");
        return 1;
    }
    path[n] = '\0';
    int locked = mlockall(MCL_CURRENT) == 0;
    printf("kryptik-probe 1.0, from the probe image: %s (mlockall: %s)\n", path, locked ? "ok" : strerror(errno));
    return 0;
}
