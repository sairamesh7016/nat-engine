#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

#define NAT_IPC_SOCK_PATH "/tmp/nat-engine.sock"

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: natctl <show stats|show conn|show json|flush>\n");
        return 1;
    }

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return 1;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", NAT_IPC_SOCK_PATH);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect(/tmp/nat-engine.sock) - is nat-engine running?");
        close(fd);
        return 1;
    }

    char cmd[128];
    size_t pos = 0U;
    for (int i = 1; i < argc && pos < sizeof(cmd) - 2U; i++) {
        int n = snprintf(cmd + pos, sizeof(cmd) - pos, "%s%s", (i > 1) ? " " : "", argv[i]);
        if (n < 0) break;
        pos += (size_t)n;
    }
    if (pos < sizeof(cmd) - 1U) {
        cmd[pos++] = '\n';
    }

    ssize_t w = write(fd, cmd, pos);
    (void)w;

    char buf[1024];
    ssize_t r;
    while ((r = read(fd, buf, sizeof(buf))) > 0) {
        fwrite(buf, 1, (size_t)r, stdout);
    }

    close(fd);
    return 0;
}
