#define _GNU_SOURCE
#include "nat_ct.h"
#include "nat_rewrite.h"
#include "nat_state.h"
#include "nat_frag.h"
#include "nat_cli.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <linux/if.h>
#include <linux/if_tun.h>

#define NAT_IPC_SOCK_PATH "/tmp/nat-engine.sock"

static volatile sig_atomic_t g_running = 1;

static void handle_sig(int sig) {
    (void)sig;
    g_running = 0;
}

static uint64_t monotonic_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ((uint64_t)ts.tv_sec * 1000000000ULL) + (uint64_t)ts.tv_nsec;
}

static int tun_open(const char *ifname) {
    struct ifreq ifr;
    int fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0) {
        perror("open(/dev/net/tun)");
        return -1;
    }
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    snprintf(ifr.ifr_name, IFNAMSIZ, "%s", ifname);
    if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
        perror("ioctl(TUNSETIFF)");
        close(fd);
        return -1;
    }
    return fd;
}

static int ipc_open(const char *sock_path) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket(AF_UNIX)");
        return -1;
    }

    unlink(sock_path);

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", sock_path);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind(AF_UNIX)");
        close(fd);
        return -1;
    }
    if (listen(fd, 8) < 0) {
        perror("listen(AF_UNIX)");
        close(fd);
        return -1;
    }
    (void)chmod(sock_path, 0666);
    return fd;
}

static void handle_ipc_client(int client_fd, struct nat_ct_table *ct) {
    char cmd[128];
    ssize_t n = read(client_fd, cmd, sizeof(cmd) - 1U);
    if (n <= 0) {
        close(client_fd);
        return;
    }
    cmd[n] = '\0';
    char *nl = strpbrk(cmd, "\r\n");
    if (nl) {
        *nl = '\0';
    }

    FILE *fp = fdopen(client_fd, "w");
    if (!fp) {
        close(client_fd);
        return;
    }

    if (strcmp(cmd, "show stats") == 0) {
        nat_cli_print_stats(fp, ct);
    } else if (strcmp(cmd, "show conn") == 0) {
        nat_cli_print_conns(fp, ct);
    } else if (strcmp(cmd, "show json") == 0) {
        nat_cli_print_json_telemetry(fp, ct);
    } else if (strcmp(cmd, "flush") == 0) {
        nat_ct_flush(ct);
        fprintf(fp, "Connection table flushed.\n");
    } else {
        fprintf(fp, "Unknown command: %s\n", cmd);
    }

    fflush(fp);
    fclose(fp); /* also closes client_fd */
}

/* Returns 1 if out_pkt should be forwarded (*out_len set), 0 if dropped/buffered. */
static int handle_packet(struct nat_ct_table *ct,
                         struct nat_frag_table *ft,
                         const uint8_t *raw, ssize_t nread,
                         bool outbound,
                         uint8_t *out_pkt, size_t out_cap, size_t *out_len) {
    uint64_t t0 = monotonic_ns();
    time_t now = time(NULL);

    if (nread <= 0 || (size_t)nread > NAT_MAX_PKT_SIZE || !out_pkt || !out_len) {
        ct->stats.drops_invalid++;
        return 0;
    }

    size_t pkt_len = 0U;
    bool was_frag = false;
    int f_rc = nat_frag_process(ft, raw, (size_t)nread,
                                out_pkt, out_cap, &pkt_len, &was_frag, now);
    if (f_rc < 0) {
        ct->stats.drops_invalid++;
        return 0;
    }
    if (f_rc == 0) {
        return 0; /* waiting for remaining fragments */
    }
    (void)was_frag;

    struct nat_tuple tup;
    uint8_t tcp_flags = 0U;
    size_t l4_off = 0U;
    if (nat_extract_tuple(out_pkt, pkt_len, &tup, &tcp_flags, &l4_off) != NAT_REWRITE_OK) {
        ct->stats.drops_invalid++;
        return 0;
    }
    (void)l4_off;

    if (outbound) {
        struct nat_conn *conn = nat_ct_create_or_get(ct, &tup, tup.src_port, now);
        if (!conn) {
            return 0;
        }
        if (nat_rewrite_outbound(out_pkt, pkt_len, conn) != NAT_REWRITE_OK) {
            ct->stats.drops_invalid++;
            return 0;
        }
        nat_state_update_conn(conn, tcp_flags, true, now);
        nat_ct_touch(ct, conn, (uint64_t)pkt_len, true, now);
    } else {
        struct nat_conn *conn = nat_ct_lookup_inbound(ct, &tup);
        if (!conn) {
            ct->stats.drops_no_route++;
            return 0;
        }
        if (nat_rewrite_inbound(out_pkt, pkt_len, conn) != NAT_REWRITE_OK) {
            ct->stats.drops_invalid++;
            return 0;
        }
        nat_state_update_conn(conn, tcp_flags, false, now);
        nat_ct_touch(ct, conn, (uint64_t)pkt_len, false, now);
    }

    uint64_t dt = monotonic_ns() - t0;
    ct->stats.total_latency_ns += dt;
    ct->stats.latency_samples++;
    *out_len = pkt_len;
    return 1;
}

static void run_selftest(void) {
    struct nat_ct_table ct;
    struct nat_frag_table ft;
    uint32_t nat_ip = inet_addr("203.0.113.10");

    if (nat_ct_init(&ct, NAT_HASH_BUCKETS_DEFAULT, nat_ip) != 0) {
        fprintf(stderr, "selftest: ct init failed\n");
        exit(1);
    }
    nat_frag_init(&ft);

    uint8_t sample[64];
    uint8_t out_pkt[NAT_MAX_PKT_SIZE];
    size_t out_len = 0U;

    memset(sample, 0, sizeof(sample));
    sample[0] = 0x45U;
    sample[3] = 28U;
    sample[9] = IPPROTO_ICMP;
    inet_pton(AF_INET, "192.168.1.10", sample + 12);
    inet_pton(AF_INET, "8.8.8.8", sample + 16);
    sample[20] = 8U;
    sample[24] = 0x12U;
    sample[25] = 0x34U;
    handle_packet(&ct, &ft, sample, 28, true, out_pkt, sizeof(out_pkt), &out_len);

    uint8_t reply[64];
    memset(reply, 0, sizeof(reply));
    reply[0] = 0x45U;
    reply[3] = 28U;
    reply[9] = IPPROTO_ICMP;
    inet_pton(AF_INET, "8.8.8.8", reply + 12);
    inet_pton(AF_INET, "203.0.113.10", reply + 16);
    reply[20] = 0U;
    reply[24] = 0x12U;
    reply[25] = 0x34U;
    handle_packet(&ct, &ft, reply, 28, false, out_pkt, sizeof(out_pkt), &out_len);

    nat_cli_print_stats(stdout, &ct);
    nat_cli_print_conns(stdout, &ct);
    nat_cli_print_json_telemetry(stdout, &ct);

    nat_ct_destroy(&ct);
}

int main(int argc, char **argv) {
    if (argc >= 2 && strcmp(argv[1], "--selftest") == 0) {
        run_selftest();
        return 0;
    }

    if (argc < 4) {
        fprintf(stderr, "Usage: %s <lan_tun> <wan_tun> <nat_public_ip> [--selftest]\n", argv[0]);
        return 1;
    }

    const char *lan_if = argv[1];
    const char *wan_if = argv[2];
    uint32_t nat_ip = inet_addr(argv[3]);
    if (nat_ip == INADDR_NONE) {
        fprintf(stderr, "Invalid NAT public IP: %s\n", argv[3]);
        return 1;
    }

    signal(SIGINT, handle_sig);
    signal(SIGTERM, handle_sig);

    int lan_fd = tun_open(lan_if);
    int wan_fd = tun_open(wan_if);
    int ipc_fd = ipc_open(NAT_IPC_SOCK_PATH);
    if (lan_fd < 0 || wan_fd < 0 || ipc_fd < 0) {
        if (lan_fd >= 0) close(lan_fd);
        if (wan_fd >= 0) close(wan_fd);
        if (ipc_fd >= 0) {
            close(ipc_fd);
            unlink(NAT_IPC_SOCK_PATH);
        }
        return 1;
    }

    struct nat_ct_table ct;
    struct nat_frag_table ft;
    if (nat_ct_init(&ct, NAT_HASH_BUCKETS_DEFAULT, nat_ip) != 0) {
        close(lan_fd);
        close(wan_fd);
        close(ipc_fd);
        unlink(NAT_IPC_SOCK_PATH);
        return 1;
    }
    nat_frag_init(&ft);

    time_t last_tick = time(NULL);
    while (g_running) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(lan_fd, &rfds);
        FD_SET(wan_fd, &rfds);
        FD_SET(ipc_fd, &rfds);

        int maxfd = lan_fd;
        if (wan_fd > maxfd) maxfd = wan_fd;
        if (ipc_fd > maxfd) maxfd = ipc_fd;

        struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
        int rc = select(maxfd + 1, &rfds, NULL, NULL, &tv);
        if (rc < 0) {
            if (errno == EINTR) continue;
            break;
        }

        uint8_t raw[NAT_MAX_PKT_SIZE];
        uint8_t out_pkt[NAT_MAX_PKT_SIZE];
        size_t out_len = 0U;

        if (rc > 0 && FD_ISSET(lan_fd, &rfds)) {
            ssize_t n = read(lan_fd, raw, sizeof(raw));
            if (n > 0 && handle_packet(&ct, &ft, raw, n, true,
                                       out_pkt, sizeof(out_pkt), &out_len)) {
                ssize_t w = write(wan_fd, out_pkt, out_len);
                (void)w;
            }
        }
        if (rc > 0 && FD_ISSET(wan_fd, &rfds)) {
            ssize_t n = read(wan_fd, raw, sizeof(raw));
            if (n > 0 && handle_packet(&ct, &ft, raw, n, false,
                                       out_pkt, sizeof(out_pkt), &out_len)) {
                ssize_t w = write(lan_fd, out_pkt, out_len);
                (void)w;
            }
        }
        if (rc > 0 && FD_ISSET(ipc_fd, &rfds)) {
            int cfd = accept(ipc_fd, NULL, NULL);
            if (cfd >= 0) {
                handle_ipc_client(cfd, &ct);
            }
        }

        time_t now = time(NULL);
        if (now - last_tick >= 5) {
            nat_ct_expire(&ct, now);
            nat_frag_expire(&ft, now);
            last_tick = now;
        }
    }

    nat_ct_destroy(&ct);
    close(lan_fd);
    close(wan_fd);
    close(ipc_fd);
    unlink(NAT_IPC_SOCK_PATH);
    return 0;
}
