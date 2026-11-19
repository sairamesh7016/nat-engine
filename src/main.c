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
#include <linux/if.h>
#include <linux/if_tun.h>

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

static void handle_packet(struct nat_ct_table *ct,
                          struct nat_frag_table *ft,
                          const uint8_t *raw, ssize_t nread,
                          bool outbound) {
    uint64_t t0 = monotonic_ns();
    time_t now = time(NULL);

    if (nread <= 0 || (size_t)nread > NAT_MAX_PKT_SIZE) {
        ct->stats.drops_invalid++;
        return;
    }

    uint8_t pkt[NAT_MAX_PKT_SIZE];
    size_t pkt_len = 0U;
    bool was_frag = false;

    int f_rc = nat_frag_process(ft, raw, (size_t)nread,
                                pkt, sizeof(pkt), &pkt_len, &was_frag, now);
    if (f_rc < 0) {
        ct->stats.drops_invalid++;
        return;
    }
    if (f_rc == 0) {
        return; /* buffered partial fragment */
    }
    (void)was_frag;

    struct nat_tuple tup;
    uint8_t tcp_flags = 0U;
    size_t l4_off = 0U;
    if (nat_extract_tuple(pkt, pkt_len, &tup, &tcp_flags, &l4_off) != NAT_REWRITE_OK) {
        ct->stats.drops_invalid++;
        return;
    }
    (void)l4_off;

    if (outbound) {
        struct nat_conn *conn = nat_ct_create_or_get(ct, &tup, tup.src_port, now);
        if (!conn) {
            return;
        }
        if (nat_rewrite_outbound(pkt, pkt_len, conn) != NAT_REWRITE_OK) {
            ct->stats.drops_invalid++;
            return;
        }
        nat_state_update_conn(conn, tcp_flags, true, now);
        nat_ct_touch(ct, conn, (uint64_t)pkt_len, true, now);
    } else {
        struct nat_conn *conn = nat_ct_lookup_inbound(ct, &tup);
        if (!conn) {
            ct->stats.drops_no_route++;
            return;
        }
        if (nat_rewrite_inbound(pkt, pkt_len, conn) != NAT_REWRITE_OK) {
            ct->stats.drops_invalid++;
            return;
        }
        nat_state_update_conn(conn, tcp_flags, false, now);
        nat_ct_touch(ct, conn, (uint64_t)pkt_len, false, now);
    }

    uint64_t dt = monotonic_ns() - t0;
    ct->stats.total_latency_ns += dt;
    ct->stats.latency_samples++;
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
    memset(sample, 0, sizeof(sample));
    sample[0] = 0x45U; /* IPv4, IHL=5 */
    sample[2] = 0x00U;
    sample[3] = 28U;   /* IPv4 tot_len = 28 bytes (20 IP + 8 ICMP) */
    sample[9] = IPPROTO_ICMP;
    inet_pton(AF_INET, "192.168.1.10", sample + 12);
    inet_pton(AF_INET, "8.8.8.8", sample + 16);
    sample[20] = 8U; /* ICMP Echo Request */
    sample[24] = 0x12U;
    sample[25] = 0x34U;

    /* Outbound SNAT */
    handle_packet(&ct, &ft, sample, 28, true);

    /* Inbound DNAT reply (8.8.8.8 -> 203.0.113.10, same ICMP ID 0x1234) */
    uint8_t reply[64];
    memset(reply, 0, sizeof(reply));
    reply[0] = 0x45U;
    reply[3] = 28U;
    reply[9] = IPPROTO_ICMP;
    inet_pton(AF_INET, "8.8.8.8", reply + 12);
    inet_pton(AF_INET, "203.0.113.10", reply + 16);
    reply[20] = 0U; /* ICMP Echo Reply */
    reply[24] = 0x12U;
    reply[25] = 0x34U;
    handle_packet(&ct, &ft, reply, 28, false);
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
    if (lan_fd < 0 || wan_fd < 0) {
        if (lan_fd >= 0) close(lan_fd);
        if (wan_fd >= 0) close(wan_fd);
        return 1;
    }

    struct nat_ct_table ct;
    struct nat_frag_table ft;
    if (nat_ct_init(&ct, NAT_HASH_BUCKETS_DEFAULT, nat_ip) != 0) {
        close(lan_fd);
        close(wan_fd);
        return 1;
    }
    nat_frag_init(&ft);

    time_t last_tick = time(NULL);
    while (g_running) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(lan_fd, &rfds);
        FD_SET(wan_fd, &rfds);
        int maxfd = (lan_fd > wan_fd) ? lan_fd : wan_fd;

        struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
        int rc = select(maxfd + 1, &rfds, NULL, NULL, &tv);
        if (rc < 0) {
            if (errno == EINTR) continue;
            break;
        }

        uint8_t buf[NAT_MAX_PKT_SIZE];
        if (rc > 0 && FD_ISSET(lan_fd, &rfds)) {
            ssize_t n = read(lan_fd, buf, sizeof(buf));
            if (n > 0) {
                handle_packet(&ct, &ft, buf, n, true);
                ssize_t w = write(wan_fd, buf, (size_t)n);
                (void)w;
            }
        }
        if (rc > 0 && FD_ISSET(wan_fd, &rfds)) {
            ssize_t n = read(wan_fd, buf, sizeof(buf));
            if (n > 0) {
                handle_packet(&ct, &ft, buf, n, false);
                ssize_t w = write(lan_fd, buf, (size_t)n);
                (void)w;
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
    return 0;
}
