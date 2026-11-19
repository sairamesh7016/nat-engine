#define _GNU_SOURCE
#include "nat_cli.h"
#include "nat_state.h"
#include <string.h>
#include <arpa/inet.h>

static const char *proto_str(uint8_t proto) {
    switch (proto) {
        case IPPROTO_TCP:  return "TCP";
        case IPPROTO_UDP:  return "UDP";
        case IPPROTO_ICMP: return "ICMP";
        default:           return "OTHER";
    }
}

void nat_cli_print_stats(FILE *out, const struct nat_ct_table *ct) {
    if (!out || !ct) {
        return;
    }
    char nat_ip_buf[INET_ADDRSTRLEN] = "0.0.0.0";
    inet_ntop(AF_INET, &ct->nat_ip, nat_ip_buf, sizeof(nat_ip_buf));

    double avg_lat_ms = 0.0;
    if (ct->stats.latency_samples > 0U) {
        avg_lat_ms = ((double)ct->stats.total_latency_ns /
                      (double)ct->stats.latency_samples) / 1e6;
    }

    fprintf(out,
            "nat_ip=%s active_conns=%llu total_conns=%llu expired_conns=%llu "
            "pkts_out=%llu pkts_in=%llu bytes_out=%llu bytes_in=%llu "
            "drops_no_route=%llu drops_port_exhausted=%llu drops_invalid=%llu "
            "avg_latency_ms=%.3f\n",
            nat_ip_buf,
            (unsigned long long)ct->stats.active_conns,
            (unsigned long long)ct->stats.total_conns,
            (unsigned long long)ct->stats.expired_conns,
            (unsigned long long)ct->stats.pkts_translated_out,
            (unsigned long long)ct->stats.pkts_translated_in,
            (unsigned long long)ct->stats.bytes_out,
            (unsigned long long)ct->stats.bytes_in,
            (unsigned long long)ct->stats.drops_no_route,
            (unsigned long long)ct->stats.drops_port_exhausted,
            (unsigned long long)ct->stats.drops_invalid,
            avg_lat_ms);
}

void nat_cli_print_conns(FILE *out, struct nat_ct_table *ct) {
    if (!out || !ct || !ct->buckets) {
        return;
    }
    pthread_mutex_lock((pthread_mutex_t *)&ct->lock);
    fprintf(out, "%-15s %-6s -> %-15s %-6s | %-15s %-6s | %-5s %-11s %10s %10s\n",
            "SRC_IP", "SPORT", "DST_IP", "DPORT",
            "NAT_IP", "NPORT", "PROTO", "STATE", "BYTES_OUT", "BYTES_IN");
    for (size_t i = 0; i < ct->bucket_count; i++) {
        struct nat_conn *cur = ct->buckets[i];
        while (cur) {
            char s_buf[INET_ADDRSTRLEN], d_buf[INET_ADDRSTRLEN], n_buf[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &cur->orig.src_ip, s_buf, sizeof(s_buf));
            inet_ntop(AF_INET, &cur->orig.dst_ip, d_buf, sizeof(d_buf));
            inet_ntop(AF_INET, &cur->nat_ip, n_buf, sizeof(n_buf));
            fprintf(out, "%-15s %-6u -> %-15s %-6u | %-15s %-6u | %-5s %-11s %10llu %10llu\n",
                    s_buf, (unsigned)ntohs(cur->orig.src_port),
                    d_buf, (unsigned)ntohs(cur->orig.dst_port),
                    n_buf, (unsigned)ntohs(cur->nat_port),
                    proto_str(cur->orig.proto),
                    nat_state_name(cur->state),
                    (unsigned long long)cur->bytes_out,
                    (unsigned long long)cur->bytes_in);
            cur = cur->hnext;
        }
    }
    pthread_mutex_unlock((pthread_mutex_t *)&ct->lock);
}

void nat_cli_print_json_telemetry(FILE *out, struct nat_ct_table *ct) {
    if (!out || !ct) {
        return;
    }
    char nat_ip_buf[INET_ADDRSTRLEN] = "0.0.0.0";
    inet_ntop(AF_INET, &ct->nat_ip, nat_ip_buf, sizeof(nat_ip_buf));

    double avg_lat_ms = 0.0;
    if (ct->stats.latency_samples > 0U) {
        avg_lat_ms = ((double)ct->stats.total_latency_ns /
                      (double)ct->stats.latency_samples) / 1e6;
    }

    fprintf(out,
            "{\n"
            "  \"project\": \"nat-engine\",\n"
            "  \"nat_ip\": \"%s\",\n"
            "  \"active_connections\": %llu,\n"
            "  \"total_connections\": %llu,\n"
            "  \"expired_connections\": %llu,\n"
            "  \"packets_translated_out\": %llu,\n"
            "  \"packets_translated_in\": %llu,\n"
            "  \"bytes_out\": %llu,\n"
            "  \"bytes_in\": %llu,\n"
            "  \"drops\": {\n"
            "    \"no_route\": %llu,\n"
            "    \"port_exhausted\": %llu,\n"
            "    \"invalid\": %llu\n"
            "  },\n"
            "  \"avg_latency_ms\": %.3f\n"
            "}\n",
            nat_ip_buf,
            (unsigned long long)ct->stats.active_conns,
            (unsigned long long)ct->stats.total_conns,
            (unsigned long long)ct->stats.expired_conns,
            (unsigned long long)ct->stats.pkts_translated_out,
            (unsigned long long)ct->stats.pkts_translated_in,
            (unsigned long long)ct->stats.bytes_out,
            (unsigned long long)ct->stats.bytes_in,
            (unsigned long long)ct->stats.drops_no_route,
            (unsigned long long)ct->stats.drops_port_exhausted,
            (unsigned long long)ct->stats.drops_invalid,
            avg_lat_ms);
}

int nat_cli_run(int argc, char **argv, struct nat_ct_table *ct) {
    if (!ct) {
        return -1;
    }
    if (argc < 2) {
        fprintf(stderr, "Usage: natctl <show stats|show conn|show json|flush>\n");
        return 1;
    }
    if (strcmp(argv[1], "show") == 0 && argc >= 3) {
        if (strcmp(argv[2], "stats") == 0) {
            nat_cli_print_stats(stdout, ct);
            return 0;
        }
        if (strcmp(argv[2], "conn") == 0) {
            nat_cli_print_conns(stdout, ct);
            return 0;
        }
        if (strcmp(argv[2], "json") == 0) {
            nat_cli_print_json_telemetry(stdout, ct);
            return 0;
        }
    }
    if (strcmp(argv[1], "flush") == 0) {
        nat_ct_flush(ct);
        printf("Connection table flushed.\n");
        return 0;
    }
    fprintf(stderr, "Unknown command.\n");
    return 1;
}
