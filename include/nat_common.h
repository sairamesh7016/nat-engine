#ifndef NAT_COMMON_H
#define NAT_COMMON_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <time.h>

#define NAT_HASH_BUCKETS_DEFAULT 4096U
#define NAT_PORT_MIN             1024U
#define NAT_PORT_MAX             65535U
#define NAT_MAX_PKT_SIZE         2048U
#define NAT_TCP_IDLE_TIMEOUT_SEC 300U
#define NAT_TCP_TW_TIMEOUT_SEC   60U
#define NAT_UDP_TIMEOUT_SEC      120U
#define NAT_ICMP_TIMEOUT_SEC     30U

typedef enum {
    NAT_STATE_NEW = 0,
    NAT_STATE_SYN_SENT,
    NAT_STATE_ESTABLISHED,
    NAT_STATE_FIN_WAIT,
    NAT_STATE_TIME_WAIT,
    NAT_STATE_CLOSED
} nat_conn_state_t;

typedef enum {
    NAT_DIR_OUTBOUND = 0,
    NAT_DIR_INBOUND  = 1
} nat_dir_t;

struct nat_tuple {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  proto;
    uint8_t  pad[3];
};

struct nat_conn {
    struct nat_tuple orig;
    struct nat_tuple reply;
    uint32_t         nat_ip;
    uint16_t         nat_port;
    nat_conn_state_t state;
    uint64_t         pkts_out;
    uint64_t         pkts_in;
    uint64_t         bytes_out;
    uint64_t         bytes_in;
    time_t           created_at;
    time_t           last_seen;
    struct nat_conn *hnext;
};

struct nat_stats {
    uint64_t active_conns;
    uint64_t total_conns;
    uint64_t expired_conns;
    uint64_t pkts_translated_out;
    uint64_t pkts_translated_in;
    uint64_t bytes_out;
    uint64_t bytes_in;
    uint64_t drops_no_route;
    uint64_t drops_port_exhausted;
    uint64_t drops_invalid;
    uint64_t total_latency_ns;
    uint64_t latency_samples;
};

static inline uint16_t nat_csum16(const void *data, size_t len) {
    const uint16_t *buf = (const uint16_t *)data;
    uint32_t sum = 0;

    while (len > 1U) {
        sum += *buf++;
        len -= 2U;
    }
    if (len == 1U) {
        sum += *(const uint8_t *)buf;
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFFU) + (sum >> 16);
    }
    return (uint16_t)(~sum);
}

static inline uint16_t nat_csum_update32(uint16_t old_csum, uint32_t old_val, uint32_t new_val) {
    uint32_t sum = (~((uint32_t)old_csum)) & 0xFFFFU;
    sum += (~(old_val & 0xFFFFU)) & 0xFFFFU;
    sum += (~((old_val >> 16) & 0xFFFFU)) & 0xFFFFU;
    sum += (new_val & 0xFFFFU);
    sum += ((new_val >> 16) & 0xFFFFU);

    while (sum >> 16) {
        sum = (sum & 0xFFFFU) + (sum >> 16);
    }
    return (uint16_t)(~sum);
}

static inline uint16_t nat_csum_update16(uint16_t old_csum, uint16_t old_val, uint16_t new_val) {
    uint32_t sum = (~((uint32_t)old_csum)) & 0xFFFFU;
    sum += (~((uint32_t)old_val)) & 0xFFFFU;
    sum += (uint32_t)new_val;

    while (sum >> 16) {
        sum = (sum & 0xFFFFU) + (sum >> 16);
    }
    return (uint16_t)(~sum);
}

#endif /* NAT_COMMON_H */
