#ifndef NAT_FRAG_H
#define NAT_FRAG_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <time.h>

#define NAT_FRAG_MAX_ENTRIES 256U
#define NAT_FRAG_MAX_PKT     2048U
#define NAT_FRAG_TIMEOUT_SEC 30U

struct nat_frag_entry {
    bool     active;
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t ip_id;
    uint8_t  proto;
    uint16_t ihl;
    uint16_t expected_total_len;
    uint16_t received_bytes;
    uint8_t  hdr_buf[64];
    uint8_t  payload[NAT_FRAG_MAX_PKT];
    uint8_t  got_last;
    time_t   created_at;
};

struct nat_frag_table {
    struct nat_frag_entry entries[NAT_FRAG_MAX_ENTRIES];
};

void nat_frag_init(struct nat_frag_table *ft);

/* Returns true if packet is fragmented; if reassembly completes, writes
 * full IPv4 packet into out_pkt and sets *out_len. Returns 1 on complete,
 * 0 if waiting for more fragments, -1 on invalid/overflow/drop. */
int nat_frag_process(struct nat_frag_table *ft,
                     const uint8_t *pkt, size_t pkt_len,
                     uint8_t *out_pkt, size_t out_cap, size_t *out_len,
                     bool *was_fragment, time_t now);

void nat_frag_expire(struct nat_frag_table *ft, time_t now);

#endif /* NAT_FRAG_H */
