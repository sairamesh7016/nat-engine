#ifndef NAT_CT_H
#define NAT_CT_H

#include "nat_common.h"
#include <pthread.h>

struct nat_port_bitmap {
    uint64_t words[1024]; /* covers 0..65535 ports (65536 bits) */
    uint16_t next_hint;
};

struct nat_ct_table {
    struct nat_conn       **buckets;
    size_t                  bucket_count;
    size_t                  conn_count;
    uint32_t                nat_ip;     /* network byte order */
    struct nat_port_bitmap  ports;
    struct nat_stats        stats;
    pthread_mutex_t         lock;
};

int nat_ct_init(struct nat_ct_table *ct, size_t bucket_count, uint32_t nat_ip_net);
void nat_ct_destroy(struct nat_ct_table *ct);

uint32_t nat_ct_hash_tuple(const struct nat_tuple *t);
bool nat_ct_tuple_equal(const struct nat_tuple *a, const struct nat_tuple *b);

struct nat_conn *nat_ct_lookup_outbound(struct nat_ct_table *ct, const struct nat_tuple *orig);
struct nat_conn *nat_ct_lookup_inbound(struct nat_ct_table *ct, const struct nat_tuple *pkt_tuple);

struct nat_conn *nat_ct_create_or_get(struct nat_ct_table *ct,
                                      const struct nat_tuple *orig,
                                      uint16_t preferred_port_net,
                                      time_t now);

void nat_ct_touch(struct nat_ct_table *ct, struct nat_conn *conn,
                  uint64_t bytes, bool outbound, time_t now);

size_t nat_ct_expire(struct nat_ct_table *ct, time_t now);
void nat_ct_flush(struct nat_ct_table *ct);

#endif /* NAT_CT_H */
