#include "nat_ct.h"
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

static bool port_is_used(const struct nat_port_bitmap *pm, uint16_t host_port) {
    size_t idx = (size_t)host_port >> 6;
    uint64_t bit = 1ULL << (host_port & 63U);
    return (pm->words[idx] & bit) != 0ULL;
}

static void port_mark_used(struct nat_port_bitmap *pm, uint16_t host_port) {
    size_t idx = (size_t)host_port >> 6;
    uint64_t bit = 1ULL << (host_port & 63U);
    pm->words[idx] |= bit;
}

static void port_release(struct nat_port_bitmap *pm, uint16_t host_port) {
    size_t idx = (size_t)host_port >> 6;
    uint64_t bit = 1ULL << (host_port & 63U);
    pm->words[idx] &= ~bit;
}

static uint16_t alloc_nat_port(struct nat_port_bitmap *pm, uint16_t preferred_host) {
    if (preferred_host >= NAT_PORT_MIN && !port_is_used(pm, preferred_host)) {
        port_mark_used(pm, preferred_host);
        return preferred_host;
    }

    uint16_t start = pm->next_hint;
    if (start < NAT_PORT_MIN) {
        start = NAT_PORT_MIN;
    }

    uint32_t span = (NAT_PORT_MAX - NAT_PORT_MIN) + 1U;
    for (uint32_t i = 0; i < span; i++) {
        uint16_t cand = (uint16_t)(NAT_PORT_MIN + (((uint32_t)(start - NAT_PORT_MIN) + i) % span));
        if (!port_is_used(pm, cand)) {
            port_mark_used(pm, cand);
            pm->next_hint = (cand == NAT_PORT_MAX) ? NAT_PORT_MIN : (uint16_t)(cand + 1U);
            return cand;
        }
    }
    return 0U; /* port pool exhausted */
}

uint32_t nat_ct_hash_tuple(const struct nat_tuple *t) {
    uint32_t h = 2166136261U;
    const uint8_t *p = (const uint8_t *)t;
    size_t len = sizeof(t->src_ip) + sizeof(t->dst_ip) +
                 sizeof(t->src_port) + sizeof(t->dst_port) + sizeof(t->proto);
    for (size_t i = 0; i < len; i++) {
        h ^= p[i];
        h *= 16777619U;
    }
    return h;
}

bool nat_ct_tuple_equal(const struct nat_tuple *a, const struct nat_tuple *b) {
    return a->src_ip == b->src_ip &&
           a->dst_ip == b->dst_ip &&
           a->src_port == b->src_port &&
           a->dst_port == b->dst_port &&
           a->proto == b->proto;
}

int nat_ct_init(struct nat_ct_table *ct, size_t bucket_count, uint32_t nat_ip_net) {
    if (!ct || bucket_count == 0U) {
        return -1;
    }
    memset(ct, 0, sizeof(*ct));
    ct->buckets = calloc(bucket_count, sizeof(struct nat_conn *));
    if (!ct->buckets) {
        return -1;
    }
    ct->bucket_count = bucket_count;
    ct->nat_ip = nat_ip_net;
    ct->ports.next_hint = NAT_PORT_MIN;
    if (pthread_mutex_init(&ct->lock, NULL) != 0) {
        free(ct->buckets);
        ct->buckets = NULL;
        return -1;
    }
    return 0;
}

static void unlink_and_free_conn(struct nat_ct_table *ct, size_t bkt,
                                 struct nat_conn *prev, struct nat_conn *cur) {
    if (prev) {
        prev->hnext = cur->hnext;
    } else {
        ct->buckets[bkt] = cur->hnext;
    }
    port_release(&ct->ports, ntohs(cur->nat_port));
    if (ct->conn_count > 0U) {
        ct->conn_count--;
    }
    ct->stats.active_conns = ct->conn_count;
    ct->stats.expired_conns++;
    free(cur);
}

void nat_ct_destroy(struct nat_ct_table *ct) {
    if (!ct) {
        return;
    }
    pthread_mutex_lock(&ct->lock);
    if (ct->buckets) {
        for (size_t i = 0; i < ct->bucket_count; i++) {
            struct nat_conn *cur = ct->buckets[i];
            while (cur) {
                struct nat_conn *nxt = cur->hnext;
                free(cur);
                cur = nxt;
            }
        }
        free(ct->buckets);
        ct->buckets = NULL;
    }
    ct->bucket_count = 0U;
    ct->conn_count = 0U;
    pthread_mutex_unlock(&ct->lock);
    pthread_mutex_destroy(&ct->lock);
}

struct nat_conn *nat_ct_lookup_outbound(struct nat_ct_table *ct, const struct nat_tuple *orig) {
    if (!ct || !orig || !ct->buckets) {
        return NULL;
    }
    pthread_mutex_lock(&ct->lock);
    size_t bkt = nat_ct_hash_tuple(orig) % ct->bucket_count;
    struct nat_conn *cur = ct->buckets[bkt];
    while (cur) {
        if (nat_ct_tuple_equal(&cur->orig, orig)) {
            pthread_mutex_unlock(&ct->lock);
            return cur;
        }
        cur = cur->hnext;
    }
    pthread_mutex_unlock(&ct->lock);
    return NULL;
}

struct nat_conn *nat_ct_lookup_inbound(struct nat_ct_table *ct, const struct nat_tuple *pkt_tuple) {
    if (!ct || !pkt_tuple || !ct->buckets) {
        return NULL;
    }
    pthread_mutex_lock(&ct->lock);
    for (size_t i = 0; i < ct->bucket_count; i++) {
        struct nat_conn *cur = ct->buckets[i];
        while (cur) {
            if (nat_ct_tuple_equal(&cur->reply, pkt_tuple)) {
                pthread_mutex_unlock(&ct->lock);
                return cur;
            }
            cur = cur->hnext;
        }
    }
    pthread_mutex_unlock(&ct->lock);
    return NULL;
}

struct nat_conn *nat_ct_create_or_get(struct nat_ct_table *ct,
                                      const struct nat_tuple *orig,
                                      uint16_t preferred_port_net,
                                      time_t now) {
    if (!ct || !orig || !ct->buckets) {
        return NULL;
    }
    pthread_mutex_lock(&ct->lock);
    size_t bkt = nat_ct_hash_tuple(orig) % ct->bucket_count;
    struct nat_conn *cur = ct->buckets[bkt];
    while (cur) {
        if (nat_ct_tuple_equal(&cur->orig, orig)) {
            pthread_mutex_unlock(&ct->lock);
            return cur;
        }
        cur = cur->hnext;
    }

    uint16_t alloc_host = alloc_nat_port(&ct->ports, ntohs(preferred_port_net));
    if (alloc_host == 0U) {
        ct->stats.drops_port_exhausted++;
        pthread_mutex_unlock(&ct->lock);
        return NULL;
    }

    struct nat_conn *conn = calloc(1, sizeof(*conn));
    if (!conn) {
        port_release(&ct->ports, alloc_host);
        pthread_mutex_unlock(&ct->lock);
        return NULL;
    }

    conn->orig = *orig;
    conn->nat_ip = ct->nat_ip;
    conn->nat_port = htons(alloc_host);
    conn->state = NAT_STATE_NEW;
    conn->created_at = now;
    conn->last_seen = now;

    /* Expected reply flow: external dst_ip -> NAT public IP on mapped port */
    conn->reply.src_ip = orig->dst_ip;
    conn->reply.dst_ip = ct->nat_ip;
    if (orig->proto == IPPROTO_ICMP) {
        conn->reply.src_port = conn->nat_port;
        conn->reply.dst_port = 0U;
    } else {
        conn->reply.src_port = orig->dst_port;
        conn->reply.dst_port = conn->nat_port;
    }
    conn->reply.proto = orig->proto;

    conn->hnext = ct->buckets[bkt];
    ct->buckets[bkt] = conn;
    ct->conn_count++;
    ct->stats.active_conns = ct->conn_count;
    ct->stats.total_conns++;

    pthread_mutex_unlock(&ct->lock);
    return conn;
}

void nat_ct_touch(struct nat_ct_table *ct, struct nat_conn *conn,
                  uint64_t bytes, bool outbound, time_t now) {
    if (!ct || !conn) {
        return;
    }
    pthread_mutex_lock(&ct->lock);
    conn->last_seen = now;
    if (outbound) {
        conn->pkts_out++;
        conn->bytes_out += bytes;
        ct->stats.pkts_translated_out++;
        ct->stats.bytes_out += bytes;
    } else {
        conn->pkts_in++;
        conn->bytes_in += bytes;
        ct->stats.pkts_translated_in++;
        ct->stats.bytes_in += bytes;
    }
    pthread_mutex_unlock(&ct->lock);
}

static uint32_t timeout_for_conn(const struct nat_conn *conn) {
    if (conn->orig.proto == IPPROTO_TCP) {
        return (conn->state == NAT_STATE_TIME_WAIT) ? NAT_TCP_TW_TIMEOUT_SEC
                                                    : NAT_TCP_IDLE_TIMEOUT_SEC;
    }
    if (conn->orig.proto == IPPROTO_UDP) {
        return NAT_UDP_TIMEOUT_SEC;
    }
    return NAT_ICMP_TIMEOUT_SEC;
}

size_t nat_ct_expire(struct nat_ct_table *ct, time_t now) {
    if (!ct || !ct->buckets) {
        return 0U;
    }
    size_t removed = 0U;
    pthread_mutex_lock(&ct->lock);
    for (size_t i = 0; i < ct->bucket_count; i++) {
        struct nat_conn *prev = NULL;
        struct nat_conn *cur = ct->buckets[i];
        while (cur) {
            uint32_t ttl = timeout_for_conn(cur);
            if (now >= cur->last_seen && (uint64_t)(now - cur->last_seen) >= (uint64_t)ttl) {
                struct nat_conn *nxt = cur->hnext;
                unlink_and_free_conn(ct, i, prev, cur);
                removed++;
                cur = nxt;
            } else {
                prev = cur;
                cur = cur->hnext;
            }
        }
    }
    pthread_mutex_unlock(&ct->lock);
    return removed;
}

void nat_ct_flush(struct nat_ct_table *ct) {
    if (!ct || !ct->buckets) {
        return;
    }
    pthread_mutex_lock(&ct->lock);
    for (size_t i = 0; i < ct->bucket_count; i++) {
        struct nat_conn *cur = ct->buckets[i];
        while (cur) {
            struct nat_conn *nxt = cur->hnext;
            port_release(&ct->ports, ntohs(cur->nat_port));
            free(cur);
            cur = nxt;
        }
        ct->buckets[i] = NULL;
    }
    ct->conn_count = 0U;
    ct->stats.active_conns = 0U;
    memset(ct->ports.words, 0, sizeof(ct->ports.words));
    ct->ports.next_hint = NAT_PORT_MIN;
    pthread_mutex_unlock(&ct->lock);
}
