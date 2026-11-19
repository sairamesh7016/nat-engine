#include "nat_frag.h"
#include "nat_common.h"
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip.h>

#define IP_OFF_MASK 0x1FFFU

void nat_frag_init(struct nat_frag_table *ft) {
    if (ft) {
        memset(ft, 0, sizeof(*ft));
    }
}

static int find_or_alloc_slot(struct nat_frag_table *ft,
                               uint32_t src_ip, uint32_t dst_ip,
                               uint16_t ip_id, uint8_t proto, time_t now) {
    int free_idx = -1;
    for (size_t i = 0; i < NAT_FRAG_MAX_ENTRIES; i++) {
        struct nat_frag_entry *e = &ft->entries[i];
        if (e->active &&
            e->src_ip == src_ip &&
            e->dst_ip == dst_ip &&
            e->ip_id == ip_id &&
            e->proto == proto) {
            return (int)i;
        }
        if (!e->active && free_idx < 0) {
            free_idx = (int)i;
        }
    }
    if (free_idx >= 0) {
        struct nat_frag_entry *e = &ft->entries[free_idx];
        memset(e, 0, sizeof(*e));
        e->active = true;
        e->src_ip = src_ip;
        e->dst_ip = dst_ip;
        e->ip_id = ip_id;
        e->proto = proto;
        e->created_at = now;
    }
    return free_idx;
}

int nat_frag_process(struct nat_frag_table *ft,
                     const uint8_t *pkt, size_t pkt_len,
                     uint8_t *out_pkt, size_t out_cap, size_t *out_len,
                     bool *was_fragment, time_t now) {
    if (!ft || !pkt || !out_pkt || !out_len || !was_fragment || pkt_len < sizeof(struct iphdr)) {
        return -1;
    }

    const struct iphdr *ip = (const struct iphdr *)pkt;
    size_t ihl = (size_t)ip->ihl * 4U;
    uint16_t tot_len = ntohs(ip->tot_len);
    uint16_t frag_off_field = ntohs(ip->frag_off);
    bool mf = (frag_off_field & IP_MF) != 0U;
    uint16_t offset_bytes = (uint16_t)((frag_off_field & IP_OFF_MASK) * 8U);

    if (ihl < sizeof(struct iphdr) || tot_len < ihl || pkt_len < tot_len) {
        return -1;
    }

    if (!mf && offset_bytes == 0U) {
        *was_fragment = false;
        if (out_cap < tot_len) {
            return -1;
        }
        memcpy(out_pkt, pkt, tot_len);
        *out_len = tot_len;
        return 1;
    }

    *was_fragment = true;
    size_t frag_payload_len = (size_t)tot_len - ihl;
    if ((size_t)offset_bytes + frag_payload_len > NAT_FRAG_MAX_PKT) {
        return -1;
    }

    int slot = find_or_alloc_slot(ft, ip->saddr, ip->daddr, ip->id, ip->protocol, now);
    if (slot < 0) {
        return -1;
    }

    struct nat_frag_entry *e = &ft->entries[slot];
    if (offset_bytes == 0U && ihl <= sizeof(e->hdr_buf)) {
        memcpy(e->hdr_buf, pkt, ihl);
        e->ihl = (uint16_t)ihl;
    }

    memcpy(e->payload + offset_bytes, pkt + ihl, frag_payload_len);
    e->received_bytes += (uint16_t)frag_payload_len;
    if (!mf) {
        e->got_last = 1U;
        e->expected_total_len = (uint16_t)(offset_bytes + frag_payload_len);
    }

    if (e->got_last && e->ihl > 0U && e->received_bytes >= e->expected_total_len) {
        size_t full_len = (size_t)e->ihl + (size_t)e->expected_total_len;
        if (out_cap < full_len) {
            e->active = false;
            return -1;
        }
        memcpy(out_pkt, e->hdr_buf, e->ihl);
        memcpy(out_pkt + e->ihl, e->payload, e->expected_total_len);

        struct iphdr *re_ip = (struct iphdr *)out_pkt;
        re_ip->tot_len = htons((uint16_t)full_len);
        re_ip->frag_off = 0U;
        re_ip->check = 0U;
        re_ip->check = nat_csum16(re_ip, e->ihl);

        *out_len = full_len;
        e->active = false;
        return 1;
    }

    return 0;
}

void nat_frag_expire(struct nat_frag_table *ft, time_t now) {
    if (!ft) {
        return;
    }
    for (size_t i = 0; i < NAT_FRAG_MAX_ENTRIES; i++) {
        struct nat_frag_entry *e = &ft->entries[i];
        if (e->active && now >= e->created_at &&
            (uint64_t)(now - e->created_at) >= NAT_FRAG_TIMEOUT_SEC) {
            e->active = false;
        }
    }
}
