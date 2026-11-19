#include "nat_rewrite.h"
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

static void update_l4_csum_ip32(uint16_t *l4_csum_net,
                                uint32_t old_ip_net, uint32_t new_ip_net) {
    if (!l4_csum_net) {
        return;
    }
    *l4_csum_net = nat_csum_update32(*l4_csum_net, old_ip_net, new_ip_net);
}

static void update_l4_csum_port16(uint16_t *l4_csum_net,
                                  uint16_t old_port_net, uint16_t new_port_net) {
    if (!l4_csum_net) {
        return;
    }
    *l4_csum_net = nat_csum_update16(*l4_csum_net, old_port_net, new_port_net);
}

int nat_extract_tuple(const uint8_t *pkt, size_t pkt_len,
                      struct nat_tuple *out_tuple,
                      uint8_t *out_tcp_flags,
                      size_t *out_l4_offset) {
    if (!pkt || !out_tuple || pkt_len < sizeof(struct iphdr)) {
        return NAT_REWRITE_ERR_NULL;
    }

    const struct iphdr *ip = (const struct iphdr *)pkt;
    if (ip->version != 4U) {
        return NAT_REWRITE_ERR_PROTO;
    }

    size_t ihl = (size_t)ip->ihl * 4U;
    if (ihl < sizeof(struct iphdr) || pkt_len < ihl) {
        return NAT_REWRITE_ERR_LEN;
    }

    memset(out_tuple, 0, sizeof(*out_tuple));
    out_tuple->src_ip = ip->saddr;
    out_tuple->dst_ip = ip->daddr;
    out_tuple->proto = ip->protocol;

    if (out_tcp_flags) {
        *out_tcp_flags = 0U;
    }
    if (out_l4_offset) {
        *out_l4_offset = ihl;
    }

    const uint8_t *l4 = pkt + ihl;
    size_t rem = pkt_len - ihl;

    if (ip->protocol == IPPROTO_TCP) {
        if (rem < sizeof(struct tcphdr)) {
            return NAT_REWRITE_ERR_LEN;
        }
        const struct tcphdr *tcp = (const struct tcphdr *)l4;
        out_tuple->src_port = tcp->source;
        out_tuple->dst_port = tcp->dest;
        if (out_tcp_flags) {
            uint8_t flags = 0U;
            if (tcp->fin) flags |= NAT_TCP_FIN;
            if (tcp->syn) flags |= NAT_TCP_SYN;
            if (tcp->rst) flags |= NAT_TCP_RST;
            if (tcp->psh) flags |= NAT_TCP_PSH;
            if (tcp->ack) flags |= NAT_TCP_ACK;
            if (tcp->urg) flags |= NAT_TCP_URG;
            *out_tcp_flags = flags;
        }
        return NAT_REWRITE_OK;
    }

    if (ip->protocol == IPPROTO_UDP) {
        if (rem < sizeof(struct udphdr)) {
            return NAT_REWRITE_ERR_LEN;
        }
        const struct udphdr *udp = (const struct udphdr *)l4;
        out_tuple->src_port = udp->source;
        out_tuple->dst_port = udp->dest;
        return NAT_REWRITE_OK;
    }

    if (ip->protocol == IPPROTO_ICMP) {
        if (rem < sizeof(struct icmphdr)) {
            return NAT_REWRITE_ERR_LEN;
        }
        const struct icmphdr *icmp = (const struct icmphdr *)l4;
        out_tuple->src_port = icmp->un.echo.id;
        out_tuple->dst_port = 0U;
        return NAT_REWRITE_OK;
    }

    return NAT_REWRITE_ERR_PROTO;
}

int nat_rewrite_outbound(uint8_t *pkt, size_t pkt_len,
                       const struct nat_conn *conn) {
    if (!pkt || !conn || pkt_len < sizeof(struct iphdr)) {
        return NAT_REWRITE_ERR_NULL;
    }

    struct iphdr *ip = (struct iphdr *)pkt;
    size_t ihl = (size_t)ip->ihl * 4U;
    if (ihl < sizeof(struct iphdr) || pkt_len < ihl) {
        return NAT_REWRITE_ERR_LEN;
    }

    uint32_t old_src_ip = ip->saddr;
    uint32_t new_src_ip = conn->nat_ip;
    ip->saddr = new_src_ip;
    ip->check = nat_csum_update32(ip->check, old_src_ip, new_src_ip);

    uint8_t *l4 = pkt + ihl;
    size_t rem = pkt_len - ihl;

    if (ip->protocol == IPPROTO_TCP) {
        if (rem < sizeof(struct tcphdr)) {
            return NAT_REWRITE_ERR_LEN;
        }
        struct tcphdr *tcp = (struct tcphdr *)l4;
        uint16_t old_sport = tcp->source;
        uint16_t new_sport = conn->nat_port;
        tcp->source = new_sport;
        update_l4_csum_ip32(&tcp->check, old_src_ip, new_src_ip);
        update_l4_csum_port16(&tcp->check, old_sport, new_sport);
        return NAT_REWRITE_OK;
    }

    if (ip->protocol == IPPROTO_UDP) {
        if (rem < sizeof(struct udphdr)) {
            return NAT_REWRITE_ERR_LEN;
        }
        struct udphdr *udp = (struct udphdr *)l4;
        uint16_t old_sport = udp->source;
        uint16_t new_sport = conn->nat_port;
        udp->source = new_sport;
        if (udp->check != 0U) {
            update_l4_csum_ip32(&udp->check, old_src_ip, new_src_ip);
            update_l4_csum_port16(&udp->check, old_sport, new_sport);
        }
        return NAT_REWRITE_OK;
    }

    if (ip->protocol == IPPROTO_ICMP) {
        if (rem < sizeof(struct icmphdr)) {
            return NAT_REWRITE_ERR_LEN;
        }
        struct icmphdr *icmp = (struct icmphdr *)l4;
        uint16_t old_id = icmp->un.echo.id;
        uint16_t new_id = conn->nat_port;
        icmp->un.echo.id = new_id;
        icmp->checksum = nat_csum_update16(icmp->checksum, old_id, new_id);
        return NAT_REWRITE_OK;
    }

    return NAT_REWRITE_ERR_PROTO;
}

int nat_rewrite_inbound(uint8_t *pkt, size_t pkt_len,
                      const struct nat_conn *conn) {
    if (!pkt || !conn || pkt_len < sizeof(struct iphdr)) {
        return NAT_REWRITE_ERR_NULL;
    }

    struct iphdr *ip = (struct iphdr *)pkt;
    size_t ihl = (size_t)ip->ihl * 4U;
    if (ihl < sizeof(struct iphdr) || pkt_len < ihl) {
        return NAT_REWRITE_ERR_LEN;
    }

    uint32_t old_dst_ip = ip->daddr;
    uint32_t new_dst_ip = conn->orig.src_ip;
    ip->daddr = new_dst_ip;
    ip->check = nat_csum_update32(ip->check, old_dst_ip, new_dst_ip);

    uint8_t *l4 = pkt + ihl;
    size_t rem = pkt_len - ihl;

    if (ip->protocol == IPPROTO_TCP) {
        if (rem < sizeof(struct tcphdr)) {
            return NAT_REWRITE_ERR_LEN;
        }
        struct tcphdr *tcp = (struct tcphdr *)l4;
        uint16_t old_dport = tcp->dest;
        uint16_t new_dport = conn->orig.src_port;
        tcp->dest = new_dport;
        update_l4_csum_ip32(&tcp->check, old_dst_ip, new_dst_ip);
        update_l4_csum_port16(&tcp->check, old_dport, new_dport);
        return NAT_REWRITE_OK;
    }

    if (ip->protocol == IPPROTO_UDP) {
        if (rem < sizeof(struct udphdr)) {
            return NAT_REWRITE_ERR_LEN;
        }
        struct udphdr *udp = (struct udphdr *)l4;
        uint16_t old_dport = udp->dest;
        uint16_t new_dport = conn->orig.src_port;
        udp->dest = new_dport;
        if (udp->check != 0U) {
            update_l4_csum_ip32(&udp->check, old_dst_ip, new_dst_ip);
            update_l4_csum_port16(&udp->check, old_dport, new_dport);
        }
        return NAT_REWRITE_OK;
    }

    if (ip->protocol == IPPROTO_ICMP) {
        if (rem < sizeof(struct icmphdr)) {
            return NAT_REWRITE_ERR_LEN;
        }
        struct icmphdr *icmp = (struct icmphdr *)l4;
        uint16_t old_id = icmp->un.echo.id;
        uint16_t new_id = conn->orig.src_port;
        icmp->un.echo.id = new_id;
        icmp->checksum = nat_csum_update16(icmp->checksum, old_id, new_id);
        return NAT_REWRITE_OK;
    }

    return NAT_REWRITE_ERR_PROTO;
}
