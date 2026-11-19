#ifndef NAT_REWRITE_H
#define NAT_REWRITE_H

#include "nat_ct.h"
#include "nat_state.h"
#include <stddef.h>
#include <stdint.h>

typedef enum {
    NAT_REWRITE_OK = 0,
    NAT_REWRITE_ERR_LEN = -1,
    NAT_REWRITE_ERR_PROTO = -2,
    NAT_REWRITE_ERR_NULL = -3
} nat_rewrite_status_t;

int nat_extract_tuple(const uint8_t *pkt, size_t pkt_len,
                      struct nat_tuple *out_tuple,
                      uint8_t *out_tcp_flags,
                      size_t *out_l4_offset);

int nat_rewrite_outbound(uint8_t *pkt, size_t pkt_len,
                       const struct nat_conn *conn);

int nat_rewrite_inbound(uint8_t *pkt, size_t pkt_len,
                      const struct nat_conn *conn);

#endif /* NAT_REWRITE_H */
