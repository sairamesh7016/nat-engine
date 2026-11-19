#ifndef NAT_STATE_H
#define NAT_STATE_H

#include "nat_common.h"

/* TCP flag bitmasks (in network byte order when read from wire) */
#define NAT_TCP_FIN 0x01U
#define NAT_TCP_SYN 0x02U
#define NAT_TCP_RST 0x04U
#define NAT_TCP_PSH 0x08U
#define NAT_TCP_ACK 0x10U
#define NAT_TCP_URG 0x20U

nat_conn_state_t nat_state_tcp_step(nat_conn_state_t current,
                                     uint8_t tcp_flags,
                                     bool outbound);

void nat_state_update_conn(struct nat_conn *conn,
                           uint8_t tcp_flags,
                           bool outbound,
                           time_t now);

const char *nat_state_name(nat_conn_state_t state);

#endif /* NAT_STATE_H */
