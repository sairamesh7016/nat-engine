#include "nat_state.h"
#include <netinet/in.h>

nat_conn_state_t nat_state_tcp_step(nat_conn_state_t current,
                                     uint8_t tcp_flags,
                                     bool outbound) {
    if (tcp_flags & NAT_TCP_RST) {
        return NAT_STATE_CLOSED;
    }

    switch (current) {
        case NAT_STATE_NEW:
            if (outbound && (tcp_flags & NAT_TCP_SYN) && !(tcp_flags & NAT_TCP_ACK)) {
                return NAT_STATE_SYN_SENT;
            }
            if (tcp_flags & NAT_TCP_ACK) {
                return NAT_STATE_ESTABLISHED;
            }
            return NAT_STATE_NEW;

        case NAT_STATE_SYN_SENT:
            if (!outbound && (tcp_flags & NAT_TCP_SYN) && (tcp_flags & NAT_TCP_ACK)) {
                return NAT_STATE_ESTABLISHED;
            }
            if (outbound && (tcp_flags & NAT_TCP_ACK) && !(tcp_flags & NAT_TCP_SYN)) {
                return NAT_STATE_ESTABLISHED;
            }
            return NAT_STATE_SYN_SENT;

        case NAT_STATE_ESTABLISHED:
            if (tcp_flags & NAT_TCP_FIN) {
                return NAT_STATE_FIN_WAIT;
            }
            return NAT_STATE_ESTABLISHED;

        case NAT_STATE_FIN_WAIT:
            if ((tcp_flags & NAT_TCP_FIN) || (tcp_flags & NAT_TCP_ACK)) {
                return NAT_STATE_TIME_WAIT;
            }
            return NAT_STATE_FIN_WAIT;

        case NAT_STATE_TIME_WAIT:
            return NAT_STATE_TIME_WAIT;

        case NAT_STATE_CLOSED:
        default:
            return NAT_STATE_CLOSED;
    }
}

void nat_state_update_conn(struct nat_conn *conn,
                           uint8_t tcp_flags,
                           bool outbound,
                           time_t now) {
    if (!conn) {
        return;
    }
    conn->last_seen = now;

    if (conn->orig.proto == IPPROTO_TCP) {
        conn->state = nat_state_tcp_step(conn->state, tcp_flags, outbound);
    } else if (conn->orig.proto == IPPROTO_UDP || conn->orig.proto == IPPROTO_ICMP) {
        conn->state = NAT_STATE_ESTABLISHED;
    }
}

const char *nat_state_name(nat_conn_state_t state) {
    switch (state) {
        case NAT_STATE_NEW:         return "NEW";
        case NAT_STATE_SYN_SENT:    return "SYN_SENT";
        case NAT_STATE_ESTABLISHED: return "ESTABLISHED";
        case NAT_STATE_FIN_WAIT:    return "FIN_WAIT";
        case NAT_STATE_TIME_WAIT:   return "TIME_WAIT";
        case NAT_STATE_CLOSED:      return "CLOSED";
        default:                    return "UNKNOWN";
    }
}
