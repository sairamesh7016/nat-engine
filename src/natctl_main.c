#include "nat_cli.h"
#include <arpa/inet.h>

int main(int argc, char **argv) {
    struct nat_ct_table ct;
    if (nat_ct_init(&ct, NAT_HASH_BUCKETS_DEFAULT, inet_addr("203.0.113.10")) != 0) {
        return 1;
    }
    int rc = nat_cli_run(argc, argv, &ct);
    nat_ct_destroy(&ct);
    return rc;
}
