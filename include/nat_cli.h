#ifndef NAT_CLI_H
#define NAT_CLI_H

#include "nat_ct.h"
#include <stdio.h>

void nat_cli_print_stats(FILE *out, const struct nat_ct_table *ct);
void nat_cli_print_conns(FILE *out, struct nat_ct_table *ct);
void nat_cli_print_json_telemetry(FILE *out, struct nat_ct_table *ct);
int nat_cli_run(int argc, char **argv, struct nat_ct_table *ct);

#endif /* NAT_CLI_H */
