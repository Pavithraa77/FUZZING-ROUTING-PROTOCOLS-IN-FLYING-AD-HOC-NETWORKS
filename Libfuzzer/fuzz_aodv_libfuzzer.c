#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <arpa/inet.h>

/* AODV headers */
#include "../aodv_rreq.h"
#include "../aodv_rrep.h"
#include "../aodv_rerr.h"
#include "../routing_table.h"

/* ========================= */
/* Global variables normally */
/* defined in main.c         */
/* ========================= */

int log_to_file = 0;
int rt_log_interval = 0;
char *progname = "libfuzzer_aodv";

/* Protocol configuration flags */
int delete_period = 0;
int active_route_timeout = 3000;
int ttl_start = 1;
int rreq_gratuitous = 0;
int expanding_ring_search = 0;
int optimized_hellos = 0;
int llfeedback = 0;
int unidir_hack = 0;

/* ========================= */
/* Stub runtime functions    */
/* ========================= */

void *aodv_socket_new_msg(int size) {
    return malloc(size);
}

int aodv_socket_send(void *msg, int len, struct in_addr dst, int ttl) {
    return 0;
}

int aodv_socket_queue_msg(void *msg, int len, struct in_addr dst) {
    return 0;
}

void route_expire_timeout(void *data) {}
void route_delete_timeout(void *data) {}
void local_repair_timeout(void *data) {}
void route_discovery_timeout(void *data) {}
void rrep_ack_timeout(void *data) {}
void hello_timeout(void *data) {}

void neighbor_link_break(struct in_addr addr) {}
void hello_start(void) {}

void nl_send_add_route_msg(void *rt) {}
void nl_send_del_route_msg(void *rt) {}

/* ========================= */
/* One-time initialization   */
/* ========================= */

static int initialized = 0;

static void fuzz_init(void)
{
    if (initialized)
        return;

    rt_table_init();   /* Critical fix */
    initialized = 1;
}

/* ========================= */
/* libFuzzer Entry Point     */
/* ========================= */

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    fuzz_init();

    if (size < 4 || size > 1500)
        return 0;

    struct in_addr src, dst;
    src.s_addr = inet_addr("10.0.0.1");
    dst.s_addr = inet_addr("10.0.0.2");

    uint8_t type = data[0];

    switch (type)
{
    case 1:
        if (size >= sizeof(RREQ))
            rreq_process((RREQ *)data, size, src, dst, 1, 0);
        break;

    case 2:
        if (size >= sizeof(RREP))
            rrep_process((RREP *)data, size, src, dst, 1, 0);
        break;

    case 3:
        if (size >= sizeof(RERR))
            rerr_process((RERR *)data, size, src, dst);
        break;

    default:
        break;
}

    return 0;
}