#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include "../aodv_rreq.h"
#include "../aodv_rrep.h"
#include "../aodv_rerr.h"
#include "../routing_table.h"

/* ========================= */
/* Global config variables   */
/* ========================= */

int log_to_file = 0;
int rt_log_interval = 0;
char *progname = "afl_aodv";

int delete_period = 0;
int active_route_timeout = 3000;
int ttl_start = 1;
int rreq_gratuitous = 0;
int expanding_ring_search = 0;
int optimized_hellos = 0;
int llfeedback = 0;
int unidir_hack = 0;

/* ========================= */
/* Stubbed runtime functions */
/* ========================= */

void *aodv_socket_new_msg(int size) { return malloc(size); }
int aodv_socket_send(void *msg, int len, struct in_addr dst, int ttl) { return 0; }
int aodv_socket_queue_msg(void *msg, int len, struct in_addr dst) { return 0; }

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
/* Initialization            */
/* ========================= */

static int initialized = 0;

static void fuzz_init(void)
{
    if (!initialized) {
        rt_table_init();
        initialized = 1;
    }
}

/* ========================= */
/* AFL Persistent Harness    */
/* ========================= */

int main(void)
{
    fuzz_init();

    static uint8_t buf[4096];

#ifdef __AFL_HAVE_MANUAL_CONTROL
    __AFL_INIT();
#endif

    while (__AFL_LOOP(1000))
    {
        ssize_t len = read(0, buf, sizeof(buf));
        if (len <= 0)
            continue;

        if (len < 4 || len > 4096)
            continue;

        struct in_addr src, dst;
        src.s_addr = inet_addr("10.0.0.1");
        dst.s_addr = inet_addr("10.0.0.2");

        /* ------------------------------
           Sequence format:
           [pkt_count]
           [len_hi][len_lo][pkt]
           ...
        -------------------------------- */

        uint8_t pkt_count = buf[0];
        if (pkt_count == 0)
            pkt_count = 1;
        if (pkt_count > 16)
            pkt_count = 16;

        size_t pos = 1;

        for (uint8_t i = 0; i < pkt_count; i++)
        {
            if (pos + 2 > len)
                break;

            uint16_t plen = (buf[pos] << 8) | buf[pos + 1];
            pos += 2;

            if (plen == 0 || pos + plen > len)
                break;

            uint8_t *pkt = buf + pos;

            /* Ensure packet type valid */
            uint8_t type = pkt[0];

            switch (type)
            {
                case 1:
                    if (plen >= sizeof(RREQ))
                        rreq_process((RREQ *)pkt, plen, src, dst, 1, 0);
                    break;

                case 2:
                    if (plen >= sizeof(RREP))
                        rrep_process((RREP *)pkt, plen, src, dst, 1, 0);
                    break;

                case 3:
                    if (plen >= sizeof(RERR))
                        rerr_process((RERR *)pkt, plen, src, dst);
                    break;

                default:
                    break;
            }

            pos += plen;
        }
    }

    return 0;
}