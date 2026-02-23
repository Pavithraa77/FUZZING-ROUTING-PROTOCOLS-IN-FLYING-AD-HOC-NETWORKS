#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "../src/olsr_protocol.h"

#define MAX_PACKET 4096

/*
 * Minimal OLSR packet parser harness
 * Designed for honggfuzz (stdin-based fuzzing)
 */

static void parse_olsr_packet(const uint8_t *data, size_t len) {

    if (len < sizeof(struct olsr))
        return;

    const struct olsr *packet = (const struct olsr *)data;

    uint16_t pkt_len = ntohs(packet->olsr_packlen);

    if (pkt_len > len || pkt_len < sizeof(struct olsr))
        return;

    const uint8_t *ptr = (const uint8_t *)&packet->olsr_msg[0];
    const uint8_t *end = data + pkt_len;

    while (ptr + sizeof(struct olsrmsg) <= end) {

        const struct olsrmsg *msg = (const struct olsrmsg *)ptr;

        uint16_t msg_len = ntohs(msg->olsr_msgsize);

        if (msg_len < sizeof(struct olsrmsg))
            break;

        if (ptr + msg_len > end)
            break;

        /* Touch important fields to exercise structure */
        volatile uint8_t type = msg->olsr_msgtype;
        volatile uint8_t ttl  = msg->ttl;
        volatile uint16_t seq = ntohs(msg->seqno);

        (void)type;
        (void)ttl;
        (void)seq;

        ptr += msg_len;
    }
}

int main(void) {

    uint8_t buf[MAX_PACKET];

    for (;;) {
        ssize_t len = read(STDIN_FILENO, buf, sizeof(buf));
        if (len <= 0)
            break;

        parse_olsr_packet(buf, (size_t)len);
    }

    return 0;
}
