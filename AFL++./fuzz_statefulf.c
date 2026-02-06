#include <unistd.h>
#include <stdint.h>
#include <string.h>

#include "packet.h"
#include "proto_state.h"

/* protocol callback */
extern void fuzz_handle_ogm(unsigned char *buf, int len);

#define MAX_PKTS 32

int main(void) {

    unsigned char buf[4096];
    ssize_t len = read(0, buf, sizeof(buf));
    if (len <= 1)
        return 0;

    proto_state_reset();

    uint8_t pkt_count = buf[0];
    if (pkt_count == 0 || pkt_count > MAX_PKTS)
        return 0;

    unsigned char *ptr = buf + 1;
    unsigned char *end = buf + len;

    for (uint8_t i = 0; i < pkt_count; i++) {

        if (ptr + sizeof(struct bat_packet) > end)
            break;

        fuzz_handle_ogm(ptr, sizeof(struct bat_packet));
        ptr += sizeof(struct bat_packet);
    }

    return 0;
}

