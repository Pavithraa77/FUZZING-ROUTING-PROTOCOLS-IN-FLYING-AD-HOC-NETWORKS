#include <stdint.h>
#include <unistd.h>
#include <string.h>

/* Core packet entry */
extern void fuzz_handle_ogm(unsigned char *buf, int len);

/* Real batmand internal functions */
extern void purge_orig(void);
extern void send_outstanding_packets(void);

#define MAX_PKTS 32
#define MAX_PKT_SIZE 512
#define SIM_TICKS 5

int main(void)
{
    uint8_t buf[4096];
    ssize_t len = read(0, buf, sizeof(buf));
    if (len <= 1)
        return 0;

    uint8_t pkt_count = buf[0];
    if (pkt_count == 0 || pkt_count > MAX_PKTS)
        return 0;

    uint8_t *ptr = buf + 1;
    uint8_t *end = buf + len;

    /* Process input packets */
    for (uint8_t i = 0; i < pkt_count; i++) {

        if (ptr + 2 > end)
            break;

        uint16_t pkt_len = (ptr[0] << 8) | ptr[1];
        ptr += 2;

        if (pkt_len > MAX_PKT_SIZE)
            return 0;

        if (ptr + pkt_len > end)
            break;

        fuzz_handle_ogm(ptr, pkt_len);
        ptr += pkt_len;
    }

    /* Simulate daemon evolution */
    for (int i = 0; i < SIM_TICKS; i++) {

        purge_orig();
        send_outstanding_packets();
    }

    return 0;
}
