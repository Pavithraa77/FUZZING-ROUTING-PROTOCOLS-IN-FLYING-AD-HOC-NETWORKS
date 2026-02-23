#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* Forward declaration from AODV */
void recv_aodv_packet(uint8_t *data, size_t len);

/* Entry point for Honggfuzz */
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {

    if (Size < 4)
        return 0;

    uint8_t *buf = malloc(Size);
    if (!buf)
        return 0;

    memcpy(buf, Data, Size);

    recv_aodv_packet(buf, Size);

    free(buf);
    return 0;
}
