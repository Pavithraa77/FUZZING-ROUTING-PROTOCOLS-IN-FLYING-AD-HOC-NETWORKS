#include <stdint.h>
#include <stddef.h>

#include "packet.h"
#include "proto_state.h"
#include "fuzz_proto.h"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    if (Size < 1)
        return 0;

    proto_state_reset();   /* CRITICAL */

    const uint8_t *ptr = Data;
    const uint8_t *end = Data + Size;

    uint8_t count = *ptr++;
    if (count == 0 || count > 16)
        return 0;

    for (uint8_t i = 0; i < count; i++) {
        if (ptr + sizeof(struct bat_packet) > end)
            break;

        fuzz_handle_ogm((unsigned char *)ptr,
                        sizeof(struct bat_packet));

        ptr += sizeof(struct bat_packet);
    }

    return 0;
}
