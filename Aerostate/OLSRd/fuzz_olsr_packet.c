#include <stdint.h>
#include <stddef.h>

void fuzz_parse_packet(uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {

    fuzz_parse_packet((uint8_t *)Data, Size);

    return 0;
}
