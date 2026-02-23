#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#define MAX_PKTS 16

/* ---------- INIT ---------- */
void *afl_custom_init(void *afl, unsigned int seed)
{
    srand(seed);
    return afl;
}

void afl_custom_deinit(void *data)
{
    (void)data;
}

/* ---------- Structural Byte Mutation ---------- */
static void structural_mutate(uint8_t *data, size_t len)
{
    if (!len) return;

    size_t off = rand() % len;

    switch(rand() % 4) {
        case 0: data[off] ^= 0xFF; break;
        case 1: data[off] += 1; break;
        case 2: data[off] = 0; break;
        case 3: data[off] ^= (1 << (rand()%8)); break;
    }
}

/* ---------- Stateful Sequence Mutation ---------- */
static void sequence_mutate(uint8_t *buf, size_t *len)
{
    if (*len < 4) return;

    uint8_t pkt_count = buf[0];
    if (!pkt_count) pkt_count = 1;
    if (pkt_count > MAX_PKTS) pkt_count = MAX_PKTS;

    size_t pos = 1;

    for (uint8_t i = 0; i < pkt_count; i++) {

        if (pos + 2 > *len)
            break;

        uint16_t plen = (buf[pos] << 8) | buf[pos+1];
        pos += 2;

        if (pos + plen > *len)
            break;

        /* 50% mutate packet */
        if (rand() % 2)
            structural_mutate(buf + pos, plen);

        pos += plen;
    }

    /* Occasionally grow sequence */
    if ((rand() % 6) == 0 && pkt_count < MAX_PKTS) {

        size_t new_pos = *len;

        if (new_pos + 10 < 4096) {
            buf[0]++;

            buf[new_pos++] = 0;
            buf[new_pos++] = 8;

            for (int i = 0; i < 8; i++)
                buf[new_pos++] = rand();

            *len = new_pos;
        }
    }
}

/* ---------- AFL FUZZ ENTRY ---------- */
size_t afl_custom_fuzz(
    void *data,
    uint8_t *buf, size_t buf_size,
    uint8_t **out_buf,
    uint8_t *add_buf, size_t add_buf_size,
    size_t max_size
)
{
    (void)data;
    (void)add_buf;
    (void)add_buf_size;
    (void)max_size;

    if (buf_size < 4)
        return buf_size;

    sequence_mutate(buf, &buf_size);

    *out_buf = buf;
    return buf_size;
}

/* Optional hook */
void afl_custom_queue_new_entry(
    void *data,
    const uint8_t *filename_new_queue,
    const uint8_t *filename_orig_queue
)
{
    (void)data;
    (void)filename_new_queue;
    (void)filename_orig_queue;
}
