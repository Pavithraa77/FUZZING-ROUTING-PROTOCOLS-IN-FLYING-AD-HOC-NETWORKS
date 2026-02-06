#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>

/* ============================================================
 * AFL++ Custom Mutator API
 * ============================================================ */

void *afl_custom_init(void *afl, unsigned int seed) {
    srand(seed);
    return afl;
}

void afl_custom_deinit(void *data) {
    (void)data;
}

/* ============================================================
 * BATMAN OGM Packet Definition
 * ============================================================ */

#define TTL_MAX     64
#define DIRECTLINK  0x40
#define MAX_PKTS    8

typedef struct {
    uint8_t  version;
    uint8_t  flags;
    uint8_t  ttl;
    uint8_t  tq;
    uint16_t seqno;
    uint32_t orig;
    uint32_t prev_sender;
    uint8_t  gwflags;
    uint16_t gwport;
} __attribute__((packed)) bat_packet_t;

/* ============================================================
 * PROTOCOL STATE MODEL (CRITICAL PART)
 * ============================================================ */

typedef enum {
    ST_NEW_ORIG = 0,
    ST_SEEN_ONCE,
    ST_BIDIRECTIONAL,
    ST_GATEWAY
} proto_state_t;

typedef struct {
    proto_state_t state;
    uint32_t last_orig;
    uint16_t last_seqno;
    uint8_t  last_ttl;
} fuzz_state_t;

/* Global fuzzing state */
static fuzz_state_t G = {
    .state = ST_NEW_ORIG,
    .last_orig = 0,
    .last_seqno = 0,
    .last_ttl = 0
};

/* ============================================================
 * SEMANTIC MUTATION FUNCTIONS
 * ============================================================ */

/* -------- Sequence Number Semantics -------- */
static void semantic_seqno(bat_packet_t *pkt) {
    switch (G.state) {
    case ST_NEW_ORIG:
        pkt->seqno = rand() % 4;              /* too small */
        break;

    case ST_SEEN_ONCE:
        pkt->seqno = G.last_seqno - 5;        /* replay */
        break;

    case ST_BIDIRECTIONAL:
        pkt->seqno = G.last_seqno + (rand() % 2); /* edge-valid */
        break;

    case ST_GATEWAY:
        pkt->seqno = 0;                       /* illegal reset */
        break;
    }
}

/* -------- TTL Semantics -------- */
static void semantic_ttl(bat_packet_t *pkt) {
    if (G.state == ST_BIDIRECTIONAL)
        pkt->ttl = 1;                  /* breaks neighbor aging */
    else if (G.state == ST_GATEWAY)
        pkt->ttl = TTL_MAX;            /* persistent gateway */
    else
        pkt->ttl = (rand() % 2) + 1;
}

/* -------- Address Relationship Semantics -------- */
static void semantic_addr(bat_packet_t *pkt) {
    if (G.last_orig == 0)
        pkt->orig = rand();
    else
        pkt->orig = G.last_orig;

    pkt->prev_sender = pkt->orig ^ 0x01010101;

    if (rand() % 4 == 0)
        pkt->prev_sender = pkt->orig;     /* illegal self-loop */

    if (G.state == ST_SEEN_ONCE)
        pkt->orig ^= 0x10000000;           /* identity drift */

    if (G.state == ST_GATEWAY)
        pkt->prev_sender = 0;              /* invalid neighbor */
}

/* -------- Flags Semantics -------- */
static void semantic_flags(bat_packet_t *pkt) {
    pkt->flags = 0;

    if (G.state == ST_BIDIRECTIONAL)
        pkt->flags |= DIRECTLINK;

    if (rand() % 5 == 0)
        pkt->flags ^= DIRECTLINK;          /* contradiction */
}

/* -------- Gateway Semantics -------- */
static void semantic_gateway(bat_packet_t *pkt) {
    if (G.state == ST_GATEWAY) {
        pkt->gwflags = rand() & 0xFF;
        pkt->gwport  = htons(rand() & 0xFFFF);
    } else {
        pkt->gwflags = 0;
        pkt->gwport  = 0;
    }
}

/* ============================================================
 * STATE TRANSITION LOGIC
 * ============================================================ */

static void advance_state(bat_packet_t *pkt) {
    if (pkt->flags & DIRECTLINK)
        G.state = ST_BIDIRECTIONAL;

    if (pkt->gwflags)
        G.state = ST_GATEWAY;

    if (G.state == ST_NEW_ORIG)
        G.state = ST_SEEN_ONCE;

    G.last_seqno = pkt->seqno;
    G.last_orig  = pkt->orig;
    G.last_ttl   = pkt->ttl;
}

/* ============================================================
 * AFL++ CUSTOM FUZZ FUNCTION
 * ============================================================ */

size_t afl_custom_fuzz(
    void *data,
    uint8_t *buf, size_t buf_size,
    uint8_t **out_buf,
    uint8_t *add_buf, size_t add_buf_size,
    size_t max_size
) {
    (void)data;
    (void)add_buf;
    (void)add_buf_size;

    if (buf_size < 1 + sizeof(bat_packet_t))
        return buf_size;

    uint8_t count = buf[0];
    if (count < 1) count = 1;
    if (count > MAX_PKTS) count = MAX_PKTS;

    size_t needed = 1 + count * sizeof(bat_packet_t);
    if (needed > buf_size || needed > max_size)
        return buf_size;

    /* Occasionally grow packet sequence */
    if ((rand() % 10 == 0) && count < MAX_PKTS) {
        buf[0] = ++count;
        memset(buf + 1 + (count - 1) * sizeof(bat_packet_t),
               0, sizeof(bat_packet_t));
    }

    /* Reset protocol state for each input */
    memset(&G, 0, sizeof(G));
    G.state = ST_NEW_ORIG;

    /* Semantic mutation loop */
    for (int i = 0; i < count; i++) {
        bat_packet_t *pkt =
            (bat_packet_t *)(buf + 1 + i * sizeof(bat_packet_t));

        pkt->version = 5;
        pkt->tq = 255;

        semantic_seqno(pkt);
        semantic_ttl(pkt);
        semantic_addr(pkt);
        semantic_flags(pkt);
        semantic_gateway(pkt);

        advance_state(pkt);
    }

    *out_buf = buf;
    return 1 + count * sizeof(bat_packet_t);
}
