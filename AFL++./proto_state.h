#ifndef PROTO_STATE_H
#define PROTO_STATE_H

#include <stdint.h>

/* ---------- Protocol State Machine ---------- */
enum proto_state {
    ST_INIT = 0,
    ST_ORIG_SEEN,
    ST_NEIGH_SEEN,
    ST_BIDIRECTIONAL,
    ST_ROUTING,
    ST_MAX
};

/* ---------- State API ---------- */
void proto_state_reset(void);
void proto_state_hit(enum proto_state s);

/* Compatibility alias for protocol code */
void hit_state(enum proto_state s);

#endif
