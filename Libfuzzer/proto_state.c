#include "proto_state.h"

/* Current protocol state */
static enum proto_state current_state = ST_INIT;

void proto_state_reset(void)
{
    current_state = ST_INIT;
}

void proto_state_hit(enum proto_state s)
{
    if (s > current_state)
        current_state = s;
}
enum proto_state proto_state_get(void)
{
    return current_state;
}



/* Alias used by protocol code (batman.c) */
void hit_state(enum proto_state s)
{
    proto_state_hit(s);
}
