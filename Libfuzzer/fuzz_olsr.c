#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>

/* OLSR headers */
#include "../src/olsr.h"
#include "../src/defs.h"
#include "../src/parser.h"

#define MAX_PACKET_SIZE 2048

static uint8_t buffer[MAX_PACKET_SIZE];

/* Minimal fake OLSR core structure */
static struct olsr fake_olsr;

/* Minimal config object */
struct olsrd_config *olsr_cnf;

/* Minimal initialization */
static void init_olsr_state(void) {
    static struct olsrd_config config;
    memset(&config, 0, sizeof(config));
    olsr_cnf = &config;

    memset(&fake_olsr, 0, sizeof(fake_olsr));
}

/* Fuzz one packet */
static void fuzz_one_input(uint8_t *data, size_t len) {

    if (len == 0 || len > MAX_PACKET_SIZE)
        return;

    /* Call real OLSR parser */
    parse_packet(&fake_olsr, (int)len, NULL, NULL);
}

int main(void) {

    init_olsr_state();

    while (__AFL_LOOP(1000)) {

        ssize_t len = read(0, buffer, sizeof(buffer));
        if (len <= 0)
            break;

        fuzz_one_input(buffer, (size_t)len);
    }

    return 0;
}