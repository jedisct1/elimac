#ifndef elimac_H
#define elimac_H

#define elimac_KEYBYTES 32
#define elimac_MACBYTES 16

#include <stdint.h>
#include <stdlib.h>

typedef struct elimac_state {
    uint8_t opaque[1024];
} elimac_state;

int elimac_init(elimac_state *st_, const uint8_t key[elimac_KEYBYTES], size_t max_length);

void elimac_free(elimac_state *st_);

int elimac_mac(const elimac_state *st_, uint8_t tag[elimac_MACBYTES], const uint8_t *message,
               size_t length);

#endif