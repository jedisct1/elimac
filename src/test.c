#include "elimac.h"
#include <stdio.h>

int
main(void)
{
    uint8_t key[elimac_KEYBYTES] = { 0 };
    uint8_t msg[65536]           = { 0 };
    uint8_t tag[elimac_MACBYTES];

    elimac_state st;
    if (elimac_init(&st, key, sizeof msg) == -1) {
        return 1;
    }

    const unsigned long long iters = 2500000LL;
    for (unsigned long long i = 0; i < iters; i++) {
        if (elimac_mac(&st, tag, msg, sizeof msg) == -1) {
            return 1;
        }
        msg[0] ^= tag[0];
    }
    for (size_t i = 0; i < elimac_MACBYTES; i++) {
        printf("%02x", tag[i]);
    }
    putchar('\n');

    return 0;
}