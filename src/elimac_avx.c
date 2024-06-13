#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "elimac.h"

#if !defined(MSC_VER) || _MSC_VER < 1800
#    define __vectorcall
#endif

#define COMPILER_ASSERT(X) (void) sizeof(char[(X) ? 1 : -1])

#ifdef __clang__
#    pragma clang attribute push(__attribute__((target("aes,avx"))), apply_to = function)
#elif defined(__GNUC__)
#    pragma GCC target("aes,avx")
#endif

#include <immintrin.h>

typedef __m128i BlockVec;

#define LOAD128(a)                 _mm_loadu_si128((const BlockVec *) (a))
#define STORE128(a, b)             _mm_storeu_si128((BlockVec *) (a), (b))
#define SET64x2(a, b)              _mm_set_epi64x((uint64_t) (a), (uint64_t) (b))
#define ZERO128                    _mm_setzero_si128()
#define ADD64x2(a, b)              _mm_add_epi64((a), (b))
#define XOR128(a, b)               _mm_xor_si128((a), (b))
#define SHUFFLE32x4(x, a, b, c, d) _mm_shuffle_epi32((x), _MM_SHUFFLE((d), (c), (b), (a)))
#define BYTESHL128(a, b)           _mm_slli_si128(a, b)

#define AES_ENCRYPT(block_vec, rkey)     _mm_aesenc_si128((block_vec), (rkey))
#define AES_ENCRYPTLAST(block_vec, rkey) _mm_aesenclast_si128((block_vec), (rkey))
#define AES_KEYGEN(block_vec, rc)        _mm_aeskeygenassist_si128((block_vec), (rc))

#ifndef elimac_PARALLELISM
#    define elimac_PARALLELISM 10
#endif

#define elimac_H_ROUNDS 7
#define elimac_E_ROUNDS 10
#define elimac_I_ROUNDS 4

typedef struct EliMac {
    BlockVec  i_rks[1 + elimac_I_ROUNDS];
    BlockVec  e_rks[1 + elimac_E_ROUNDS];
    BlockVec *i_keys;
    size_t    max_length;
} EliMac;

#define elimac_STATE_ALIGN 16

static void __vectorcall expand128(BlockVec key, BlockVec *rkeys, const int rounds)
{
    BlockVec s;
    size_t   i = 0;

#define EXPAND_KEY(RC)                            \
    rkeys[i++] = key;                             \
    s          = AES_KEYGEN(key, RC);             \
    key        = XOR128(key, BYTESHL128(key, 4)); \
    key        = XOR128(key, BYTESHL128(key, 8)); \
    key        = XOR128(key, SHUFFLE32x4(s, 3, 3, 3, 3));

    EXPAND_KEY(0x01);
    EXPAND_KEY(0x02);
    EXPAND_KEY(0x04);
    EXPAND_KEY(0x08);
    if (rounds > 4) {
        EXPAND_KEY(0x10);
        EXPAND_KEY(0x20);
        EXPAND_KEY(0x40);
    }
    if (rounds > 7) {
        EXPAND_KEY(0x80);
        EXPAND_KEY(0x1b);
        EXPAND_KEY(0x36);
    }
    rkeys[i++] = key;
}

int
elimac_init(elimac_state *st_, const uint8_t key[elimac_KEYBYTES], size_t max_length)
{
    EliMac *const st = (EliMac *) ((((uintptr_t) &st_->opaque) + (elimac_STATE_ALIGN - 1)) &
                                   ~(uintptr_t) (elimac_STATE_ALIGN - 1));
    COMPILER_ASSERT((sizeof *st) + elimac_STATE_ALIGN <= sizeof *st_);

    if ((max_length >> 32) != 0) {
        errno = E2BIG;
        return -1;
    }
    st->max_length          = max_length;
    const size_t max_blocks = (max_length + 15) / 16;

    st->i_keys = malloc(max_blocks * sizeof(BlockVec));
    if (st->i_keys == NULL) {
        return -1;
    }

    const BlockVec h_key = LOAD128(&key[0]);
    const BlockVec e_key = LOAD128(&key[16]);

    BlockVec h_rks[1 + elimac_H_ROUNDS];
    expand128(h_key, h_rks, elimac_H_ROUNDS);
    expand128(ZERO128, st->i_rks, elimac_I_ROUNDS);
    expand128(e_key, st->e_rks, elimac_E_ROUNDS);

    BlockVec       ctr  = ZERO128;
    const BlockVec incr = SET64x2(0x00010001, 0x00010001);
    for (size_t i = 0; i < max_blocks; i++) {
        BlockVec i_key;

        ctr = ADD64x2(ctr, incr);

        i_key = XOR128(ctr, h_rks[0]);
        for (size_t j = 1; j < elimac_H_ROUNDS - 1; j++) {
            i_key = AES_ENCRYPT(i_key, h_rks[j]);
        }
        i_key = AES_ENCRYPTLAST(i_key, h_rks[elimac_H_ROUNDS]);

        st->i_keys[i] = i_key;
    }
    return 0;
}

void
elimac_free(elimac_state *st_)
{
    EliMac *const st = (EliMac *) ((((uintptr_t) &st_->opaque) + (elimac_STATE_ALIGN - 1)) &
                                   ~(uintptr_t) (elimac_STATE_ALIGN - 1));
    free(st->i_keys);
    st->i_keys = NULL;
}

int
elimac_mac(const elimac_state *st_, uint8_t tag[elimac_MACBYTES], const uint8_t *message,
           size_t length)
{
    const EliMac *const st = (EliMac *) ((((uintptr_t) &st_->opaque) + (elimac_STATE_ALIGN - 1)) &
                                         ~(uintptr_t) (elimac_STATE_ALIGN - 1));

    memset(tag, 0, elimac_MACBYTES);
    if (length > st->max_length) {
        errno = E2BIG;
        return -1;
    }

#if elimac_PARALLELISM > 1

    BlockVec accs[elimac_PARALLELISM];
    for (size_t i = 0; i < elimac_PARALLELISM; i++) {
        accs[i] = ZERO128;
    }

    size_t i = 0;
    for (; i + elimac_PARALLELISM * 16 <= length; i += elimac_PARALLELISM * 16) {
        const BlockVec k = st->i_keys[i / 16];
        BlockVec       kx[elimac_PARALLELISM];

        for (size_t j = 0; j < elimac_PARALLELISM; j++) {
            kx[j] = XOR128(k, LOAD128(&message[i + j * 16]));
            kx[j] = XOR128(kx[j], st->i_rks[0]);
        }
        for (size_t j = 1; j < elimac_I_ROUNDS; j++) {
            for (size_t k = 0; k < elimac_PARALLELISM; k++) {
                kx[k] = AES_ENCRYPT(kx[k], st->i_rks[j]);
            }
        }
        for (size_t j = 0; j < elimac_PARALLELISM; j++) {
            kx[j] = AES_ENCRYPTLAST(kx[j], st->i_rks[elimac_I_ROUNDS]);
        }

        for (size_t j = 0; j < elimac_PARALLELISM; j++) {
            accs[j] = XOR128(accs[j], kx[j]);
        }
    }

    BlockVec acc = accs[0];
    for (size_t j = 1; j < elimac_PARALLELISM; j++) {
        acc = XOR128(acc, accs[j]);
    }

#else
    size_t   i   = 0;
    BlockVec acc = ZERO128;
#endif

    for (; i + 16 <= length; i += 16) {
        const BlockVec k = st->i_keys[i / 16];
        BlockVec       kx;

        kx = XOR128(k, LOAD128(&message[i]));

        kx = XOR128(kx, st->i_rks[0]);
        for (size_t j = 1; j < elimac_I_ROUNDS; j++) {
            kx = AES_ENCRYPT(kx, st->i_rks[j]);
        }
        kx = AES_ENCRYPTLAST(kx, st->i_rks[elimac_I_ROUNDS]);

        acc = XOR128(acc, kx);
    }
    const size_t left       = length - i;
    uint8_t      padded[16] = { 0 };
    memcpy(padded, &message[i], left);
    padded[left] = 0x80;
    acc          = XOR128(acc, LOAD128(padded));

    BlockVec t = XOR128(acc, st->e_rks[0]);
    for (size_t j = 1; j < elimac_E_ROUNDS; j++) {
        t = AES_ENCRYPT(t, st->e_rks[j]);
    }
    t = AES_ENCRYPTLAST(t, st->e_rks[elimac_E_ROUNDS]);

    STORE128(tag, t);

    return 0;
}

#ifdef __clang__
#    pragma clang attribute pop
#endif