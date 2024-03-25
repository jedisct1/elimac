#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "elimac.h"

#if !defined(MSC_VER) || _MSC_VER < 1800
#    define __vectorcall
#endif

#define COMPILER_ASSERT(X) (void) sizeof(char[(X) ? 1 : -1])

#if !(defined(__aarch64__) || defined(_M_ARM64))
#    error "Unsupported architecture"
#endif

#ifndef __ARM_FEATURE_CRYPTO
#    define __ARM_FEATURE_CRYPTO 1
#endif
#ifndef __ARM_FEATURE_AES
#    define __ARM_FEATURE_AES 1
#endif

#include <arm_neon.h>

#ifdef __clang__
#    pragma clang attribute push(__attribute__((target("neon,crypto,aes"))), apply_to = function)
#elif defined(__GNUC__)
#    pragma GCC target("+simd+crypto")
#endif

typedef uint64x2_t BlockVec;

#define LOAD128(a)     vld1q_u64((const uint64_t *) (const void *) (a))
#define STORE128(a, b) vst1q_u64((uint64_t *) (void *) (a), (b))
#define SET64x2(a, b)  vsetq_lane_u64((uint64_t) (a), vmovq_n_u64((uint64_t) (b)), 1)
#define ZERO128        vmovq_n_u8(0)
#define ADD64x2(a, b)  vaddq_u64((a), (b))
#define XOR128(a, b)   veorq_u64((a), (b))
#define SHUFFLE32x4(x, a, b, c, d)                                          \
    vreinterpretq_u64_u32(__builtin_shufflevector(vreinterpretq_u32_u64(x), \
                                                  vreinterpretq_u32_u64(x), (a), (b), (c), (d)))
#define BYTESHL128(a, b) vreinterpretq_u64_u8(vextq_s8(vdupq_n_s8(0), (int8x16_t) a, 16 - (b)))

#define AES_XENCRYPT(block_vec, rkey) \
    vreinterpretq_u64_u8(vaesmcq_u8(vaeseq_u8(vreinterpretq_u8_u64(block_vec), rkey)))
#define AES_XENCRYPTLAST(block_vec, rkey) \
    vreinterpretq_u64_u8(vaeseq_u8(vreinterpretq_u8_u64(block_vec), rkey))

static inline BlockVec
AES_KEYGEN(BlockVec block_vec, const int rc)
{
    uint8x16_t       a = vaeseq_u8(vreinterpretq_u8_u64(block_vec), vmovq_n_u8(0));
    const uint8x16_t b =
        __builtin_shufflevector(a, a, 4, 1, 14, 11, 1, 14, 11, 4, 12, 9, 6, 3, 9, 6, 3, 12);
    const uint64x2_t c = SET64x2((uint64_t) rc << 32, (uint64_t) rc << 32);
    return XOR128(b, c);
}

#ifndef elimac_PARALLELISM
#    define elimac_PARALLELISM 8
#endif

#define elimac_H_ROUNDS 7
#define elimac_E_ROUNDS 10
#define elimac_I_ROUNDS 4

typedef struct EliMac {
    BlockVec  e_rks[1 + elimac_E_ROUNDS];
    BlockVec  i_rks[1 + elimac_I_ROUNDS];
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
        ctr            = ADD64x2(ctr, incr);
        BlockVec i_key = AES_XENCRYPT(ctr, h_rks[0]);
        for (size_t j = 1; j < elimac_H_ROUNDS - 1; j++) {
            i_key = AES_XENCRYPT(i_key, h_rks[j]);
        }
        i_key         = AES_XENCRYPTLAST(i_key, h_rks[elimac_H_ROUNDS - 1]);
        i_key         = XOR128(i_key, h_rks[elimac_H_ROUNDS]);
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
            kx[j] = AES_XENCRYPT(kx[j], st->i_rks[0]);
        }
        for (size_t j = 1; j < elimac_I_ROUNDS - 1; j++) {
            for (size_t k = 0; k < elimac_PARALLELISM; k++) {
                kx[k] = AES_XENCRYPT(kx[k], st->i_rks[j]);
            }
        }
        for (size_t j = 0; j < elimac_PARALLELISM; j++) {
            kx[j] = AES_XENCRYPTLAST(kx[j], st->i_rks[elimac_I_ROUNDS - 1]);
            kx[j] = XOR128(kx[j], st->i_rks[elimac_I_ROUNDS]);
        }
        for (size_t j = 0; j < elimac_PARALLELISM; j++) {
            accs[j] = XOR128(accs[j], kx[j]);
        }
    }

    BlockVec acc = accs[0];
    for (size_t j = 1; j < elimac_PARALLELISM; j++) {
        acc = XOR128(acc, accs[j]);
    }
    for (; i + 16 <= length; i += 16) {
        const BlockVec k = st->i_keys[i / 16];
        BlockVec       kx;

        kx = XOR128(k, LOAD128(&message[i]));
        kx = AES_XENCRYPT(kx, st->i_rks[0]);
        for (size_t j = 1; j < elimac_I_ROUNDS - 1; j++) {
            kx = AES_XENCRYPT(kx, st->i_rks[j]);
        }
        kx  = AES_XENCRYPTLAST(kx, st->i_rks[elimac_I_ROUNDS - 1]);
        kx  = XOR128(kx, st->i_rks[elimac_I_ROUNDS]);
        acc = XOR128(acc, kx);
    }
    const size_t left       = length - i;
    uint8_t      padded[16] = { 0 };
    memcpy(padded, &message[i], left);
    padded[left] = 0x80;
    {
        const BlockVec k = st->i_keys[i / 16];
        BlockVec       kx;

        kx = XOR128(k, LOAD128(padded));
        kx = AES_XENCRYPT(kx, st->i_rks[0]);
        for (size_t j = 1; j < elimac_I_ROUNDS - 1; j++) {
            kx = AES_XENCRYPT(kx, st->i_rks[j]);
        }
        kx  = AES_XENCRYPTLAST(kx, st->i_rks[elimac_I_ROUNDS - 1]);
        kx  = XOR128(kx, st->i_rks[elimac_I_ROUNDS]);
        acc = XOR128(acc, kx);
    }

    BlockVec t;
    t = AES_XENCRYPT(acc, st->e_rks[0]);
    for (size_t j = 1; j < elimac_E_ROUNDS - 1; j++) {
        t = AES_XENCRYPT(t, st->e_rks[j]);
    }
    t = AES_XENCRYPTLAST(t, st->e_rks[elimac_E_ROUNDS - 1]);
    t = XOR128(t, st->e_rks[elimac_E_ROUNDS]);
    STORE128(tag, t);

    return 0;
}

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

    const unsigned long long iters = 100000000LL;
    for (unsigned long long i = 0; i < iters; i++) {
        if (elimac_mac(&st, tag, msg, 1) == -1) {
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

#ifdef __clang__
#    pragma clang attribute pop
#endif