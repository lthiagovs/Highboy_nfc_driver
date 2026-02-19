/**
 * @file crypto1.c
 * @brief Crypto1 cipher for MIFARE Classic — exact port of Flipper Zero / proxmark3.
 *
 * This is a line-by-line port of the Flipper Zero firmware's crypto1 implementation:
 *   https://github.com/flipperdevices/flipperzero-firmware
 *   lib/nfc/helpers/crypto1.c
 *
 * Key design decisions (all matching Flipper Zero):
 *   1. Split odd/even LFSR representation (24 bits each).
 *   2. LF_POLY_ODD / LF_POLY_EVEN constants (NOT a single 48-bit polynomial).
 *   3. crypto1_filter uses the compact 5-stage lookup table approach.
 *   4. BEBIT macro in crypto1_word for byte-swapped bit ordering.
 *   5. SWAPENDIAN in prng_successor.
 *   6. crypto1_filter_output() reads filter WITHOUT advancing LFSR
 *      (used for parity bit encryption — the 9th keystream bit per byte).
 */
#include "crypto1.h"

/* ── Macros matching proxmark3 / Flipper Zero ── */

#define SWAPENDIAN(x) \
    ((x) = ((x) >> 8 & 0xff00ffU) | ((x) & 0xff00ffU) << 8, \
     (x) = (x) >> 16 | (x) << 16)

#define BIT(x, n)   (((x) >> (n)) & 1U)
#define BEBIT(x, n) BIT((x), (n) ^ 24)

#define LF_POLY_ODD  (0x29CE5CU)
#define LF_POLY_EVEN (0x870804U)

/* ── Parity helpers ── */

static const uint8_t s_odd_parity_table[256] = {
    1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
    0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
    0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
    1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
    0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
    1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
    1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
    0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
    0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
    1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
    1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
    0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
    1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
    0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
    0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
    1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1
};

uint8_t crypto1_odd_parity8(uint8_t data)
{
    return s_odd_parity_table[data];
}

uint8_t crypto1_even_parity32(uint32_t data)
{
    data ^= data >> 16;
    data ^= data >> 8;
    return (uint8_t)(!s_odd_parity_table[data & 0xFF]);
}

/* ── Filter function (compact proxmark3 style) ── */

static uint32_t crypto1_filter(uint32_t in)
{
    uint32_t out = 0;
    out  = 0xf22c0U >> (in        & 0xfU) & 16U;
    out |= 0x6c9c0U >> (in >>  4  & 0xfU) &  8U;
    out |= 0x3c8b0U >> (in >>  8  & 0xfU) &  4U;
    out |= 0x1e458U >> (in >> 12  & 0xfU) &  2U;
    out |= 0x0d938U >> (in >> 16  & 0xfU) &  1U;
    return BIT(0xEC57E80AU, out);
}

/* ── Public API ── */

void crypto1_init(crypto1_state_t *s, uint64_t key)
{
    s->even = 0;
    s->odd  = 0;
    for (int8_t i = 47; i > 0; i -= 2) {
        s->odd  = s->odd  << 1 | BIT(key, (unsigned)((i - 1) ^ 7));
        s->even = s->even << 1 | BIT(key, (unsigned)(i ^ 7));
    }
}

void crypto1_reset(crypto1_state_t *s)
{
    s->odd  = 0;
    s->even = 0;
}

uint8_t crypto1_bit(crypto1_state_t *s, uint8_t in, int is_encrypted)
{
    uint8_t  out  = (uint8_t)crypto1_filter(s->odd);
    uint32_t feed = out & (uint32_t)(!!is_encrypted);
    feed ^= (uint32_t)(!!in);
    feed ^= LF_POLY_ODD  & s->odd;
    feed ^= LF_POLY_EVEN & s->even;
    s->even = s->even << 1 | crypto1_even_parity32(feed);

    /* Swap odd ↔ even */
    uint32_t tmp = s->odd;
    s->odd  = s->even;
    s->even = tmp;

    return out;
}

uint8_t crypto1_byte(crypto1_state_t *s, uint8_t in, int is_encrypted)
{
    uint8_t out = 0;
    for (uint8_t i = 0; i < 8; i++) {
        out |= (uint8_t)(crypto1_bit(s, BIT(in, i), is_encrypted) << i);
    }
    return out;
}

/**
 * crypto1_word — clock 32 bits in BEBIT order.
 *
 * BEBIT(x, i) = bit ((i) ^ 24) of x.
 * This processes bytes in MSB-first order but bits within each byte LSB-first.
 * Output uses the same byte-swapped convention (<< (24 ^ i)).
 *
 * This is identical to the Flipper Zero / proxmark3 implementation.
 */
uint32_t crypto1_word(crypto1_state_t *s, uint32_t in, int is_encrypted)
{
    uint32_t out = 0;
    for (uint8_t i = 0; i < 32; i++) {
        out |= (uint32_t)crypto1_bit(s, BEBIT(in, i), is_encrypted) << (24 ^ i);
    }
    return out;
}

/**
 * crypto1_filter_output — read keystream bit WITHOUT advancing LFSR.
 *
 * Used for encrypted parity: after clocking 8 data bits with crypto1_byte,
 * call this to get the parity keystream bit without disturbing the LFSR state.
 * This matches how the Flipper Zero handles parity in crypto1_encrypt().
 */
uint8_t crypto1_filter_output(crypto1_state_t *s)
{
    return (uint8_t)crypto1_filter(s->odd);
}

/**
 * prng_successor — MIFARE Classic card PRNG.
 *
 * CRITICAL: SWAPENDIAN before and after computation!
 * The Flipper Zero does this and without it the ar/at values are wrong.
 *
 * Input/output are in big-endian (wire) byte order.
 */
uint32_t crypto1_prng_successor(uint32_t x, uint32_t n)
{
    SWAPENDIAN(x);
    while (n--)
        x = x >> 1 | (x >> 16 ^ x >> 18 ^ x >> 19 ^ x >> 21) << 31;
    return SWAPENDIAN(x);
}
