/**
 * @file crypto1.c
 * @brief Crypto1 — stub.
 *
 * TODO: Implement LFSR (48-bit), filter function,
 *       encrypt/decrypt, parity attack support.
 */
#include "crypto1.h"

void crypto1_init(crypto1_state_t* s, uint64_t key)
{
    s->state = key & 0xFFFFFFFFFFFFULL;
}

uint8_t crypto1_bit(crypto1_state_t* s, uint8_t in, int is_encrypted)
{
    (void)in; (void)is_encrypted;
    /* TODO: implement LFSR step + filter */
    return (uint8_t)(s->state & 1);
}

uint8_t crypto1_byte(crypto1_state_t* s, uint8_t in, int is_encrypted)
{
    uint8_t out = 0;
    for (int i = 0; i < 8; i++) {
        out |= (crypto1_bit(s, (in >> i) & 1, is_encrypted) << i);
    }
    return out;
}

void crypto1_encrypt(crypto1_state_t* s, uint8_t* data, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        data[i] ^= crypto1_byte(s, 0, 0);
    }
}

void crypto1_decrypt(crypto1_state_t* s, uint8_t* data, size_t len)
{
    crypto1_encrypt(s, data, len);  /* XOR is symmetric */
}
