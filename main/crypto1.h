/**
 * @file crypto1.h
 * @brief Crypto1 cipher for MIFARE Classic.
 *
 * TODO: LFSR implementation, encrypt/decrypt, parity generation.
 */
#ifndef CRYPTO1_H
#define CRYPTO1_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint64_t state;
} crypto1_state_t;

void crypto1_init(crypto1_state_t* s, uint64_t key);
uint8_t crypto1_bit(crypto1_state_t* s, uint8_t in, int is_encrypted);
uint8_t crypto1_byte(crypto1_state_t* s, uint8_t in, int is_encrypted);
void crypto1_encrypt(crypto1_state_t* s, uint8_t* data, size_t len);
void crypto1_decrypt(crypto1_state_t* s, uint8_t* data, size_t len);

#endif
