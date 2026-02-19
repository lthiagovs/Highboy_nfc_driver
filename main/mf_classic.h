/**
 * @file mf_classic.h
 * @brief MIFARE Classic — auth, read, write sectors (Phase 7).
 */
#ifndef MF_CLASSIC_H
#define MF_CLASSIC_H

#include <stdint.h>
#include "highboy_nfc_types.h"
#include "highboy_nfc_error.h"

/** Authenticate a sector with key A or B. */
hb_nfc_err_t mf_classic_auth(uint8_t block, mf_key_type_t key_type,
                               const mf_classic_key_t* key,
                               const uint8_t uid[4]);

/** Read a single block (16 bytes). Must be authenticated first. */
hb_nfc_err_t mf_classic_read_block(uint8_t block, uint8_t data[16]);

/** Write a single block (16 bytes). Must be authenticated first. */
hb_nfc_err_t mf_classic_write_block(uint8_t block, const uint8_t data[16]);

/** Get card type from SAK. */
mf_classic_type_t mf_classic_get_type(uint8_t sak);

/** Get number of sectors for a given type. */
int mf_classic_get_sector_count(mf_classic_type_t type);

#endif
