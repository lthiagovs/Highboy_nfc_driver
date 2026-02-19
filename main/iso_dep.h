/**
 * @file iso_dep.h
 * @brief ISO-DEP (ISO14443-4) — RATS, I-Block, chaining (Phase 6).
 */
#ifndef ISO_DEP_H
#define ISO_DEP_H

#include <stdint.h>
#include <stddef.h>
#include "highboy_nfc_error.h"
#include "highboy_nfc_types.h"

/** Send RATS and receive ATS. */
hb_nfc_err_t iso_dep_rats(uint8_t fsdi, uint8_t cid, nfc_iso_dep_data_t* dep);

/** Exchange I-Block (with optional chaining). */
int iso_dep_transceive(const uint8_t* tx, size_t tx_len,
                        uint8_t* rx, size_t rx_max, int timeout_ms);

#endif
