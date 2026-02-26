/**
 * @file nfc_reader.h
 * @brief MIFARE Classic/Ultralight read helpers.
 */
#ifndef NFC_READER_H
#define NFC_READER_H

#include "highboy_nfc_types.h"

void mf_classic_read_full(nfc_iso14443a_data_t* card);
void mful_dump_card(nfc_iso14443a_data_t* card);

#endif
