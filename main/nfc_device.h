/**
 * @file nfc_device.h
 * @brief NFC Device — serialize/deserialize card data.
 */
#ifndef NFC_DEVICE_H
#define NFC_DEVICE_H

#include "highboy_nfc_types.h"
#include "highboy_nfc_error.h"

/** Save card data to NVS. */
hb_nfc_err_t nfc_device_save(const char* name, const hb_nfc_card_data_t* card);

/** Load card data from NVS. */
hb_nfc_err_t nfc_device_load(const char* name, hb_nfc_card_data_t* card);

/** Get protocol name string. */
const char* nfc_device_protocol_name(hb_nfc_protocol_t proto);

#endif
