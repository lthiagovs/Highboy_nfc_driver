/**
 * @file nfc_device.c
 * @brief NFC Device — stub.
 */
#include "nfc_device.h"

hb_nfc_err_t nfc_device_save(const char* name, const hb_nfc_card_data_t* card)
{
    (void)name; (void)card;
    return HB_NFC_ERR_INTERNAL; /* TODO: NVS implementation */
}

hb_nfc_err_t nfc_device_load(const char* name, hb_nfc_card_data_t* card)
{
    (void)name; (void)card;
    return HB_NFC_ERR_INTERNAL;
}

const char* nfc_device_protocol_name(hb_nfc_protocol_t proto)
{
    switch (proto) {
    case HB_PROTO_ISO14443_3A:   return "ISO14443-3A";
    case HB_PROTO_ISO14443_3B:   return "ISO14443-3B";
    case HB_PROTO_ISO14443_4A:   return "ISO14443-4A (ISO-DEP)";
    case HB_PROTO_ISO14443_4B:   return "ISO14443-4B";
    case HB_PROTO_FELICA:         return "FeliCa";
    case HB_PROTO_ISO15693:       return "ISO15693 (NFC-V)";
    case HB_PROTO_ST25TB:         return "ST25TB";
    case HB_PROTO_MF_CLASSIC:    return "MIFARE Classic";
    case HB_PROTO_MF_ULTRALIGHT: return "MIFARE Ultralight/NTAG";
    case HB_PROTO_MF_DESFIRE:    return "MIFARE DESFire";
    case HB_PROTO_MF_PLUS:       return "MIFARE Plus";
    case HB_PROTO_SLIX:           return "SLIX";
    default:                      return "Unknown";
    }
}
