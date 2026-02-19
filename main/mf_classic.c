/**
 * @file mf_classic.c
 * @brief MIFARE Classic — stub (Phase 7).
 *
 * TODO: Crypto1 initialization, AUTH cmd (0x60/0x61),
 *       encrypted read/write, sector trailer handling.
 */
#include "mf_classic.h"
#include "esp_log.h"

static const char* TAG = "mf_cl";

hb_nfc_err_t mf_classic_auth(uint8_t block, mf_key_type_t key_type,
                               const mf_classic_key_t* key,
                               const uint8_t uid[4])
{
    (void)block; (void)key_type; (void)key; (void)uid;
    ESP_LOGW(TAG, "MF Classic auth not implemented (Phase 7)");
    return HB_NFC_ERR_INTERNAL;
}

hb_nfc_err_t mf_classic_read_block(uint8_t block, uint8_t data[16])
{
    (void)block; (void)data;
    return HB_NFC_ERR_INTERNAL;
}

hb_nfc_err_t mf_classic_write_block(uint8_t block, const uint8_t data[16])
{
    (void)block; (void)data;
    return HB_NFC_ERR_INTERNAL;
}

mf_classic_type_t mf_classic_get_type(uint8_t sak)
{
    switch (sak) {
    case 0x09: return MF_CLASSIC_MINI;
    case 0x08: return MF_CLASSIC_1K;
    case 0x18: return MF_CLASSIC_4K;
    default:   return MF_CLASSIC_1K;
    }
}

int mf_classic_get_sector_count(mf_classic_type_t type)
{
    switch (type) {
    case MF_CLASSIC_MINI: return 5;
    case MF_CLASSIC_1K:   return 16;
    case MF_CLASSIC_4K:   return 40;
    default:              return 16;
    }
}
