/**
 * @file st25r3916_aat.c
 * @brief ST25R3916 AAT — stub for Phase 4.
 *
 * TODO: Implement DAC sweep, amplitude/phase measurement,
 *       gradient descent to find optimal DAC_A/DAC_B,
 *       and NVS caching.
 */
#include "st25r3916_aat.h"
#include "esp_log.h"

static const char* TAG = "st25r_aat";

hb_nfc_err_t st25r_aat_calibrate(st25r_aat_result_t* result)
{
    ESP_LOGW(TAG, "AAT not yet implemented (Phase 4)");
    if (result) {
        result->dac_a = 128;
        result->dac_b = 128;
        result->amplitude = 0;
        result->phase = 0;
    }
    return HB_NFC_OK;
}

hb_nfc_err_t st25r_aat_load_nvs(st25r_aat_result_t* result)
{
    (void)result;
    return HB_NFC_ERR_INTERNAL; /* Not implemented */
}

hb_nfc_err_t st25r_aat_save_nvs(const st25r_aat_result_t* result)
{
    (void)result;
    return HB_NFC_ERR_INTERNAL; /* Not implemented */
}
