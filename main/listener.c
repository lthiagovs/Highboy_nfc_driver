/**
 * @file listener.c
 * @brief ISO14443A Listener — card emulation stub (Phase 9).
 *
 * TODO: Configure P2RAM with ATQA + SAK + UID,
 *       enter passive target mode via CMD_GOTO_SENSE.
 */
#include "highboy_nfc_error.h"
#include "esp_log.h"

static const char* TAG = "14443a_lis";

hb_nfc_err_t iso14443a_listener_start(const uint8_t uid[4], uint8_t sak)
{
    (void)uid; (void)sak;
    ESP_LOGW(TAG, "Listener not implemented (Phase 9)");
    return HB_NFC_ERR_INTERNAL;
}
