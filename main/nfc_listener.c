/**
 * @file nfc_listener.c
 * @brief NFC Listener — stub (Phase 9).
 */
#include "nfc_listener.h"
#include "esp_log.h"

hb_nfc_err_t nfc_listener_start(const hb_nfc_card_data_t* card)
{
    (void)card;
    ESP_LOGW("nfc_lis", "Listener not implemented (Phase 9)");
    return HB_NFC_ERR_INTERNAL;
}

void nfc_listener_stop(void) { }
