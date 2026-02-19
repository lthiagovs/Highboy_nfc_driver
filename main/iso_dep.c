/**
 * @file iso_dep.c
 * @brief ISO-DEP — stub (Phase 6).
 *
 * TODO: RATS, PPS, I-Block exchange, chaining, WTX handling.
 */
#include "iso_dep.h"
#include "nfc_poller.h"
#include "esp_log.h"

static const char* TAG = "iso_dep";

hb_nfc_err_t iso_dep_rats(uint8_t fsdi, uint8_t cid, nfc_iso_dep_data_t* dep)
{
    uint8_t cmd[2] = { 0xE0, (uint8_t)((fsdi << 4) | (cid & 0x0F)) };
    uint8_t rx[64] = { 0 };
    int len = nfc_poller_transceive(cmd, 2, true, rx, 64, 1, 30);
    if (len < 1) {
        ESP_LOGW(TAG, "RATS failed");
        return HB_NFC_ERR_PROTOCOL;
    }
    if (dep) {
        dep->ats_len = (size_t)len;
        for (int i = 0; i < len && i < NFC_ATS_MAX_LEN; i++) {
            dep->ats[i] = rx[i];
        }
    }
    return HB_NFC_OK;
}

int iso_dep_transceive(const uint8_t* tx, size_t tx_len,
                        uint8_t* rx, size_t rx_max, int timeout_ms)
{
    /* TODO: PCB byte, block number, chaining */
    ESP_LOGW(TAG, "I-Block exchange not fully implemented");
    return nfc_poller_transceive(tx, tx_len, true, rx, rx_max, 1, timeout_ms);
}
