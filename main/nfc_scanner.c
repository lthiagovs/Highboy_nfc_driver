/**
 * @file nfc_scanner.c
 * @brief NFC Scanner — stub (Phase 8).
 *
 * TODO: Implement probe table (NFC-A → B → F → V),
 *       SAK analysis for sub-protocol detection,
 *       FreeRTOS task loop, greedy detection.
 */
#include "nfc_scanner.h"
#include <stdlib.h>
#include "esp_log.h"

static const char* TAG = "nfc_scan";

struct nfc_scanner {
    nfc_scanner_cb_t cb;
    void* ctx;
    bool running;
};

nfc_scanner_t* nfc_scanner_alloc(void)
{
    nfc_scanner_t* s = calloc(1, sizeof(nfc_scanner_t));
    return s;
}

void nfc_scanner_free(nfc_scanner_t* s)
{
    if (s) {
        nfc_scanner_stop(s);
        free(s);
    }
}

hb_nfc_err_t nfc_scanner_start(nfc_scanner_t* s, nfc_scanner_cb_t cb, void* ctx)
{
    if (!s || !cb) return HB_NFC_ERR_PARAM;
    s->cb = cb;
    s->ctx = ctx;
    s->running = true;
    ESP_LOGW(TAG, "Scanner not fully implemented (Phase 8)");
    /* TODO: create FreeRTOS task for probe loop */
    return HB_NFC_OK;
}

void nfc_scanner_stop(nfc_scanner_t* s)
{
    if (s) s->running = false;
}
