/**
 * @file nfc_manager.c
 * @brief NFC Manager — simple poll loop.
 *
 * Replicates the working code app_main() flow but as a reusable module.
 */
#include "nfc_manager.h"
#include "st25r3916_core.h"
#include "nfc_poller.h"
#include "poller.h"
#include "hb_nfc_timer.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"

static const char* TAG = "nfc_mgr";

static struct {
    nfc_state_t state;
    nfc_card_found_cb_t cb;
    void* ctx;
    TaskHandle_t task;
    bool running;
} s_mgr = { 0 };

static void nfc_manager_task(void* arg)
{
    (void)arg;
    s_mgr.state = NFC_STATE_SCANNING;
    ESP_LOGI(TAG, "Scan loop started — present a card...");

    while (s_mgr.running) {
        nfc_iso14443a_data_t card = { 0 };
        hb_nfc_err_t err = iso14443a_poller_select(&card);

        if (err == HB_NFC_OK) {
            s_mgr.state = NFC_STATE_READING;

            /* Build generic card data */
            hb_nfc_card_data_t full = { 0 };
            full.protocol = HB_PROTO_ISO14443_3A;
            full.iso14443a = card;

            /* Identify sub-protocol from SAK */
            if (card.sak == 0x00) {
                full.protocol = HB_PROTO_MF_ULTRALIGHT;
            } else if (card.sak == 0x08 || card.sak == 0x18 || card.sak == 0x09) {
                full.protocol = HB_PROTO_MF_CLASSIC;
            } else if (card.sak & 0x20) {
                full.protocol = HB_PROTO_ISO14443_4A;
            }

            if (s_mgr.cb) {
                s_mgr.cb(&full, s_mgr.ctx);
            }

            s_mgr.state = NFC_STATE_SCANNING;
        }

        /* 100ms between polls — same as working code */
        hb_delay_us(100000);
    }

    s_mgr.state = NFC_STATE_IDLE;
    s_mgr.task = NULL;
    vTaskDelete(NULL);
}

hb_nfc_err_t nfc_manager_start(const highboy_nfc_config_t* cfg,
                                 nfc_card_found_cb_t cb, void* ctx)
{
    /* Init hardware */
    hb_nfc_err_t err = st25r_init(cfg);
    if (err != HB_NFC_OK) return err;

    /* Set NFC-A mode + field on */
    err = nfc_poller_start();
    if (err != HB_NFC_OK) {
        st25r_deinit();
        return err;
    }

    s_mgr.cb = cb;
    s_mgr.ctx = ctx;
    s_mgr.running = true;

    xTaskCreate(nfc_manager_task, "nfc_mgr", 4096, NULL, 5, &s_mgr.task);
    return HB_NFC_OK;
}

void nfc_manager_stop(void)
{
    s_mgr.running = false;
    /* Wait for task to finish */
    while (s_mgr.task != NULL) {
        vTaskDelay(pdMS_TO_TICKS(10));
    }
    nfc_poller_stop();
    st25r_deinit();
}

nfc_state_t nfc_manager_get_state(void)
{
    return s_mgr.state;
}
