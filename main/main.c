/**
 * @file main.c
 * @brief High Boy NFC — main application.
 *
 * This is the EXACT same flow as the proven working code, but
 * refactored to use the modular architecture. Every timing value,
 * every byte, every register access is identical.
 *
 * Working code flow:
 *   1. GPIO + SPI init
 *   2. CMD_SET_DEFAULT + delay
 *   3. Read IC_IDENTITY
 *   4. Configure NFC-A mode
 *   5. OP_CTRL = 0xC8 (field on)
 *   6. Poll for card (REQA/WUPA × 50)
 *   7. Anticollision + SELECT (all CLs)
 *   8. READ pages / PWD_AUTH
 */
#include <stdio.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"

/* High Boy NFC includes */
#include "highboy_nfc.h"
#include "st25r3916_core.h"
#include "nfc_poller.h"
#include "nfc_common.h"
#include "poller.h"
#include "mf_ultralight.h"
#include "nfc_device.h"
#include "hb_nfc_timer.h"

static const char* TAG = "hb_main";

void app_main(void)
{
    ESP_LOGI(TAG, "============================================");
    ESP_LOGI(TAG, " HIGH BOY NFC — ST25R3916 READ TEST");
    ESP_LOGI(TAG, " Architecture: HAL → Driver → Stack → App");
    ESP_LOGI(TAG, "============================================");

    /* ── Step 1-6: Init (same as working code) ── */
    highboy_nfc_config_t cfg = HIGHBOY_NFC_CONFIG_DEFAULT();

    hb_nfc_err_t err = st25r_init(&cfg);
    if (err != HB_NFC_OK) {
        ESP_LOGE(TAG, "Init FAILED: %s (0x%02X)", hb_nfc_err_str(err), err);
        return;
    }

    /* Set NFC-A mode + field ON */
    err = nfc_poller_start();
    if (err != HB_NFC_OK) {
        ESP_LOGE(TAG, "Poller start failed: %s", hb_nfc_err_str(err));
        st25r_deinit();
        return;
    }

    ESP_LOGI(TAG, " Present a 13.56 MHz tag...");

    /* ── Step 7: Poll for card (REQA/WUPA × 50, 100ms interval) ── */
    nfc_iso14443a_data_t card = { 0 };
    bool found = false;

    for (int i = 0; i < 50; i++) {
        err = iso14443a_poller_select(&card);
        if (err == HB_NFC_OK) {
            found = true;
            break;
        }
        hb_delay_us(100000);  /* 100ms — same as working code */
    }

    if (!found) {
        ESP_LOGW(TAG, " No tag detected.");
        nfc_poller_stop();
        st25r_deinit();
        return;
    }

    /* ── Card found! ── */
    ESP_LOGI(TAG, "════════════════════════════════════════");
    nfc_log_hex(" UID:", card.uid, card.uid_len);
    nfc_log_hex(" ATQA:", card.atqa, 2);
    ESP_LOGI(TAG, " SAK: 0x%02X", card.sak);

    /* Identify card type */
    const char* type_name = "Unknown";
    if (card.sak == 0x00)       type_name = "MIFARE Ultralight/NTAG";
    else if (card.sak == 0x08)  type_name = "MIFARE Classic 1K";
    else if (card.sak == 0x18)  type_name = "MIFARE Classic 4K";
    else if (card.sak == 0x09)  type_name = "MIFARE Mini";
    else if (card.sak & 0x20)   type_name = "ISO-DEP (DESFire/Plus/other)";
    ESP_LOGI(TAG, " Type: %s", type_name);
    ESP_LOGI(TAG, "════════════════════════════════════════");

    /* ── Step 8: Card-specific operations ── */

    /* --- Test 1: READ direto sem auth (same as working code) --- */
    ESP_LOGI(TAG, " Teste READ direto (sem auth)...");
    iso14443a_poller_reselect(&card);
    {
        uint8_t pages[18] = { 0 };
        int rlen = mful_read_pages(0x00, pages);
        if (rlen >= 16)    nfc_log_hex(" pg0-3:", pages, 16);
        else if (rlen > 0) nfc_log_hex(" pg0 partial:", pages, (size_t)rlen);
        else               ESP_LOGW(TAG, " sem resposta");
    }

    /* --- Test 2: PWD_AUTH + READ imediato (same as working code) --- */
    ESP_LOGI(TAG, " Teste PWD_AUTH + READ imediato...");
    iso14443a_poller_reselect(&card);
    {
        static const uint8_t pwd[4] = { 0xFF, 0xFF, 0xFF, 0xFF };
        uint8_t pack[2] = { 0 };
        if (mful_pwd_auth(pwd, pack) >= 2) {
            nfc_log_hex(" PACK:", pack, 2);
            uint8_t pages[18] = { 0 };
            int rlen = mful_read_pages(0x00, pages);
            if (rlen >= 16)    nfc_log_hex(" pg0-3:", pages, 16);
            else if (rlen > 0) nfc_log_hex(" partial:", pages, (size_t)rlen);
            else               ESP_LOGW(TAG, " READ falhou pos-auth");
        } else {
            ESP_LOGW(TAG, " PWD_AUTH falhou");
        }
    }

    /* --- Test 3: GET_VERSION --- */
    ESP_LOGI(TAG, " Teste GET_VERSION...");
    iso14443a_poller_reselect(&card);
    {
        uint8_t ver[8] = { 0 };
        int vlen = mful_get_version(ver);
        if (vlen >= 7) {
            nfc_log_hex(" VERSION:", ver, (size_t)vlen);
            ESP_LOGI(TAG, "  Vendor: 0x%02X  Type: 0x%02X  Subtype: 0x%02X",
                     ver[1], ver[2], ver[3]);
            ESP_LOGI(TAG, "  MajVer: %u  MinVer: %u  Size: 0x%02X  Proto: 0x%02X",
                     ver[4], ver[5], ver[6], (vlen >= 8) ? ver[7] : 0);
        } else {
            ESP_LOGW(TAG, " GET_VERSION não suportado (não é NTAG)");
        }
    }

    /* ── Cleanup ── */
    ESP_LOGI(TAG, "============================================");
    ESP_LOGI(TAG, " Done.");
    ESP_LOGI(TAG, "============================================");

    nfc_poller_stop();
    st25r_deinit();
}
