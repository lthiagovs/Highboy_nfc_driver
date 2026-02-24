/**
 * @file main.c
 * @brief High Boy NFC — Leitura e Escrita MIFARE Classic.
 *
 * Fluxo:
 *   1. Detecta cartão
 *   2. Lê todos os setores (dump completo com Crypto1)
 *   3. Demonstra escrita no setor 1
 */
#include <stdio.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"

#include "highboy_nfc.h"
#include "st25r3916_core.h"
#include "st25r3916_reg.h"
#include "nfc_poller.h"
#include "nfc_common.h"
#include "poller.h"
#include "mf_ultralight.h"
#include "mf_classic.h"
#include "nfc_card_info.h"
#include "nfc_reader.h"
#include "mf_classic_writer.h"

static const char* TAG = "hb_main";

/* ─────────────────────────────────────────────────────────
 *  Dados de exemplo para escrita
 *  Ajuste WRITE_KEY para a chave do setor que deseja escrever.
 * ───────────────────────────────────────────────────────── */
#define WRITE_SECTOR   1
#define WRITE_KEY_TYPE MF_KEY_B

static const uint8_t WRITE_KEY[6] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

static const uint8_t WRITE_BLOCK4[16] = {
    'H','e','l','l','o',',',' ','W','o','r','l','d','!',' ',' ',' '
};
static const uint8_t WRITE_BLOCK5[16] = {
    0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x01,
    0x20, 0x26, 0x02, 0x23, 0x00, 0x00, 0x00, 0x00
};
static const uint8_t WRITE_BLOCK6[16] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF
};

/* ─────────────────────────────────────────────────────────
 *  Helper
 * ───────────────────────────────────────────────────────── */
static void hex_str(const uint8_t* data, size_t len, char* buf, size_t buf_sz)
{
    size_t pos = 0;
    for (size_t i = 0; i < len && pos + 3 < buf_sz; i++) {
        pos += (size_t)snprintf(buf + pos, buf_sz - pos,
                                "%02X%s", data[i], i + 1 < len ? " " : "");
    }
}

/* ─────────────────────────────────────────────────────────
 *  Escrita
 * ───────────────────────────────────────────────────────── */
static void do_write(nfc_iso14443a_data_t* card)
{
    ESP_LOGI(TAG, "");
    ESP_LOGI(TAG, "╔══════════════════════════════════════════════════╗");
    ESP_LOGI(TAG, "║  ✏️  MODO ESCRITA — Setor %d                       ║", WRITE_SECTOR);
    ESP_LOGI(TAG, "║  Key A: %02X %02X %02X %02X %02X %02X                    ║",
             WRITE_KEY[0], WRITE_KEY[1], WRITE_KEY[2],
             WRITE_KEY[3], WRITE_KEY[4], WRITE_KEY[5]);
    ESP_LOGI(TAG, "╚══════════════════════════════════════════════════╝");

    /* Monta os 3 blocos de dados do setor (trailer não é tocado) */
    uint8_t sector_data[48];
    memcpy(sector_data +  0, WRITE_BLOCK4, 16);
    memcpy(sector_data + 16, WRITE_BLOCK5, 16);
    memcpy(sector_data + 32, WRITE_BLOCK6, 16);

    char hex_buf[50];
    hex_str(WRITE_BLOCK4, 16, hex_buf, sizeof(hex_buf));
    ESP_LOGI(TAG, "  Bloco 4: %s", hex_buf);
    hex_str(WRITE_BLOCK5, 16, hex_buf, sizeof(hex_buf));
    ESP_LOGI(TAG, "  Bloco 5: %s", hex_buf);
    hex_str(WRITE_BLOCK6, 16, hex_buf, sizeof(hex_buf));
    ESP_LOGI(TAG, "  Bloco 6: %s", hex_buf);
    ESP_LOGI(TAG, "");

    int written = mf_classic_write_sector(
        card,
        WRITE_SECTOR,
        sector_data,
        WRITE_KEY,
        WRITE_KEY_TYPE,
        true    /* verify: lê de volta após cada bloco */
    );

    ESP_LOGI(TAG, "");
    if (written == 3) {
        ESP_LOGI(TAG, "╔══════════════════════════════════════════════════╗");
        ESP_LOGI(TAG, "║  ✅ Escrita concluída: 3/3 blocos OK              ║");
        ESP_LOGI(TAG, "╚══════════════════════════════════════════════════╝");
    } else if (written > 0) {
        ESP_LOGW(TAG, "╔══════════════════════════════════════════════════╗");
        ESP_LOGW(TAG, "║  ⚠ Escrita parcial: %d/3 blocos escritos          ║", written);
        ESP_LOGW(TAG, "╚══════════════════════════════════════════════════╝");
    } else {
        ESP_LOGE(TAG, "╔══════════════════════════════════════════════════╗");
        ESP_LOGE(TAG, "║  ❌ Escrita falhou — verifique a chave            ║");
        ESP_LOGE(TAG, "╚══════════════════════════════════════════════════╝");
    }
}

/* ─────────────────────────────────────────────────────────
 *  app_main
 * ───────────────────────────────────────────────────────── */
void app_main(void)
{
    ESP_LOGI(TAG, "");
    ESP_LOGI(TAG, "╔══════════════════════════════════════════════════╗");
    ESP_LOGI(TAG, "║  HIGH BOY NFC — ST25R3916                        ║");
    ESP_LOGI(TAG, "║  Leitura + Escrita MIFARE Classic                ║");
    ESP_LOGI(TAG, "╚══════════════════════════════════════════════════╝");
    ESP_LOGI(TAG, "");

    /* ── Init ── */
    highboy_nfc_config_t cfg = HIGHBOY_NFC_CONFIG_DEFAULT();
    hb_nfc_err_t err = st25r_init(&cfg);
    if (err != HB_NFC_OK) {
        ESP_LOGE(TAG, "Init FAILED: %s", hb_nfc_err_str(err));
        return;
    }

    err = nfc_poller_start();
    if (err != HB_NFC_OK) {
        ESP_LOGE(TAG, "Poller start failed: %s", hb_nfc_err_str(err));
        st25r_deinit();
        return;
    }

    /* ── Aguardar cartão ── */
    ESP_LOGI(TAG, "  Aproxime um cartão NFC 13.56 MHz...");
    ESP_LOGI(TAG, "");

    nfc_iso14443a_data_t card = { 0 };
    bool found = false;

    for (int i = 0; i < 50 && !found; i++) {
        if (iso14443a_poller_select(&card) == HB_NFC_OK) {
            found = true;
        } else {
            vTaskDelay(pdMS_TO_TICKS(100));
        }
    }

    if (!found) {
        ESP_LOGW(TAG, "  Nenhum cartão detectado após 5 segundos.");
        nfc_poller_stop();
        st25r_deinit();
        return;
    }

    /* ── Info do cartão ── */
    card_type_info_t type_info = identify_card(card.sak, card.atqa);

    char uid_str[32];
    hex_str(card.uid, card.uid_len, uid_str, sizeof(uid_str));

    ESP_LOGI(TAG, "╔══════════════════════════════════════════════════╗");
    ESP_LOGI(TAG, "║  📟 CARTÃO DETECTADO                              ║");
    ESP_LOGI(TAG, "╠══════════════════════════════════════════════════╣");
    ESP_LOGI(TAG, "║  Tipo:  %s", type_info.full_name);
    ESP_LOGI(TAG, "║  UID:   %s (%d bytes)", uid_str, card.uid_len);
    ESP_LOGI(TAG, "║  ATQA:  %02X %02X", card.atqa[0], card.atqa[1]);
    ESP_LOGI(TAG, "║  SAK:   0x%02X", card.sak);
    ESP_LOGI(TAG, "╚══════════════════════════════════════════════════╝");

    /* ── Leitura ── */
    if (type_info.is_mf_classic) {
        mf_classic_read_full(&card);
    } else if (type_info.is_mf_ultralight) {
        mful_dump_card(&card);
    } else if (type_info.is_iso_dep) {
        ESP_LOGW(TAG, "  ISO-DEP / DESFire: leitura completa não implementada.");
    } else {
        ESP_LOGW(TAG, "  Tipo não suportado (SAK=0x%02X)", card.sak);
    }

    /* ── Escrita (apenas MIFARE Classic) ── */
    if (type_info.is_mf_classic) {
        nfc_poller_stop();
        do_write(&card);
    }

    /* ── Fim ── */
    ESP_LOGI(TAG, "");
    ESP_LOGI(TAG, "╔══════════════════════════════════════════════════╗");
    ESP_LOGI(TAG, "║  ✅ Concluído.                                    ║");
    ESP_LOGI(TAG, "╚══════════════════════════════════════════════════╝");

    st25r_deinit();
}