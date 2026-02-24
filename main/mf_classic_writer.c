/**
 * @file mf_classic_writer.c
 * @brief MIFARE Classic — escrita de blocos com autenticação Crypto1.
 */
#include "mf_classic_writer.h"

#include <string.h>
#include "esp_log.h"

#include "poller.h"
#include "mf_classic.h"
#include "nfc_poller.h"

static const char* TAG = "mf_write";

/* ── Access bits padrão ── */
const uint8_t MF_ACCESS_BITS_DEFAULT[3]   = { 0xFF, 0x07, 0x80 };
const uint8_t MF_ACCESS_BITS_READ_ONLY[3] = { 0x78, 0x77, 0x88 };

/* ─────────────────────────────────────────────────────────
 *  Helpers
 * ───────────────────────────────────────────────────────── */

const char* mf_write_result_str(mf_write_result_t r)
{
    switch (r) {
    case MF_WRITE_OK:           return "OK";
    case MF_WRITE_ERR_RESELECT: return "reselect falhou";
    case MF_WRITE_ERR_AUTH:     return "autenticação negada";
    case MF_WRITE_ERR_CMD_NACK: return "NACK no comando WRITE";
    case MF_WRITE_ERR_DATA_NACK:return "NACK nos dados";
    case MF_WRITE_ERR_VERIFY:   return "verificação falhou";
    case MF_WRITE_ERR_PROTECTED:return "bloco protegido";
    case MF_WRITE_ERR_PARAM:    return "parâmetro inválido";
    default:                    return "erro desconhecido";
    }
}

/** Retorna o número do bloco trailer de um setor (1K: setores 0-15) */
static inline uint8_t trailer_block(uint8_t sector)
{
    /* Para 1K e Mini: 4 blocos por setor */
    return (uint8_t)(sector * 4 + 3);
}

/** Retorna o primeiro bloco de um setor */
static inline uint8_t first_block(uint8_t sector)
{
    return (uint8_t)(sector * 4);
}

/** Verifica se um bloco é trailer de setor (para 1K) */
static inline bool is_trailer(uint8_t block)
{
    return ((block + 1) % 4 == 0);
}

/* ─────────────────────────────────────────────────────────
 *  Escrita raw (sessão Crypto1 já ativa)
 * ───────────────────────────────────────────────────────── */

mf_write_result_t mf_classic_write_block_raw(uint8_t block,
                                               const uint8_t data[16])
{
    hb_nfc_err_t err = mf_classic_write_block(block, data);
    if (err == HB_NFC_OK) return MF_WRITE_OK;
    if (err == HB_NFC_ERR_AUTH) return MF_WRITE_ERR_AUTH;
    if (err == HB_NFC_ERR_NACK) {
        mf_write_phase_t phase = mf_classic_get_last_write_phase();
        return (phase == MF_WRITE_PHASE_DATA) ? MF_WRITE_ERR_DATA_NACK
                                              : MF_WRITE_ERR_CMD_NACK;
    }
    return MF_WRITE_ERR_CMD_NACK;
}

/* ─────────────────────────────────────────────────────────
 *  Escrita completa (reselect + auth + write + verify)
 * ───────────────────────────────────────────────────────── */

mf_write_result_t mf_classic_write(nfc_iso14443a_data_t* card,
                                    uint8_t               block,
                                    const uint8_t         data[16],
                                    const uint8_t         key[6],
                                    mf_key_type_t         key_type,
                                    bool                  verify,
                                    bool                  allow_special)
{
    if (!card || !data || !key) return MF_WRITE_ERR_PARAM;

    /* ── Proteções ── */
    if (block == 0 && !allow_special) {
        ESP_LOGE(TAG, "Bloco 0 (manufacturer) protegido — use allow_special=true apenas em cartões magic");
        return MF_WRITE_ERR_PROTECTED;
    }
    if (is_trailer(block) && !allow_special) {
        ESP_LOGE(TAG, "Bloco %d é trailer — use allow_special=true e tenha certeza dos access bits!", block);
        return MF_WRITE_ERR_PROTECTED;
    }

    /* ── Reselect (field cycle + REQA + anticoll + SELECT) ── */
    mf_classic_reset_auth();
    hb_nfc_err_t err = iso14443a_poller_reselect(card);
    if (err != HB_NFC_OK) {
        ESP_LOGE(TAG, "Reselect falhou: %d", err);
        return MF_WRITE_ERR_RESELECT;
    }

    /* ── Auth ── */
    mf_classic_key_t k;
    memcpy(k.data, key, 6);

    err = mf_classic_auth(block, key_type, &k, card->uid);
    if (err != HB_NFC_OK) {
        ESP_LOGE(TAG, "Auth falhou no bloco %d (key%c)", block,
                 key_type == MF_KEY_A ? 'A' : 'B');
        return MF_WRITE_ERR_AUTH;
    }

    /* ── Write ── */
    mf_write_result_t wres = mf_classic_write_block_raw(block, data);
    if (wres != MF_WRITE_OK) {
        ESP_LOGE(TAG, "Write falhou (bloco %d): %s", block, mf_write_result_str(wres));
        return wres;
    }

    ESP_LOGI(TAG, "✓ Bloco %d escrito", block);

    /* ── Verify (opcional) ── */
    if (verify) {
        uint8_t readback[16] = { 0 };
        err = mf_classic_read_block(block, readback);
        if (err != HB_NFC_OK) {
            ESP_LOGW(TAG, "Verificação: leitura falhou (bloco %d)", block);
            return MF_WRITE_ERR_VERIFY;
        }
        if (memcmp(data, readback, 16) != 0) {
            ESP_LOGE(TAG, "Verificação: dado lido não confere (bloco %d)!", block);
            ESP_LOG_BUFFER_HEX("esperado", data, 16);
            ESP_LOG_BUFFER_HEX("lido    ", readback, 16);
            return MF_WRITE_ERR_VERIFY;
        }
        ESP_LOGI(TAG, "✓ Bloco %d verificado", block);
    }

    return MF_WRITE_OK;
}

/* ─────────────────────────────────────────────────────────
 *  Escrita de setor inteiro (exclui trailer)
 * ───────────────────────────────────────────────────────── */

int mf_classic_write_sector(nfc_iso14443a_data_t* card,
                             uint8_t               sector,
                             const uint8_t*        data,
                             const uint8_t         key[6],
                             mf_key_type_t         key_type,
                             bool                  verify)
{
    if (!card || !data || !key) return -1;

    /* Para MIFARE Classic 1K: 4 blocos por setor, trailer é o último */
    const int blocks_in_sector = 4;
    const int data_blocks      = blocks_in_sector - 1;  /* 3 blocos de dados */
    uint8_t   fb               = first_block(sector);

    ESP_LOGI(TAG, "Escrevendo setor %d (blocos %d..%d)...", sector, fb, fb + 2);

    /* Reselect uma vez para o setor inteiro */
    mf_classic_reset_auth();
    hb_nfc_err_t err = iso14443a_poller_reselect(card);
    if (err != HB_NFC_OK) {
        ESP_LOGE(TAG, "Reselect falhou para setor %d", sector);
        return -1;
    }

    /* Auth uma vez para o setor */
    mf_classic_key_t k;
    memcpy(k.data, key, 6);

    err = mf_classic_auth(fb, key_type, &k, card->uid);
    if (err != HB_NFC_OK) {
        ESP_LOGE(TAG, "Auth falhou no setor %d (key%c)", sector,
                 key_type == MF_KEY_A ? 'A' : 'B');
        return -1;
    }

    /* Escreve os blocos de dados (não o trailer) */
    int written = 0;
    for (int b = 0; b < data_blocks; b++) {
        uint8_t block = (uint8_t)(fb + b);
        const uint8_t* block_data = data + (b * 16);

        mf_write_result_t wres = mf_classic_write_block_raw(block, block_data);
        if (wres != MF_WRITE_OK) {
            ESP_LOGE(TAG, "Write falhou no bloco %d: %s", block,
                     mf_write_result_str(wres));
            break;
        }

        /* Verify: precisa re-auth pois write encerra a sessão no bloco */
        if (verify) {
            /* Re-auth para leitura de verificação */
            mf_classic_reset_auth();
            iso14443a_poller_reselect(card);
            mf_classic_auth(fb, key_type, &k, card->uid);

            uint8_t readback[16] = { 0 };
            err = mf_classic_read_block(block, readback);
            if (err != HB_NFC_OK || memcmp(block_data, readback, 16) != 0) {
                ESP_LOGE(TAG, "Verificação falhou no bloco %d!", block);
                return written;
            }
            ESP_LOGI(TAG, "  ✓ Bloco %d escrito e verificado", block);

            /* Re-auth para continuar escrevendo */
            if (b < data_blocks - 1) {
                mf_classic_reset_auth();
                iso14443a_poller_reselect(card);
                mf_classic_auth(fb, key_type, &k, card->uid);
            }
        } else {
            ESP_LOGI(TAG, "  ✓ Bloco %d escrito", block);
        }

        written++;
    }

    ESP_LOGI(TAG, "Setor %d: %d/%d blocos escritos", sector, written, data_blocks);
    return written;
}

/* ─────────────────────────────────────────────────────────
 *  Build Trailer
 * ───────────────────────────────────────────────────────── */

void mf_classic_build_trailer(const uint8_t  key_a[6],
                               const uint8_t  key_b[6],
                               const uint8_t  access_bits[3],
                               uint8_t        out_trailer[16])
{
    /* Bytes 0-5: Key A */
    memcpy(out_trailer, key_a, 6);

    /* Bytes 6-8: Access bits */
    const uint8_t* ac = access_bits ? access_bits : MF_ACCESS_BITS_DEFAULT;
    out_trailer[6] = ac[0];
    out_trailer[7] = ac[1];
    out_trailer[8] = ac[2];

    /* Byte 9: GPB (General Purpose Byte) — 0x00 por padrão */
    out_trailer[9] = 0x00;

    /* Bytes 10-15: Key B */
    memcpy(&out_trailer[10], key_b, 6);
}


