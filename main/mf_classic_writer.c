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

static bool mf_classic_access_bit_is_valid(uint8_t v)
{
    return (v == 0U || v == 1U);
}

bool mf_classic_access_bits_encode(const mf_classic_access_bits_t* ac,
                                    uint8_t                         out_access_bits[3])
{
    if (!ac || !out_access_bits) return false;

    uint8_t b6 = 0;
    uint8_t b7 = 0;
    uint8_t b8 = 0;

    for (int grp = 0; grp < 4; grp++) {
        uint8_t c1 = ac->c1[grp];
        uint8_t c2 = ac->c2[grp];
        uint8_t c3 = ac->c3[grp];

        if (!mf_classic_access_bit_is_valid(c1) ||
            !mf_classic_access_bit_is_valid(c2) ||
            !mf_classic_access_bit_is_valid(c3)) {
            return false;
        }

        /* Byte 7 high nibble = C1, byte 6 low nibble = ~C1 */
        if (c1) b7 |= (uint8_t)(1U << (4 + grp));
        else    b6 |= (uint8_t)(1U << grp);

        /* Byte 8 low nibble = C2, byte 6 high nibble = ~C2 */
        if (c2) b8 |= (uint8_t)(1U << grp);
        else    b6 |= (uint8_t)(1U << (4 + grp));

        /* Byte 8 high nibble = C3, byte 7 low nibble = ~C3 */
        if (c3) b8 |= (uint8_t)(1U << (4 + grp));
        else    b7 |= (uint8_t)(1U << grp);
    }

    out_access_bits[0] = b6;
    out_access_bits[1] = b7;
    out_access_bits[2] = b8;
    return true;
}

bool mf_classic_access_bits_valid(const uint8_t access_bits[3])
{
    if (!access_bits) return false;

    uint8_t b6 = access_bits[0];
    uint8_t b7 = access_bits[1];
    uint8_t b8 = access_bits[2];

    for (int grp = 0; grp < 4; grp++) {
        uint8_t c1     = (b7 >> (4 + grp)) & 1U;
        uint8_t c1_inv = (uint8_t)((~b6 >> grp) & 1U);
        uint8_t c2     = (b8 >> grp) & 1U;
        uint8_t c2_inv = (uint8_t)((~b6 >> (4 + grp)) & 1U);
        uint8_t c3     = (b8 >> (4 + grp)) & 1U;
        uint8_t c3_inv = (uint8_t)((~b7 >> grp) & 1U);
        if (c1 != c1_inv || c2 != c2_inv || c3 != c3_inv) return false;
    }

    return true;
}

/* Block/Sector mapping for Mini/1K/4K */
static inline int mf_classic_total_blocks(mf_classic_type_t type)
{
    switch (type) {
    case MF_CLASSIC_MINI: return 20;   /* 5 sectors * 4 blocks */
    case MF_CLASSIC_1K:   return 64;   /* 16 sectors * 4 blocks */
    case MF_CLASSIC_4K:   return 256;  /* 32*4 + 8*16 */
    default:              return 64;
    }
}

static inline int mf_classic_sector_block_count(mf_classic_type_t type, int sector)
{
    if (type == MF_CLASSIC_4K && sector >= 32) return 16;
    return 4;
}

static inline int mf_classic_sector_first_block(mf_classic_type_t type, int sector)
{
    if (type == MF_CLASSIC_4K && sector >= 32) return 128 + (sector - 32) * 16;
    return sector * 4;
}

static inline int mf_classic_sector_trailer_block(mf_classic_type_t type, int sector)
{
    return mf_classic_sector_first_block(type, sector) +
           mf_classic_sector_block_count(type, sector) - 1;
}

static inline int mf_classic_block_to_sector(mf_classic_type_t type, int block)
{
    if (type == MF_CLASSIC_4K && block >= 128) return 32 + (block - 128) / 16;
    return block / 4;
}

static inline bool mf_classic_is_trailer_block(mf_classic_type_t type, int block)
{
    int sector = mf_classic_block_to_sector(type, block);
    return block == mf_classic_sector_trailer_block(type, sector);
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

    mf_classic_type_t type = mf_classic_get_type(card->sak);
    if ((int)block >= mf_classic_total_blocks(type)) return MF_WRITE_ERR_PARAM;

    /* ── Proteções ── */
    if (block == 0 && !allow_special) {
        ESP_LOGE(TAG, "Bloco 0 (manufacturer) protegido — use allow_special=true apenas em cartões magic");
        return MF_WRITE_ERR_PROTECTED;
    }
    if (mf_classic_is_trailer_block(type, block) && !allow_special) {
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

    mf_classic_type_t type = mf_classic_get_type(card->sak);
    int sector_count = mf_classic_get_sector_count(type);
    if ((int)sector >= sector_count) return -1;

    const int blocks_in_sector = mf_classic_sector_block_count(type, sector);
    const int data_blocks      = blocks_in_sector - 1;
    const int fb               = mf_classic_sector_first_block(type, sector);
    const int last_data_block  = fb + data_blocks - 1;

    ESP_LOGI(TAG, "Escrevendo setor %d (blocos %d..%d)...",
             sector, fb, last_data_block);

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
            err = iso14443a_poller_reselect(card);
            if (err != HB_NFC_OK) {
                ESP_LOGE(TAG, "Reselect falhou na verificacao (bloco %d)", block);
                return written;
            }
            err = mf_classic_auth(fb, key_type, &k, card->uid);
            if (err != HB_NFC_OK) {
                ESP_LOGE(TAG, "Auth falhou na verificacao (setor %d, key%c)",
                         sector, key_type == MF_KEY_A ? 'A' : 'B');
                return written;
            }

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
                err = iso14443a_poller_reselect(card);
                if (err != HB_NFC_OK) {
                    ESP_LOGE(TAG, "Reselect falhou para continuar (setor %d)", sector);
                    return written;
                }
                err = mf_classic_auth(fb, key_type, &k, card->uid);
                if (err != HB_NFC_OK) {
                    ESP_LOGE(TAG, "Auth falhou para continuar (setor %d, key%c)",
                             sector, key_type == MF_KEY_A ? 'A' : 'B');
                    return written;
                }
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

bool mf_classic_build_trailer_safe(const uint8_t              key_a[6],
                                    const uint8_t              key_b[6],
                                    const mf_classic_access_bits_t* ac,
                                    uint8_t                    gpb,
                                    uint8_t                    out_trailer[16])
{
    if (!key_a || !key_b || !ac || !out_trailer) return false;

    uint8_t access_bits[3];
    if (!mf_classic_access_bits_encode(ac, access_bits)) return false;
    if (!mf_classic_access_bits_valid(access_bits)) return false;

    memcpy(out_trailer, key_a, 6);
    out_trailer[6] = access_bits[0];
    out_trailer[7] = access_bits[1];
    out_trailer[8] = access_bits[2];
    out_trailer[9] = gpb;
    memcpy(&out_trailer[10], key_b, 6);
    return true;
}


