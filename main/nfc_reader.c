#include "nfc_reader.h"
#include <stdio.h>
#include <string.h>
#include "esp_log.h"
#include "nfc_common.h"
#include "poller.h"
#include "mf_classic.h"
#include "mf_classic_emu.h"
#include "mf_ultralight.h"
#include "nfc_card_info.h"

static const char* TAG = "hb_main";
mfc_emu_card_data_t s_emu_card = { 0 };
bool s_emu_data_ready = false;

/* ═══════════════════════════════════════════════════════════
 *  Key Dictionary
 * ═══════════════════════════════════════════════════════════ */

static const mf_classic_key_t s_key_dict[] = {
    { .data = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF } },  /* Factory default */
    { .data = { 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5 } },  /* MAD Key A */
    { .data = { 0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5 } },  /* Default B */
    { .data = { 0xD3, 0xF7, 0xD3, 0xF7, 0xD3, 0xF7 } },  /* NFC Forum */
    { .data = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } },  /* All zeros */
    { .data = { 0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0 } },  /* Transport */
    { .data = { 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF } },  /* Test key */
    { .data = { 0x4D, 0x3A, 0x99, 0xC3, 0x51, 0xDD } },  /* Oyster */
    { .data = { 0x1A, 0x98, 0x2C, 0x7E, 0x45, 0x9A } },  /* Oyster */
    { .data = { 0x71, 0x4C, 0x5C, 0x88, 0x6E, 0x97 } },  /* Common */
    { .data = { 0x58, 0x7E, 0xE5, 0xF9, 0x35, 0x0F } },  /* Common */
    { .data = { 0xA0, 0x47, 0x8C, 0xC3, 0x90, 0x91 } },  /* Common */
    { .data = { 0x53, 0x3C, 0xB6, 0xC7, 0x23, 0xF6 } },  /* Common */
    { .data = { 0x8F, 0xD0, 0xA4, 0xF2, 0x56, 0xE9 } },  /* Common */
};

#define KEY_DICT_SIZE (sizeof(s_key_dict) / sizeof(s_key_dict[0]))

/* ═══════════════════════════════════════════════════════════
 *  Access Bits Decoding
 * ═══════════════════════════════════════════════════════════ */

static void get_access_bits_for_block(const uint8_t trailer[16], int blk,
                                       uint8_t* c1, uint8_t* c2, uint8_t* c3)
{
    uint8_t b7 = trailer[7], b8 = trailer[8];
    *c1 = (b7 >> (4 + blk)) & 1U;
    *c2 = (b8 >> blk) & 1U;
    *c3 = (b8 >> (4 + blk)) & 1U;
}

static const char* access_cond_data_str(uint8_t c1, uint8_t c2, uint8_t c3)
{
    uint8_t bits = (c1 << 2) | (c2 << 1) | c3;
    switch (bits) {
    case 0: return "rd:AB  wr:AB  inc:AB  dec:AB";
    case 1: return "rd:AB  wr:--  inc:--  dec:AB";
    case 2: return "rd:AB  wr:--  inc:--  dec:--";
    case 3: return "rd:B   wr:B   inc:--  dec:--";
    case 4: return "rd:AB  wr:B   inc:--  dec:--";
    case 5: return "rd:B   wr:--  inc:--  dec:--";
    case 6: return "rd:AB  wr:B   inc:B   dec:AB";
    case 7: return "rd:--  wr:--  inc:--  dec:--";
    default: return "?";
    }
}

static const char* access_cond_trailer_str(uint8_t c1, uint8_t c2, uint8_t c3)
{
    uint8_t bits = (c1 << 2) | (c2 << 1) | c3;
    switch (bits) {
    case 0: return "KeyA:wr_A  AC:rd_A    KeyB:rd_A/wr_A";
    case 1: return "KeyA:wr_A  AC:rd_A/wr_A KeyB:rd_A/wr_A";
    case 2: return "KeyA:--    AC:rd_A     KeyB:rd_A";
    case 3: return "KeyA:wr_B  AC:rd_AB/wr_B KeyB:wr_B";
    case 4: return "KeyA:wr_B  AC:rd_AB    KeyB:wr_B";
    case 5: return "KeyA:--    AC:rd_AB/wr_B KeyB:--";
    case 6: return "KeyA:--    AC:rd_AB    KeyB:--";
    case 7: return "KeyA:--    AC:rd_AB    KeyB:--";
    default: return "?";
    }
}

/** Check if Key B is readable from trailer given access bits for block 3 */
static bool is_key_b_readable(uint8_t c1, uint8_t c2, uint8_t c3)
{
    /* Key B is readable in trailer when C1=0 C2=0 C3=0 or C1=0 C2=0 C3=1
     * or C1=0 C2=1 C3=0 — basically when it's used as data, not as key.
     * In those configs Key B cannot be used for auth. */
    uint8_t bits = (c1 << 2) | (c2 << 1) | c3;
    return (bits == 0 || bits == 1 || bits == 2);
}

static bool verify_access_bits_parity(const uint8_t trailer[16])
{
    uint8_t b6 = trailer[6], b7 = trailer[7], b8 = trailer[8];
    for (int blk = 0; blk < 4; blk++) {
        uint8_t c1     = (b7 >> (4 + blk)) & 1U;
        uint8_t c1_inv = (~b6 >> blk) & 1U;
        uint8_t c2     = (b8 >> blk) & 1U;
        uint8_t c2_inv = (~b6 >> (4 + blk)) & 1U;
        uint8_t c3     = (b8 >> (4 + blk)) & 1U;
        uint8_t c3_inv = (~b7 >> blk) & 1U;
        if (c1 != c1_inv || c2 != c2_inv || c3 != c3_inv) return false;
    }
    return true;
}

/* ═══════════════════════════════════════════════════════════
 *  Value Block Detection & Decoding
 * ═══════════════════════════════════════════════════════════ */

static bool is_value_block(const uint8_t data[16])
{
    /* Value block format:
     * Bytes 0-3: value (little-endian)
     * Bytes 4-7: ~value (inverted)
     * Bytes 8-11: value (repeated)
     * Byte 12: address
     * Byte 13: ~address
     * Byte 14: address
     * Byte 15: ~address
     */
    if (data[0]  != data[8]  || data[1]  != data[9]  ||
        data[2]  != data[10] || data[3]  != data[11]) return false;
    if ((uint8_t)(data[0] ^ 0xFF) != data[4]  ||
        (uint8_t)(data[1] ^ 0xFF) != data[5]  ||
        (uint8_t)(data[2] ^ 0xFF) != data[6]  ||
        (uint8_t)(data[3] ^ 0xFF) != data[7])  return false;
    if (data[12] != data[14]) return false;
    if ((uint8_t)(data[12] ^ 0xFF) != data[13]) return false;
    if ((uint8_t)(data[12] ^ 0xFF) != data[15]) return false;
    return true;
}

static int32_t decode_value_block(const uint8_t data[16])
{
    return (int32_t)((uint32_t)data[0] | ((uint32_t)data[1] << 8) |
                     ((uint32_t)data[2] << 16) | ((uint32_t)data[3] << 24));
}

/* ═══════════════════════════════════════════════════════════
 *  Block Content Analysis
 * ═══════════════════════════════════════════════════════════ */

static bool is_block_empty(const uint8_t data[16])
{
    for (int i = 0; i < 16; i++) {
        if (data[i] != 0x00) return false;
    }
    return true;
}

static bool has_ascii_content(const uint8_t data[16])
{
    int printable = 0;
    for (int i = 0; i < 16; i++) {
        if (data[i] >= 0x20 && data[i] <= 0x7E) printable++;
    }
    return printable >= 8;  /* At least half is printable ASCII */
}

/* ═══════════════════════════════════════════════════════════
 *  Format Helpers
 * ═══════════════════════════════════════════════════════════ */

static void hex_str(const uint8_t* data, size_t len, char* buf, size_t buf_sz)
{
    size_t pos = 0;
    for (size_t i = 0; i < len && pos + 3 < buf_sz; i++) {
        pos += (size_t)snprintf(buf + pos, buf_sz - pos,
                                "%02X%s", data[i], i + 1 < len ? " " : "");
    }
}

static void hex_str_key(const uint8_t* data, char* buf, size_t buf_sz)
{
    snprintf(buf, buf_sz, "%02X %02X %02X %02X %02X %02X",
             data[0], data[1], data[2], data[3], data[4], data[5]);
}

static void ascii_str(const uint8_t* data, size_t len, char* buf, size_t buf_sz)
{
    size_t i;
    for (i = 0; i < len && i + 1 < buf_sz; i++) {
        buf[i] = (data[i] >= 0x20 && data[i] <= 0x7E) ? (char)data[i] : '.';
    }
    buf[i] = '\0';
}

/* ═══════════════════════════════════════════════════════════
 *  Block 0 (Manufacturer) Analysis
 * ═══════════════════════════════════════════════════════════ */

static void analyze_manufacturer_block(const uint8_t blk0[16], const nfc_iso14443a_data_t* card)
{
    ESP_LOGI(TAG, "│");
    ESP_LOGI(TAG, "│ ┌── Manufacturer Block Analysis ──");

    /* UID + BCC check */
    if (card->uid_len == 4) {
        uint8_t bcc = blk0[0] ^ blk0[1] ^ blk0[2] ^ blk0[3];
        bool bcc_ok = (bcc == blk0[4]);
        ESP_LOGI(TAG, "│ │ UID: %02X %02X %02X %02X  BCC: %02X %s",
                 blk0[0], blk0[1], blk0[2], blk0[3], blk0[4],
                 bcc_ok ? "✓ OK" : "✗ MISMATCH!");
        if (!bcc_ok) {
            ESP_LOGW(TAG, "│ │ ⚠ BCC deveria ser %02X — cartão pode ser clone/magic!", bcc);
        }
    }

    /* SAK + ATQA from block 0 */
    ESP_LOGI(TAG, "│ │ SAK stored: 0x%02X  ATQA stored: %02X %02X",
             blk0[5], blk0[6], blk0[7]);

    /* Manufacturer lookup */
    const char* mfr = get_manufacturer_name(blk0[0]);
    if (mfr) {
        ESP_LOGI(TAG, "│ │ Fabricante: %s (ID 0x%02X)", mfr, blk0[0]);
    } else {
        ESP_LOGI(TAG, "│ │ Fabricante: Desconhecido (ID 0x%02X)", blk0[0]);
    }

    /* Check for common clone indicators */
    /* UID starting with 0xE0 is not a registered manufacturer */
    if (blk0[0] == 0xE0 || blk0[0] == 0x00 || blk0[0] == 0xFF) {
        ESP_LOGW(TAG, "│ │ ⚠ UID byte 0 (0x%02X) não é fabricante NXP registrado", blk0[0]);
        ESP_LOGW(TAG, "│ │   Possível cartão clone (Gen2/CUID ou UID editável)");
    }

    /* Manufacturer data bytes 8-15 */
    char mfr_data[40];
    hex_str(&blk0[8], 8, mfr_data, sizeof(mfr_data));
    ESP_LOGI(TAG, "│ │ MFR data: %s", mfr_data);

    /* Check if manufacturer data looks like NXP */
    bool nxp_pattern = (blk0[0] == 0x04);
    if (nxp_pattern) {
        ESP_LOGI(TAG, "│ │ Fabricante NXP confirmado — cartão provavelmente original");
    }

    ESP_LOGI(TAG, "│ └──────────────────────────────");
}

/* ═══════════════════════════════════════════════════════════
 *  MAD (MIFARE Application Directory) Detection
 * ═══════════════════════════════════════════════════════════ */

static void check_mad(const uint8_t blk1[16], const uint8_t blk2[16], bool key_was_mad)
{
    /* MAD lives in sector 0, blocks 1 and 2.
     * If Key A was A0 A1 A2 A3 A4 A5, it's MAD sector. */

    /* MAD1 info byte is at block 1, byte 1 (after CRC) */
    uint8_t mad_version = blk1[1] >> 6;  /* bits 7-6 = MAD version */
    bool has_mad = (blk1[0] != 0x00 || blk1[1] != 0x00);  /* Non-zero = has MAD */

    /* Also check with key */
    if (key_was_mad || has_mad) {
        ESP_LOGI(TAG, "│");
        ESP_LOGI(TAG, "│ ┌── MAD (MIFARE Application Directory) ──");

        if (key_was_mad) {
            ESP_LOGI(TAG, "│ │ Key A = MAD Key (A0 A1 A2 A3 A4 A5)");
        }

        ESP_LOGI(TAG, "│ │ MAD CRC: 0x%02X", blk1[0]);
        ESP_LOGI(TAG, "│ │ MAD Info: 0x%02X (versão %d)", blk1[1], mad_version);

        /* Decode AIDs (Application IDs) */
        /* Block 1 bytes 2-15 = AIDs for sectors 1-7 */
        /* Block 2 bytes 0-15 = AIDs for sectors 8-15 */
        ESP_LOGI(TAG, "│ │ Sector AIDs:");
        for (int s = 1; s <= 7; s++) {
            uint16_t aid = (uint16_t)blk1[s * 2] | ((uint16_t)blk1[s * 2 + 1] << 8);
            if (aid != 0x0000) {
                const char* aid_name = "";
                if (aid == 0x0003) aid_name = " (NDEF)";
                else if (aid == 0x0001) aid_name = " (Defect)";
                else if (aid == 0x0004) aid_name = " (Card Holder)";
                ESP_LOGI(TAG, "│ │   Setor %02d → AID 0x%04X%s", s, aid, aid_name);
            }
        }
        for (int s = 8; s <= 15; s++) {
            int idx = (s - 8) * 2;
            uint16_t aid = (uint16_t)blk2[idx] | ((uint16_t)blk2[idx + 1] << 8);
            if (aid != 0x0000) {
                const char* aid_name = "";
                if (aid == 0x0003) aid_name = " (NDEF)";
                ESP_LOGI(TAG, "│ │   Setor %02d → AID 0x%04X%s", s, aid, aid_name);
            }
        }

        bool all_zero = true;
        for (int i = 2; i < 16; i++) { if (blk1[i]) all_zero = false; }
        for (int i = 0; i < 16; i++) { if (blk2[i]) all_zero = false; }
        if (all_zero) {
            ESP_LOGI(TAG, "│ │   (nenhuma aplicação registrada)");
        }

        ESP_LOGI(TAG, "│ └──────────────────────────────");
    }
}

/* ═══════════════════════════════════════════════════════════
 *  PRNG Analysis (Clone / Magic Card Detection)
 * ═══════════════════════════════════════════════════════════ */

typedef struct {
    uint32_t nonces[40];    /* Store nonce for each sector */
    int      count;
    bool     all_same;
    bool     weak_prng;
} prng_analysis_t;

static prng_analysis_t s_prng = { 0 };

static void prng_record_nonce(int sector, uint32_t nt)
{
    if (sector < 40) {
        s_prng.nonces[sector] = nt;
        s_prng.count++;
    }
}

static void prng_analyze(void)
{
    if (s_prng.count < 2) return;

    /* Check if all nonces are identical (static nonce = Gen1a/Gen2 clone) */
    s_prng.all_same = true;
    int distinct = 1;
    for (int i = 1; i < 40 && s_prng.nonces[i] != 0; i++) {
        if (s_prng.nonces[i] != s_prng.nonces[0]) {
            s_prng.all_same = false;
        }
        /* Count distinct values */
        bool found = false;
        for (int j = 0; j < i; j++) {
            if (s_prng.nonces[j] == s_prng.nonces[i]) { found = true; break; }
        }
        if (!found) distinct++;
    }

    /* If very few distinct nonces relative to count, PRNG is weak */
    if (s_prng.count > 4 && distinct <= 2) {
        s_prng.weak_prng = true;
    }
}

/* ═══════════════════════════════════════════════════════════
 *  MIFARE Classic — Full Read (Flipper Zero style)
 * ═══════════════════════════════════════════════════════════ */

typedef struct {
    bool     key_a_found;
    bool     key_b_found;
    uint8_t  key_a[6];
    uint8_t  key_b[6];
    bool     blocks_read[16];
    uint8_t  block_data[16][16];
    int      blocks_in_sector;
    int      first_block;
    int      key_a_dict_idx;
} sector_result_t;

static bool try_auth_key(nfc_iso14443a_data_t* card, uint8_t block,
                          mf_key_type_t key_type, const mf_classic_key_t* key)
{
    mf_classic_reset_auth();
    hb_nfc_err_t err = iso14443a_poller_reselect(card);
    if (err != HB_NFC_OK) return false;

    err = mf_classic_auth(block, key_type, key, card->uid);
    return (err == HB_NFC_OK);
}

void mf_classic_read_full(nfc_iso14443a_data_t* card)
{
    mf_classic_type_t type  = mf_classic_get_type(card->sak);
    int               nsect = mf_classic_get_sector_count(type);

    /* Initialize emulation card data */
    mfc_emu_card_data_init(&s_emu_card, card, type);
    s_emu_data_ready = false;

    const char* type_str = "1K (1024 bytes / 16 setores)";
    int total_mem = 1024;
    if (type == MF_CLASSIC_MINI)  { type_str = "Mini (320 bytes / 5 setores)"; total_mem = 320; }
    else if (type == MF_CLASSIC_4K) { type_str = "4K (4096 bytes / 40 setores)"; total_mem = 4096; }

    ESP_LOGI(TAG, "");
    ESP_LOGI(TAG, "╔══════════════════════════════════════════════════╗");
    ESP_LOGI(TAG, "║  MIFARE Classic %s", type_str);
    ESP_LOGI(TAG, "║  Memória: %d bytes úteis", total_mem);
    ESP_LOGI(TAG, "║  Dicionário: %d chaves × 2 (A+B) = %d tentativas/setor",
             (int)KEY_DICT_SIZE, (int)KEY_DICT_SIZE * 2);
    ESP_LOGI(TAG, "╚══════════════════════════════════════════════════╝");
    ESP_LOGI(TAG, "");

    int sectors_read     = 0;
    int sectors_partial  = 0;
    int sectors_failed   = 0;
    int total_blocks_read = 0;
    int total_blocks      = 0;
    int keys_a_found     = 0;
    int keys_b_found     = 0;
    int data_blocks_used = 0;  /* Non-empty data blocks */

    /* Store sector 0 blocks for MAD analysis */
    uint8_t sect0_blk[4][16];
    bool    sect0_read = false;
    (void)sect0_read;

    for (int sect = 0; sect < nsect; sect++) {
        sector_result_t res = { 0 };
        res.blocks_in_sector = (sect < 32) ? 4 : 16;
        res.first_block      = (sect < 32) ? (sect * 4) : (128 + (sect - 32) * 16);
        int trailer_block    = res.first_block + res.blocks_in_sector - 1;
        res.key_a_dict_idx   = -1;
        total_blocks += res.blocks_in_sector;

        ESP_LOGI(TAG, "┌─── Setor %02d  [bloco %03d..%03d] ─────────────────────",
                 sect, res.first_block, trailer_block);

        /* ── Try Key A ── */
        for (int k = 0; k < (int)KEY_DICT_SIZE; k++) {
            if (try_auth_key(card, (uint8_t)res.first_block, MF_KEY_A, &s_key_dict[k])) {
                res.key_a_found = true;
                res.key_a_dict_idx = k;
                memcpy(res.key_a, s_key_dict[k].data, 6);
                keys_a_found++;
                /* Store for emulation */
                memcpy(s_emu_card.keys[sect].key_a, s_key_dict[k].data, 6);
                s_emu_card.keys[sect].key_a_known = true;
                /* Record nonce for PRNG analysis (clone detection) */
                prng_record_nonce(sect, mf_classic_get_last_nt());
                break;
            }
        }

        /* Read blocks with Key A */
        if (res.key_a_found) {
            for (int b = 0; b < res.blocks_in_sector; b++) {
                hb_nfc_err_t err = mf_classic_read_block(
                    (uint8_t)(res.first_block + b), res.block_data[b]);
                if (err == HB_NFC_OK) {
                    res.blocks_read[b] = true;
                    total_blocks_read++;
                    /* Store for emulation */
                    memcpy(s_emu_card.blocks[res.first_block + b],
                           res.block_data[b], 16);
                }
            }
        }

        /* ── Try Key B (if some blocks not read, or always try for key discovery) ── */
        bool all_read = true;
        for (int b = 0; b < res.blocks_in_sector; b++) {
            if (!res.blocks_read[b]) { all_read = false; break; }
        }

        /* Always try Key B for discovery even if all blocks read with A */
        for (int k = 0; k < (int)KEY_DICT_SIZE; k++) {
            if (try_auth_key(card, (uint8_t)res.first_block, MF_KEY_B, &s_key_dict[k])) {
                res.key_b_found = true;
                memcpy(res.key_b, s_key_dict[k].data, 6);
                keys_b_found++;
                /* Store for emulation */
                memcpy(s_emu_card.keys[sect].key_b, s_key_dict[k].data, 6);
                s_emu_card.keys[sect].key_b_known = true;

                /* Read any remaining blocks */
                if (!all_read) {
                    for (int b = 0; b < res.blocks_in_sector; b++) {
                        if (!res.blocks_read[b]) {
                            hb_nfc_err_t err = mf_classic_read_block(
                                (uint8_t)(res.first_block + b), res.block_data[b]);
                            if (err == HB_NFC_OK) {
                                res.blocks_read[b] = true;
                                total_blocks_read++;
                                /* Store for emulation */
                                memcpy(s_emu_card.blocks[res.first_block + b],
                                       res.block_data[b], 16);
                            }
                        }
                    }
                }
                break;
            }
        }

        /* Save sector 0 for MAD analysis */
        if (sect == 0 && res.blocks_read[0]) {
            for (int b = 0; b < 4; b++) {
                memcpy(sect0_blk[b], res.block_data[b], 16);
            }
            sect0_read = true;
        }

        /* ── Display Keys ── */
        char key_str[24];

        if (res.key_a_found) {
            hex_str_key(res.key_a, key_str, sizeof(key_str));
            ESP_LOGI(TAG, "│ 🔑 Key A: %s", key_str);
        } else {
            ESP_LOGW(TAG, "│ 🔑 Key A: -- -- -- -- -- --  (não encontrada)");
        }

        if (res.key_b_found) {
            hex_str_key(res.key_b, key_str, sizeof(key_str));
            ESP_LOGI(TAG, "│ 🔑 Key B: %s", key_str);
        } else {
            /* Check if Key B is readable from trailer */
            if (res.blocks_read[res.blocks_in_sector - 1]) {
                uint8_t c1, c2, c3;
                get_access_bits_for_block(res.block_data[res.blocks_in_sector - 1], 3, &c1, &c2, &c3);
                if (is_key_b_readable(c1, c2, c3)) {
                    /* Key B is stored as data, extract from trailer bytes 10-15 */
                    uint8_t kb_from_trailer[6];
                    memcpy(kb_from_trailer, &res.block_data[res.blocks_in_sector - 1][10], 6);
                    hex_str_key(kb_from_trailer, key_str, sizeof(key_str));
                    ESP_LOGI(TAG, "│ 🔑 Key B: %s (lida do trailer — usado como dado)", key_str);
                    memcpy(res.key_b, kb_from_trailer, 6);
                    res.key_b_found = true;
                    keys_b_found++;
                } else {
                    ESP_LOGI(TAG, "│ 🔑 Key B: (não testada / protegida)");
                }
            }
        }

        ESP_LOGI(TAG, "│");

        /* ── Display Block Data ── */
        char hex_buf[64], asc_buf[20];

        for (int b = 0; b < res.blocks_in_sector; b++) {
            int blk_num = res.first_block + b;
            bool is_trailer = (b == res.blocks_in_sector - 1);

            if (!res.blocks_read[b]) {
                ESP_LOGW(TAG, "│ [%03d] ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??%s",
                         blk_num, is_trailer ? "  ◄ trailer" : "");
                continue;
            }

            if (is_trailer) {
                /* ── Sector Trailer ── */
                /* IMPORTANT: Key A read from card is ALWAYS 00 00 00 00 00 00
                 * (card never reveals Key A). Show the KNOWN key from auth instead. */
                char ka_display[24], kb_display[24], ac_str[16];

                if (res.key_a_found) {
                    hex_str_key(res.key_a, ka_display, sizeof(ka_display));
                } else {
                    snprintf(ka_display, sizeof(ka_display), "?? ?? ?? ?? ?? ??");
                }

                snprintf(ac_str, sizeof(ac_str), "%02X %02X %02X %02X",
                         res.block_data[b][6], res.block_data[b][7],
                         res.block_data[b][8], res.block_data[b][9]);

                /* Key B from trailer read or from auth */
                if (res.key_b_found) {
                    hex_str_key(res.key_b, kb_display, sizeof(kb_display));
                } else {
                    hex_str_key(&res.block_data[b][10], kb_display, sizeof(kb_display));
                }

                /* Build the "corrected" trailer hex display */
                ESP_LOGI(TAG, "│ [%03d] %s|%s|%s  ◄ trailer",
                         blk_num, ka_display, ac_str, kb_display);

                /* Access bits detail */
                if (verify_access_bits_parity(res.block_data[b])) {
                    ESP_LOGI(TAG, "│       Access bits ✓ válidos:");
                } else {
                    ESP_LOGW(TAG, "│       Access bits ✗ INVÁLIDOS (possível corrupção!):");
                }

                for (int ab = 0; ab < res.blocks_in_sector; ab++) {
                    uint8_t c1, c2, c3;
                    get_access_bits_for_block(res.block_data[b], ab, &c1, &c2, &c3);
                    if (ab < res.blocks_in_sector - 1) {
                        ESP_LOGI(TAG, "│         Blk %d: C%d%d%d → %s",
                                 ab, c1, c2, c3, access_cond_data_str(c1, c2, c3));
                    } else {
                        ESP_LOGI(TAG, "│         Trail: C%d%d%d → %s",
                                 c1, c2, c3, access_cond_trailer_str(c1, c2, c3));
                    }
                }
            }
            else if (blk_num == 0) {
                /* ── Block 0: Manufacturer ── */
                hex_str(res.block_data[b], 16, hex_buf, sizeof(hex_buf));
                ESP_LOGI(TAG, "│ [%03d] %s  ◄ manufacturer", blk_num, hex_buf);
            }
            else {
                /* ── Data Block ── */
                hex_str(res.block_data[b], 16, hex_buf, sizeof(hex_buf));
                ascii_str(res.block_data[b], 16, asc_buf, sizeof(asc_buf));

                if (is_value_block(res.block_data[b])) {
                    int32_t val = decode_value_block(res.block_data[b]);
                    ESP_LOGI(TAG, "│ [%03d] %s  ◄ value: %ld (addr %d)",
                             blk_num, hex_buf, (long)val, res.block_data[b][12]);
                    data_blocks_used++;
                }
                else if (is_block_empty(res.block_data[b])) {
                    ESP_LOGI(TAG, "│ [%03d] %s  ◄ empty", blk_num, hex_buf);
                }
                else if (has_ascii_content(res.block_data[b])) {
                    ESP_LOGI(TAG, "│ [%03d] %s  |%s|", blk_num, hex_buf, asc_buf);
                    data_blocks_used++;
                }
                else {
                    ESP_LOGI(TAG, "│ [%03d] %s", blk_num, hex_buf);
                    data_blocks_used++;
                }
            }
        }

        /* Manufacturer block analysis for sector 0 */
        if (sect == 0 && res.blocks_read[0]) {
            analyze_manufacturer_block(res.block_data[0], card);

            /* MAD check */
            if (res.blocks_read[1] && res.blocks_read[2]) {
                bool mad_key = (res.key_a_dict_idx == 1); /* Index 1 = MAD key A0..A5 */
                check_mad(res.block_data[1], res.block_data[2], mad_key);
            }
        }

        /* Sector status line */
        all_read = true;
        bool any_read = false;
        for (int b = 0; b < res.blocks_in_sector; b++) {
            if (res.blocks_read[b]) any_read = true;
            else all_read = false;
        }

        if (all_read) {
            ESP_LOGI(TAG, "└─── ✓ Setor %02d: COMPLETO", sect);
            sectors_read++;
        } else if (any_read) {
            ESP_LOGW(TAG, "└─── ~ Setor %02d: PARCIAL", sect);
            sectors_partial++;
        } else {
            ESP_LOGW(TAG, "└─── ✗ Setor %02d: FALHOU", sect);
            sectors_failed++;
        }
        ESP_LOGI(TAG, "");
    }

    /* ── PRNG Analysis ── */
    prng_analyze();

    /* ═══ Final Summary ═══ */
    ESP_LOGI(TAG, "╔══════════════════════════════════════════════════╗");
    ESP_LOGI(TAG, "║  📊 RESULTADO DA LEITURA                         ║");
    ESP_LOGI(TAG, "╠══════════════════════════════════════════════════╣");
    ESP_LOGI(TAG, "║  Setores completos:  %2d / %2d                      ║",
             sectors_read, nsect);
    if (sectors_partial > 0) {
        ESP_LOGW(TAG, "║  Setores parciais:   %2d                          ║", sectors_partial);
    }
    if (sectors_failed > 0) {
        ESP_LOGW(TAG, "║  Setores falharam:   %2d                          ║", sectors_failed);
    }
    ESP_LOGI(TAG, "║  Blocos lidos:       %3d / %3d                     ║",
             total_blocks_read, total_blocks);
    ESP_LOGI(TAG, "║  Blocos c/ dados:    %3d (excl. trailers/vazio)   ║",
             data_blocks_used);
    ESP_LOGI(TAG, "║  Keys A encontradas: %2d / %2d                      ║",
             keys_a_found, nsect);
    ESP_LOGI(TAG, "║  Keys B encontradas: %2d / %2d                      ║",
             keys_b_found, nsect);

    /* PRNG info */
    if (s_prng.all_same && s_prng.count > 2) {
        ESP_LOGW(TAG, "║                                                  ║");
        ESP_LOGW(TAG, "║  ⚠ NONCE ESTÁTICO detectado!                     ║");
        ESP_LOGW(TAG, "║    Cartão é provavelmente um CLONE (Gen1a/Gen2). ║");
        ESP_LOGW(TAG, "║    PRNG fixo = nt sempre 0x%08lX           ║",
                 (unsigned long)s_prng.nonces[0]);
    } else if (s_prng.weak_prng) {
        ESP_LOGW(TAG, "║                                                  ║");
        ESP_LOGW(TAG, "║  ⚠ PRNG fraco detectado — poucos nonces únicos. ║");
        ESP_LOGW(TAG, "║    Possível cartão clone com PRNG simplificado.  ║");
    }

    if (sectors_read == nsect) {
        ESP_LOGI(TAG, "║                                                  ║");
        ESP_LOGI(TAG, "║  ✓ DUMP COMPLETO — Todos os setores lidos!       ║");
        s_emu_data_ready = true;
    }

    ESP_LOGI(TAG, "╚══════════════════════════════════════════════════╝");
}

/* ═══════════════════════════════════════════════════════════
 *  MIFARE Ultralight / NTAG — Read
 * ═══════════════════════════════════════════════════════════ */

void mful_dump_card(nfc_iso14443a_data_t* card)
{
    ESP_LOGI(TAG, "");
    ESP_LOGI(TAG, "╔══════════════════════════════════════════════════╗");
    ESP_LOGI(TAG, "║  MIFARE Ultralight / NTAG — Leitura              ║");
    ESP_LOGI(TAG, "╚══════════════════════════════════════════════════╝");
    ESP_LOGI(TAG, "");

    iso14443a_poller_reselect(card);
    uint8_t ver[8] = { 0 };
    int vlen = mful_get_version(ver);

    const char* tag_type = "Ultralight (classic)";
    int total_pages = 16;

    if (vlen >= 7) {
        nfc_log_hex("  VERSION:", ver, (size_t)vlen);
        uint8_t prod_type = ver[2];
        uint8_t prod_sub  = ver[3];
        uint8_t storage   = ver[6];

        if (prod_type == 0x03) {
            /* MIFARE Ultralight */
            switch (storage) {
            case 0x03: tag_type = "Ultralight (64 bytes)"; total_pages = 16; break;
            case 0x0B: tag_type = "Ultralight EV1 (48 bytes)"; total_pages = 20; break;
            case 0x11: tag_type = "Ultralight EV1 (128 bytes)"; total_pages = 41; break;
            case 0x0E: tag_type = "Ultralight Nano (48 bytes)"; total_pages = 20; break;
            default: tag_type = "Ultralight (unknown size)"; break;
            }
        } else if (prod_type == 0x04) {
            /* NTAG */
            switch (storage) {
            case 0x06: tag_type = "NTAG213 (144 bytes user)"; total_pages = 45; break;
            case 0x0E: tag_type = "NTAG215 (504 bytes user)"; total_pages = 135; break;
            case 0x12: tag_type = "NTAG216 (888 bytes user)"; total_pages = 231; break;
            case 0x0F: tag_type = "NTAG I2C 1K"; total_pages = 231; break;
            case 0x13: tag_type = "NTAG I2C 2K"; total_pages = 485; break;
            default:
                if (prod_sub == 0x02) {
                    tag_type = "NTAG (unknown size)";
                } else if (prod_sub == 0x05) {
                    tag_type = "NTAG I2C (unknown size)";
                }
                break;
            }
        }

        ESP_LOGI(TAG, "  IC vendor: 0x%02X  Type: 0x%02X  Subtype: 0x%02X",
                 ver[1], prod_type, prod_sub);
        ESP_LOGI(TAG, "  Major: %d  Minor: %d  Storage: 0x%02X", ver[4], ver[5], storage);
    }

    ESP_LOGI(TAG, "  Tag: %s", tag_type);
    ESP_LOGI(TAG, "  Total: %d páginas (%d bytes)", total_pages, total_pages * 4);
    ESP_LOGI(TAG, "");

    iso14443a_poller_reselect(card);

    int pages_read = 0;
    char hex_buf[16], asc_buf[8];

    for (int pg = 0; pg < total_pages; pg += 4) {
        uint8_t pages[18] = { 0 };
        int rlen = mful_read_pages((uint8_t)pg, pages);

        if (rlen >= 16) {
            for (int p = 0; p < 4 && (pg + p) < total_pages; p++) {
                hex_str(&pages[p * 4], 4, hex_buf, sizeof(hex_buf));
                ascii_str(&pages[p * 4], 4, asc_buf, sizeof(asc_buf));

                const char* label = "";
                int page_num = pg + p;
                if (page_num <= 1) label = "  ◄ UID";
                else if (page_num == 2) label = "  ◄ Internal/Lock";
                else if (page_num == 3) label = "  ◄ OTP/CC";
                else if (page_num == 4) label = "  ◄ Data start";

                ESP_LOGI(TAG, "  [%03d] %s  |%s|%s", page_num, hex_buf, asc_buf, label);
                pages_read++;
            }
        } else {
            for (int p = 0; p < 4 && (pg + p) < total_pages; p++) {
                ESP_LOGW(TAG, "  [%03d] ?? ?? ?? ??  |....|  ◄ protected", pg + p);
            }
            break;
        }
    }

    ESP_LOGI(TAG, "");
    ESP_LOGI(TAG, "  📊 Páginas lidas: %d / %d (%d%%)",
             pages_read, total_pages, pages_read * 100 / total_pages);
}

