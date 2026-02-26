/* === main\nfc_debug.c === */
/**
 * @file nfc_debug.c
 * @brief NFC Debug — CW test + register dump.
 */
#include "nfc_debug.h"
#include "st25r3916_core.h"
#include "st25r3916_reg.h"
#include "st25r3916_aat.h"
#include "hb_nfc_spi.h"

hb_nfc_err_t nfc_debug_cw_on(void)
{
    return st25r_field_on();
}

void nfc_debug_cw_off(void)
{
    st25r_field_off();
}

void nfc_debug_dump_regs(void)
{
    st25r_dump_regs();
}

hb_nfc_err_t nfc_debug_aat_sweep(void)
{
    st25r_aat_result_t result;
    return st25r_aat_calibrate(&result);
}

/* === main\nfc_card_info.c === */
#include "nfc_card_info.h"
#include <stddef.h>

/* ═══════════════════════════════════════════════════════════
 *  NXP Manufacturer ID Lookup (byte 0 of UID / block 0)
 *  Reference: ISO/IEC 7816-6 + NXP AN10833
 * ═══════════════════════════════════════════════════════════ */

const char* get_manufacturer_name(uint8_t uid0)
{
    switch (uid0) {
    case 0x01: return "Motorola";
    case 0x02: return "STMicroelectronics";
    case 0x03: return "Hitachi";
    case 0x04: return "NXP Semiconductors";
    case 0x05: return "Infineon Technologies";
    case 0x06: return "Cylink";
    case 0x07: return "Texas Instruments";
    case 0x08: return "Fujitsu";
    case 0x09: return "Matsushita";
    case 0x0A: return "NEC";
    case 0x0B: return "Oki Electric";
    case 0x0C: return "Toshiba";
    case 0x0D: return "Mitsubishi Electric";
    case 0x0E: return "Samsung Electronics";
    case 0x0F: return "Hynix";
    case 0x10: return "LG Semiconductors";
    case 0x11: return "Emosyn-EM Microelectronics";
    case 0x12: return "INSIDE Technology";
    case 0x13: return "ORGA Kartensysteme";
    case 0x14: return "SHARP";
    case 0x15: return "ATMEL";
    case 0x16: return "EM Microelectronic-Marin";
    case 0x17: return "SMARTRAC";
    case 0x18: return "ZMD";
    case 0x19: return "XICOR";
    case 0x1A: return "Sony";
    case 0x1B: return "Malaysia Microelectronic Solutions";
    case 0x1C: return "Emosyn";
    case 0x1D: return "Shanghai Fudan Microelectronics";
    case 0x1E: return "Magellan Technology";
    case 0x1F: return "Melexis";
    case 0x20: return "Renesas Technology";
    case 0x21: return "TAGSYS";
    case 0x22: return "Transcore";
    case 0x23: return "Shanghai Belling";
    case 0x24: return "Masktech";
    case 0x25: return "Innovision R&T";
    case 0x26: return "Hitachi ULSI Systems";
    case 0x27: return "Yubico";
    case 0x28: return "Ricoh";
    case 0x29: return "ASK";
    case 0x2A: return "Unicore Microsystems";
    case 0x2B: return "Dallas/Maxim";
    case 0x2C: return "Impinj";
    case 0x2D: return "RightPlug Alliance";
    case 0x2E: return "Broadcom";
    case 0x2F: return "MStar Semiconductor";
    case 0x50: return "HID Global";
    case 0x88: return "Infineon Technologies (cascade)";
    case 0xE0: return "Desconocido (Chinese clone?)";
    default:   return NULL;
    }
}

/* ═══════════════════════════════════════════════════════════
 *  Card Type Identification (Flipper Zero style)
 * ═══════════════════════════════════════════════════════════ */


card_type_info_t identify_card(uint8_t sak, const uint8_t atqa[2])
{
    card_type_info_t info = { "Unknown", "Unknown NFC-A Tag", false, false, false };

    if (sak == 0x00) {
        info.name = "NTAG/Ultralight";
        info.full_name = "MIFARE Ultralight / NTAG";
        info.is_mf_ultralight = true;
    }
    else if (sak == 0x08) {
        info.name = "Classic 1K";
        info.is_mf_classic = true;
        if (atqa[0] == 0x44 && atqa[1] == 0x00) {
            info.full_name = "MIFARE Classic 1K (4-byte NUID)";
        } else if (atqa[0] == 0x04 && atqa[1] == 0x04) {
            info.full_name = "MIFARE Plus 2K (SL1)";
        } else if (atqa[0] == 0x44 && atqa[1] == 0x04) {
            info.full_name = "MIFARE Plus 2K (SL1 7b)";
        } else {
            info.full_name = "MIFARE Classic 1K";
        }
    }
    else if (sak == 0x09) {
        info.name = "Classic Mini";
        info.full_name = "MIFARE Classic Mini 0.3K (320 bytes)";
        info.is_mf_classic = true;
    }
    else if (sak == 0x10) {
        info.name = "Plus 2K SL2";
        info.full_name = "MIFARE Plus 2K (SL2)";
        info.is_mf_classic = true;
    }
    else if (sak == 0x11) {
        info.name = "Plus 4K SL2";
        info.full_name = "MIFARE Plus 4K (SL2)";
        info.is_mf_classic = true;
    }
    else if (sak == 0x18) {
        info.name = "Classic 4K";
        info.full_name = "MIFARE Classic 4K";
        info.is_mf_classic = true;
    }
    else if (sak == 0x01) {
        info.name = "Classic 1K TNP";
        info.full_name = "TNP3XXX (Classic 1K protocol)";
        info.is_mf_classic = true;
    }
    else if (sak == 0x28) {
        info.name = "Classic 1K-EV1";
        info.full_name = "MIFARE Classic 1K (emulated / EV1)";
        info.is_mf_classic = true;
    }
    else if (sak == 0x38) {
        info.name = "Classic 4K-EV1";
        info.full_name = "MIFARE Classic 4K (emulated / EV1)";
        info.is_mf_classic = true;
    }
    else if (sak & 0x20) {
        info.name = "ISO-DEP";
        info.is_iso_dep = true;
        if (sak == 0x20) info.full_name = "ISO 14443-4 (DESFire / Plus SL3 / JCOP)";
        else if (sak == 0x60) info.full_name = "ISO 14443-4 (CL3 cascade)";
        else info.full_name = "ISO 14443-4 Compatible";
    }

    return info;
}


/* === main\nfc_reader.c === */
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

#define TAG TAG_NFC_READER
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

#undef TAG

/* === main\nfc_device.c === */
/**
 * @file nfc_device.c
 * @brief NFC Device — Card profile persistence via ESP-IDF NVS.
 *
 * Serialization format (binary blob):
 *   [0]       uid_len (1 byte)
 *   [1..10]   uid (10 bytes, padded)
 *   [11..12]  atqa (2 bytes)
 *   [13]      sak (1 byte)
 *   [14]      type (1 byte)
 *   [15..16]  sector_count (2 bytes LE)
 *   [17..18]  total_blocks (2 bytes LE)
 *   [19..]    keys: for each sector (sector_count):
 *               key_a[6] + key_b[6] + key_a_known(1) + key_b_known(1) = 14 bytes
 *   [...]     blocks: total_blocks × 16 bytes
 *
 * Total for MFC 1K: 19 + 16×14 + 64×16 = 19 + 224 + 1024 = 1267 bytes
 * Total for MFC 4K: 19 + 40×14 + 256×16 = 19 + 560 + 4096 = 4675 bytes
 */
#include "nfc_device.h"
#include <string.h>
#include "esp_log.h"
#include "nvs_flash.h"
#include "nvs.h"

#define TAG TAG_NFC_DEV
static const char* TAG = "nfc_dev";

/* Max serialized size: MFC 4K */
#define SERIALIZE_HEADER_SIZE   19
#define SERIALIZE_KEY_SIZE      14  /* per sector */
#define SERIALIZE_MAX_SIZE      (SERIALIZE_HEADER_SIZE + \
                                 MFC_EMU_MAX_SECTORS * SERIALIZE_KEY_SIZE + \
                                 MFC_EMU_MAX_BLOCKS * MFC_EMU_BLOCK_SIZE)

static bool s_initialized = false;

/* ═══════════════════════════════════════════════════════════
 *  Serialization
 * ═══════════════════════════════════════════════════════════ */

static size_t serialize_card(const mfc_emu_card_data_t* card, uint8_t* buf, size_t buf_max)
{
    size_t pos = 0;

    if (buf_max < SERIALIZE_HEADER_SIZE) return 0;

    /* Header */
    buf[pos++] = card->uid_len;
    memcpy(&buf[pos], card->uid, 10); pos += 10;
    memcpy(&buf[pos], card->atqa, 2); pos += 2;
    buf[pos++] = card->sak;
    buf[pos++] = (uint8_t)card->type;
    buf[pos++] = (uint8_t)(card->sector_count & 0xFF);
    buf[pos++] = (uint8_t)((card->sector_count >> 8) & 0xFF);
    buf[pos++] = (uint8_t)(card->total_blocks & 0xFF);
    buf[pos++] = (uint8_t)((card->total_blocks >> 8) & 0xFF);

    /* Keys */
    for (int s = 0; s < card->sector_count && s < MFC_EMU_MAX_SECTORS; s++) {
        if (pos + SERIALIZE_KEY_SIZE > buf_max) return 0;
        memcpy(&buf[pos], card->keys[s].key_a, 6); pos += 6;
        memcpy(&buf[pos], card->keys[s].key_b, 6); pos += 6;
        buf[pos++] = card->keys[s].key_a_known ? 1 : 0;
        buf[pos++] = card->keys[s].key_b_known ? 1 : 0;
    }

    /* Blocks */
    for (int b = 0; b < card->total_blocks && b < MFC_EMU_MAX_BLOCKS; b++) {
        if (pos + MFC_EMU_BLOCK_SIZE > buf_max) return 0;
        memcpy(&buf[pos], card->blocks[b], MFC_EMU_BLOCK_SIZE);
        pos += MFC_EMU_BLOCK_SIZE;
    }

    return pos;
}

static bool deserialize_card(const uint8_t* buf, size_t len, mfc_emu_card_data_t* card)
{
    if (len < SERIALIZE_HEADER_SIZE) return false;

    memset(card, 0, sizeof(*card));
    size_t pos = 0;

    /* Header */
    card->uid_len = buf[pos++];
    if (card->uid_len > 10) return false;
    memcpy(card->uid, &buf[pos], 10); pos += 10;
    memcpy(card->atqa, &buf[pos], 2); pos += 2;
    card->sak = buf[pos++];
    card->type = (mf_classic_type_t)buf[pos++];
    card->sector_count = buf[pos] | (buf[pos+1] << 8); pos += 2;
    card->total_blocks = buf[pos] | (buf[pos+1] << 8); pos += 2;

    if (card->sector_count > MFC_EMU_MAX_SECTORS) return false;
    if (card->total_blocks > MFC_EMU_MAX_BLOCKS) return false;

    /* Keys */
    for (int s = 0; s < card->sector_count; s++) {
        if (pos + SERIALIZE_KEY_SIZE > len) return false;
        memcpy(card->keys[s].key_a, &buf[pos], 6); pos += 6;
        memcpy(card->keys[s].key_b, &buf[pos], 6); pos += 6;
        card->keys[s].key_a_known = (buf[pos++] != 0);
        card->keys[s].key_b_known = (buf[pos++] != 0);
    }

    /* Blocks */
    for (int b = 0; b < card->total_blocks; b++) {
        if (pos + MFC_EMU_BLOCK_SIZE > len) return false;
        memcpy(card->blocks[b], &buf[pos], MFC_EMU_BLOCK_SIZE);
        pos += MFC_EMU_BLOCK_SIZE;
    }

    return true;
}

/* ═══════════════════════════════════════════════════════════
 *  NVS Helpers
 * ═══════════════════════════════════════════════════════════ */

static nvs_handle_t open_nvs(nvs_open_mode_t mode)
{
    nvs_handle_t handle = 0;
    esp_err_t err = nvs_open(NFC_DEVICE_NVS_NAMESPACE, mode, &handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "NVS open failed: %s", esp_err_to_name(err));
        return 0;
    }
    return handle;
}

/* ═══════════════════════════════════════════════════════════
 *  Public API
 * ═══════════════════════════════════════════════════════════ */

hb_nfc_err_t nfc_device_init(void)
{
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_LOGW(TAG, "NVS full or version mismatch — erasing...");
        nvs_flash_erase();
        err = nvs_flash_init();
    }
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "NVS init failed: %s", esp_err_to_name(err));
        return HB_NFC_ERR_INTERNAL;
    }

    s_initialized = true;
    ESP_LOGI(TAG, "NFC device storage initialized (%d profiles max)",
             NFC_DEVICE_MAX_PROFILES);
    return HB_NFC_OK;
}

hb_nfc_err_t nfc_device_save(const char* name, const mfc_emu_card_data_t* card)
{
    if (!s_initialized || !name || !card) return HB_NFC_ERR_PARAM;

    nvs_handle_t nvs = open_nvs(NVS_READWRITE);
    if (!nvs) return HB_NFC_ERR_INTERNAL;

    /* Get current count */
    uint8_t count = 0;
    nvs_get_u8(nvs, "count", &count);

    /* Check if name already exists → update */
    int slot = -1;
    for (int i = 0; i < count && i < NFC_DEVICE_MAX_PROFILES; i++) {
        char key[16];
        snprintf(key, sizeof(key), "name_%d", i);
        char existing[NFC_DEVICE_NAME_MAX_LEN] = { 0 };
        size_t len = sizeof(existing);
        if (nvs_get_str(nvs, key, existing, &len) == ESP_OK) {
            if (strcmp(existing, name) == 0) {
                slot = i;
                break;
            }
        }
    }

    if (slot < 0) {
        /* New profile */
        if (count >= NFC_DEVICE_MAX_PROFILES) {
            ESP_LOGW(TAG, "Max profiles reached (%d)", NFC_DEVICE_MAX_PROFILES);
            nvs_close(nvs);
            return HB_NFC_ERR_INTERNAL;
        }
        slot = count;
        count++;
    }

    /* Serialize */
    static uint8_t buf[SERIALIZE_MAX_SIZE];
    size_t data_len = serialize_card(card, buf, sizeof(buf));
    if (data_len == 0) {
        nvs_close(nvs);
        return HB_NFC_ERR_INTERNAL;
    }

    /* Write name */
    char key[16];
    snprintf(key, sizeof(key), "name_%d", slot);
    esp_err_t err = nvs_set_str(nvs, key, name);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "NVS set name failed: %s", esp_err_to_name(err));
        nvs_close(nvs);
        return HB_NFC_ERR_INTERNAL;
    }

    /* Write data */
    snprintf(key, sizeof(key), "data_%d", slot);
    err = nvs_set_blob(nvs, key, buf, data_len);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "NVS set data failed: %s", esp_err_to_name(err));
        nvs_close(nvs);
        return HB_NFC_ERR_INTERNAL;
    }

    /* Update count */
    nvs_set_u8(nvs, "count", count);

    err = nvs_commit(nvs);
    nvs_close(nvs);

    if (err != ESP_OK) {
        ESP_LOGE(TAG, "NVS commit failed: %s", esp_err_to_name(err));
        return HB_NFC_ERR_INTERNAL;
    }

    ESP_LOGI(TAG, "Profile '%s' saved (slot %d, %zu bytes)", name, slot, data_len);
    return HB_NFC_OK;
}

hb_nfc_err_t nfc_device_load(int index, mfc_emu_card_data_t* card)
{
    if (!s_initialized || !card) return HB_NFC_ERR_PARAM;

    nvs_handle_t nvs = open_nvs(NVS_READONLY);
    if (!nvs) return HB_NFC_ERR_INTERNAL;

    uint8_t count = 0;
    nvs_get_u8(nvs, "count", &count);
    if (index < 0 || index >= count) {
        nvs_close(nvs);
        return HB_NFC_ERR_PARAM;
    }

    char key[16];
    snprintf(key, sizeof(key), "data_%d", index);

    static uint8_t buf[SERIALIZE_MAX_SIZE];
    size_t len = sizeof(buf);
    esp_err_t err = nvs_get_blob(nvs, key, buf, &len);
    nvs_close(nvs);

    if (err != ESP_OK) {
        ESP_LOGE(TAG, "NVS load failed: %s", esp_err_to_name(err));
        return HB_NFC_ERR_INTERNAL;
    }

    if (!deserialize_card(buf, len, card)) {
        ESP_LOGE(TAG, "Deserialization failed");
        return HB_NFC_ERR_INTERNAL;
    }

    ESP_LOGI(TAG, "Profile %d loaded (%zu bytes, UID=%02X%02X%02X%02X)",
             index, len, card->uid[0], card->uid[1], card->uid[2], card->uid[3]);
    return HB_NFC_OK;
}

hb_nfc_err_t nfc_device_load_by_name(const char* name, mfc_emu_card_data_t* card)
{
    if (!s_initialized || !name || !card) return HB_NFC_ERR_PARAM;

    nvs_handle_t nvs = open_nvs(NVS_READONLY);
    if (!nvs) return HB_NFC_ERR_INTERNAL;

    uint8_t count = 0;
    nvs_get_u8(nvs, "count", &count);

    for (int i = 0; i < count && i < NFC_DEVICE_MAX_PROFILES; i++) {
        char key[16];
        snprintf(key, sizeof(key), "name_%d", i);
        char existing[NFC_DEVICE_NAME_MAX_LEN] = { 0 };
        size_t len = sizeof(existing);
        if (nvs_get_str(nvs, key, existing, &len) == ESP_OK) {
            if (strcmp(existing, name) == 0) {
                nvs_close(nvs);
                return nfc_device_load(i, card);
            }
        }
    }

    nvs_close(nvs);
    return HB_NFC_ERR_PARAM;  /* Not found */
}

hb_nfc_err_t nfc_device_delete(int index)
{
    if (!s_initialized) return HB_NFC_ERR_PARAM;

    nvs_handle_t nvs = open_nvs(NVS_READWRITE);
    if (!nvs) return HB_NFC_ERR_INTERNAL;

    uint8_t count = 0;
    nvs_get_u8(nvs, "count", &count);
    if (index < 0 || index >= count) {
        nvs_close(nvs);
        return HB_NFC_ERR_PARAM;
    }

    /* Shift all profiles after 'index' down by one */
    for (int i = index; i < count - 1; i++) {
        char src_key[16], dst_key[16];

        /* Move name */
        snprintf(src_key, sizeof(src_key), "name_%d", i + 1);
        snprintf(dst_key, sizeof(dst_key), "name_%d", i);
        char name_buf[NFC_DEVICE_NAME_MAX_LEN] = { 0 };
        size_t name_len = sizeof(name_buf);
        if (nvs_get_str(nvs, src_key, name_buf, &name_len) == ESP_OK) {
            nvs_set_str(nvs, dst_key, name_buf);
        }

        /* Move data */
        snprintf(src_key, sizeof(src_key), "data_%d", i + 1);
        snprintf(dst_key, sizeof(dst_key), "data_%d", i);
        static uint8_t blob[SERIALIZE_MAX_SIZE];
        size_t blob_len = sizeof(blob);
        if (nvs_get_blob(nvs, src_key, blob, &blob_len) == ESP_OK) {
            nvs_set_blob(nvs, dst_key, blob, blob_len);
        }
    }

    /* Remove last slot */
    char key[16];
    snprintf(key, sizeof(key), "name_%d", count - 1);
    nvs_erase_key(nvs, key);
    snprintf(key, sizeof(key), "data_%d", count - 1);
    nvs_erase_key(nvs, key);

    /* Update count */
    count--;
    nvs_set_u8(nvs, "count", count);
    nvs_commit(nvs);
    nvs_close(nvs);

    ESP_LOGI(TAG, "Profile %d deleted, %d remaining", index, count);
    return HB_NFC_OK;
}

int nfc_device_get_count(void)
{
    if (!s_initialized) return 0;

    nvs_handle_t nvs = open_nvs(NVS_READONLY);
    if (!nvs) return 0;

    uint8_t count = 0;
    nvs_get_u8(nvs, "count", &count);
    nvs_close(nvs);
    return (int)count;
}

hb_nfc_err_t nfc_device_get_info(int index, nfc_device_profile_info_t* info)
{
    if (!s_initialized || !info) return HB_NFC_ERR_PARAM;

    nvs_handle_t nvs = open_nvs(NVS_READONLY);
    if (!nvs) return HB_NFC_ERR_INTERNAL;

    uint8_t count = 0;
    nvs_get_u8(nvs, "count", &count);
    if (index < 0 || index >= count) {
        nvs_close(nvs);
        return HB_NFC_ERR_PARAM;
    }

    memset(info, 0, sizeof(*info));

    /* Read name */
    char key[16];
    snprintf(key, sizeof(key), "name_%d", index);
    size_t name_len = sizeof(info->name);
    nvs_get_str(nvs, key, info->name, &name_len);

    /* Read data header only (first 19 bytes) */
    snprintf(key, sizeof(key), "data_%d", index);
    uint8_t header[SERIALIZE_HEADER_SIZE];
    size_t len = sizeof(header);
    esp_err_t err = nvs_get_blob(nvs, key, header, &len);
    nvs_close(nvs);

    if (err != ESP_OK || len < SERIALIZE_HEADER_SIZE) {
        return HB_NFC_ERR_INTERNAL;
    }

    /* Parse header */
    info->uid_len = header[0];
    memcpy(info->uid, &header[1], 10);
    info->sak = header[13];
    info->type = (mf_classic_type_t)header[14];
    info->sector_count = header[15] | (header[16] << 8);

    /* Count known keys (need full data for this) */
    mfc_emu_card_data_t card;
    if (nfc_device_load(index, &card) == HB_NFC_OK) {
        info->keys_known = 0;
        info->complete = true;
        for (int s = 0; s < card.sector_count; s++) {
            if (card.keys[s].key_a_known) info->keys_known++;
            if (card.keys[s].key_b_known) info->keys_known++;
            if (!card.keys[s].key_a_known && !card.keys[s].key_b_known) {
                info->complete = false;
            }
        }
    }

    return HB_NFC_OK;
}

int nfc_device_list(nfc_device_profile_info_t* infos, int max_count)
{
    int count = nfc_device_get_count();
    if (count > max_count) count = max_count;

    for (int i = 0; i < count; i++) {
        nfc_device_get_info(i, &infos[i]);
    }
    return count;
}

hb_nfc_err_t nfc_device_set_active(int index)
{
    if (!s_initialized) return HB_NFC_ERR_PARAM;

    nvs_handle_t nvs = open_nvs(NVS_READWRITE);
    if (!nvs) return HB_NFC_ERR_INTERNAL;

    nvs_set_u8(nvs, "active", (uint8_t)index);
    nvs_commit(nvs);
    nvs_close(nvs);
    return HB_NFC_OK;
}

int nfc_device_get_active(void)
{
    if (!s_initialized) return -1;

    nvs_handle_t nvs = open_nvs(NVS_READONLY);
    if (!nvs) return -1;

    uint8_t active = 0xFF;
    nvs_get_u8(nvs, "active", &active);
    nvs_close(nvs);

    return (active == 0xFF) ? -1 : (int)active;
}

/* ═══════════════════════════════════════════════════════════
 *  Legacy API (generic card data)
 * ═══════════════════════════════════════════════════════════ */

hb_nfc_err_t nfc_device_save_generic(const char* name, const hb_nfc_card_data_t* card)
{
    (void)name; (void)card;
    ESP_LOGW(TAG, "Generic card save — use nfc_device_save() for MFC profiles");
    return HB_NFC_ERR_INTERNAL;
}

hb_nfc_err_t nfc_device_load_generic(const char* name, hb_nfc_card_data_t* card)
{
    (void)name; (void)card;
    ESP_LOGW(TAG, "Generic card load — use nfc_device_load() for MFC profiles");
    return HB_NFC_ERR_INTERNAL;
}

const char* nfc_device_protocol_name(hb_nfc_protocol_t proto)
{
    switch (proto) {
    case HB_PROTO_ISO14443_3A:   return "ISO14443-3A";
    case HB_PROTO_ISO14443_3B:   return "ISO14443-3B";
    case HB_PROTO_ISO14443_4A:   return "ISO14443-4A (ISO-DEP)";
    case HB_PROTO_ISO14443_4B:   return "ISO14443-4B";
    case HB_PROTO_FELICA:        return "FeliCa";
    case HB_PROTO_ISO15693:      return "ISO15693 (NFC-V)";
    case HB_PROTO_ST25TB:        return "ST25TB";
    case HB_PROTO_MF_CLASSIC:    return "MIFARE Classic";
    case HB_PROTO_MF_ULTRALIGHT: return "MIFARE Ultralight/NTAG";
    case HB_PROTO_MF_DESFIRE:    return "MIFARE DESFire";
    case HB_PROTO_MF_PLUS:       return "MIFARE Plus";
    case HB_PROTO_SLIX:          return "SLIX";
    default:                     return "Unknown";
    }
}
#undef TAG

/* === main\nfc_manager.c === */
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

#define TAG TAG_NFC_MGR
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
#undef TAG

/* === main\\nfc_scanner.c === */
/**
 * @file nfc_scanner.c
 * @brief NFC Scanner - basic NFC-A scan.
 *
 * TODO: Implement probe table (NFC-A -> B -> F -> V) and task loop.
 */
#include "nfc_scanner.h"
#include "poller.h"
#include "nfc_card_info.h"
#include <stdlib.h>
#include "esp_log.h"

#define TAG TAG_NFC_SCAN
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

    nfc_iso14443a_data_t card = { 0 };
    hb_nfc_err_t err = iso14443a_poller_select(&card);
    if (err != HB_NFC_OK) {
        s->running = false;
        return err;
    }

    nfc_scanner_event_t evt = { 0 };
    evt.protocols[evt.count++] = HB_PROTO_ISO14443_3A;
    card_type_info_t info = identify_card(card.sak, card.atqa);
    if (info.is_mf_classic) {
        evt.protocols[evt.count++] = HB_PROTO_MF_CLASSIC;
    } else if (info.is_mf_ultralight) {
        evt.protocols[evt.count++] = HB_PROTO_MF_ULTRALIGHT;
    } else if (info.is_iso_dep) {
        evt.protocols[evt.count++] = HB_PROTO_ISO14443_4A;
    }

    cb(evt, ctx);
    return HB_NFC_OK;
}

void nfc_scanner_stop(nfc_scanner_t* s)
{
    if (s) s->running = false;
}
#undef TAG

/* === main\\nfc_listener.c === */
/**
 * @file nfc_listener.c
 * @brief NFC Listener - starts MIFARE Classic emulation.
 */
#include "nfc_listener.h"
#include "nfc_device.h"
#include "mf_classic.h"
#include "mf_classic_emu.h"
#include "esp_log.h"

hb_nfc_err_t nfc_listener_start(const hb_nfc_card_data_t* card)
{
    mfc_emu_card_data_t emu = { 0 };
    hb_nfc_err_t err;

    if (card && card->protocol == HB_PROTO_MF_CLASSIC) {
        mf_classic_type_t type = mf_classic_get_type(card->iso14443a.sak);
        mfc_emu_card_data_init(&emu, &card->iso14443a, type);
        err = mfc_emu_init(&emu);
    } else {
        int idx = nfc_device_get_active();
        if (idx < 0) return HB_NFC_ERR_PARAM;
        err = nfc_device_load(idx, &emu);
        if (err != HB_NFC_OK) return err;
        err = mfc_emu_init(&emu);
    }

    if (err != HB_NFC_OK) return err;
    err = mfc_emu_configure_target();
    if (err != HB_NFC_OK) return err;
    return mfc_emu_start();
}

void nfc_listener_stop(void)
{
    mfc_emu_stop();
}

/* === main\emu_diag.c === */
/**
 * @file emu_diag.c
 * @brief Emulation Diagnostics — Find why readers can't see us.
 *
 * PROBLEM: 60 seconds of emulation with ZERO activations.
 * This means the ST25R3916 isn't detecting the external field
 * or isn't completing anti-collision.
 *
 * This module tests:
 *   1. Register state after poller → target transition
 *   2. External field detection (CMD_MEAS_AMPLITUDE)
 *   3. Multiple field thresholds
 *   4. Multiple OP_CTRL configurations
 *   5. GOTO_SENSE state verification
 *   6. IRQ monitoring with reader present
 *   7. PT Memory verification
 *   8. Oscillator status
 */
#include "emu_diag.h"
#include "mf_classic_emu.h"
#include "st25r3916_core.h"
#include "st25r3916_reg.h"
#include "st25r3916_cmd.h"
#include "st25r3916_irq.h"
#include "hb_nfc_spi.h"
#include "hb_nfc_timer.h"

#include <string.h>
#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#define TAG TAG_EMU_DIAG
static const char* TAG = "emu_diag";

/* ═══════════════════════════════════════════════════════════
 *  Helper: Dump key registers with clear labels
 * ═══════════════════════════════════════════════════════════ */
static void dump_key_regs(const char* label)
{
    uint8_t r[64];
    for (int i = 0; i < 64; i++) {
        hb_spi_reg_read((uint8_t)i, &r[i]);
    }

    ESP_LOGW(TAG, "");
    ESP_LOGW(TAG, "╔═══ REG DUMP: %s ═══", label);
    ESP_LOGW(TAG, "│ IO_CONF1(00)=%02X  IO_CONF2(01)=%02X", r[0x00], r[0x01]);
    ESP_LOGW(TAG, "│ OP_CTRL(02)=%02X   [EN=%d RX_EN=%d TX_EN=%d wu=%d]",
             r[0x02],
             (r[0x02] >> 7) & 1,
             (r[0x02] >> 6) & 1,
             (r[0x02] >> 3) & 1,
             (r[0x02] >> 2) & 1);
    ESP_LOGW(TAG, "│ MODE(03)=%02X      [targ=%d om=0x%X]",
             r[0x03],
             (r[0x03] >> 7) & 1,
             (r[0x03] >> 3) & 0x0F);
    ESP_LOGW(TAG, "│ BIT_RATE(04)=%02X  ISO14443A(05)=%02X [no_tx_par=%d no_rx_par=%d antcl=%d]",
             r[0x04], r[0x05],
             (r[0x05] >> 7) & 1, (r[0x05] >> 6) & 1, r[0x05] & 1);
    ESP_LOGW(TAG, "│ PASSIVE_TGT(08)=%02X [d_106=%d d_212=%d d_ap2p=%d]",
             r[0x08], r[0x08] & 1, (r[0x08] >> 1) & 1, (r[0x08] >> 2) & 1);
    ESP_LOGW(TAG, "│ AUX_DEF(0A)=%02X", r[0x0A]);
    ESP_LOGW(TAG, "│ RX_CONF: %02X %02X %02X %02X",
             r[0x0B], r[0x0C], r[0x0D], r[0x0E]);
    ESP_LOGW(TAG, "│ MASK: MAIN(16)=%02X TMR(17)=%02X ERR(18)=%02X TGT(19)=%02X",
             r[0x16], r[0x17], r[0x18], r[0x19]);
    ESP_LOGW(TAG, "│ IRQ:  MAIN(1A)=%02X TMR(1B)=%02X ERR(1C)=%02X TGT(1D)=%02X",
             r[0x1A], r[0x1B], r[0x1C], r[0x1D]);
    ESP_LOGW(TAG, "│ PT_STS(21)=%02X", r[0x21]);
    ESP_LOGW(TAG, "│ AD_RESULT(24)=%d  ANT_TUNE: A=%02X B=%02X",
             r[0x24], r[0x26], r[0x27]);
    ESP_LOGW(TAG, "│ TX_DRIVER(28)=%02X  PT_MOD(29)=%02X",
             r[0x28], r[0x29]);
    ESP_LOGW(TAG, "│ FLD_ACT(2A)=%02X  FLD_DEACT(2B)=%02X",
             r[0x2A], r[0x2B]);
    ESP_LOGW(TAG, "│ REG_CTRL(2C)=%02X  RSSI(2D)=%02X",
             r[0x2C], r[0x2D]);
    ESP_LOGW(TAG, "│ AUX_DISP(31)=%02X [efd_o=%d efd_i=%d osc=%d nfc_t=%d rx_on=%d rx_act=%d tx_on=%d tgt=%d]",
             r[0x31],
             (r[0x31] >> 0) & 1,
             (r[0x31] >> 1) & 1,
             (r[0x31] >> 2) & 1,
             (r[0x31] >> 3) & 1,
             (r[0x31] >> 4) & 1,
             (r[0x31] >> 5) & 1,
             (r[0x31] >> 6) & 1,
             (r[0x31] >> 7) & 1);
    ESP_LOGW(TAG, "│ IC_ID(3F)=%02X [type=%d rev=%d]",
             r[0x3F], (r[0x3F] >> 3) & 0x1F, r[0x3F] & 0x07);
    ESP_LOGW(TAG, "╚════════════════════════════════════════");
}

static void read_regs(uint8_t r[64])
{
    for (int i = 0; i < 64; i++) {
        hb_spi_reg_read((uint8_t)i, &r[i]);
    }
}

typedef struct {
    uint8_t addr;
    const char* name;
} reg_name_t;

static void diff_key_regs(const char* a_label, const uint8_t* a,
                          const char* b_label, const uint8_t* b)
{
    static const reg_name_t keys[] = {
        { REG_IO_CONF1, "IO_CONF1" },
        { REG_IO_CONF2, "IO_CONF2" },
        { REG_OP_CTRL, "OP_CTRL" },
        { REG_MODE, "MODE" },
        { REG_BIT_RATE, "BIT_RATE" },
        { REG_ISO14443A, "ISO14443A" },
        { REG_PASSIVE_TARGET, "PASSIVE_TGT" },
        { REG_AUX_DEF, "AUX_DEF" },
        { REG_RX_CONF1, "RX_CONF1" },
        { REG_RX_CONF2, "RX_CONF2" },
        { REG_RX_CONF3, "RX_CONF3" },
        { REG_RX_CONF4, "RX_CONF4" },
        { REG_MASK_MAIN_INT, "MASK_MAIN" },
        { REG_MASK_TIMER_NFC_INT, "MASK_TMR" },
        { REG_MASK_ERROR_WUP_INT, "MASK_ERR" },
        { REG_MASK_TARGET_INT, "MASK_TGT" },
        { REG_PASSIVE_TARGET_STS, "PT_STS" },
        { REG_AD_RESULT, "AD_RESULT" },
        { REG_ANT_TUNE_A, "ANT_TUNE_A" },
        { REG_ANT_TUNE_B, "ANT_TUNE_B" },
        { REG_TX_DRIVER, "TX_DRIVER" },
        { REG_PT_MOD, "PT_MOD" },
        { REG_FIELD_THRESH_ACT, "FLD_ACT" },
        { REG_FIELD_THRESH_DEACT, "FLD_DEACT" },
        { REG_REGULATOR_CTRL, "REG_CTRL" },
        { REG_RSSI_RESULT, "RSSI" },
        { REG_AUX_DISPLAY, "AUX_DISP" },
    };

    bool key_map[64] = { 0 };
    for (size_t i = 0; i < sizeof(keys)/sizeof(keys[0]); i++) {
        key_map[keys[i].addr] = true;
    }

    ESP_LOGW(TAG, "");
    ESP_LOGW(TAG, "╔═══ REG DIFF: %s vs %s (KEY REGS) ═══", a_label, b_label);
    int diff_count = 0;
    for (size_t i = 0; i < sizeof(keys)/sizeof(keys[0]); i++) {
        uint8_t addr = keys[i].addr;
        if (a[addr] != b[addr]) {
            ESP_LOGW(TAG, "│ %-12s (0x%02X): %s=0x%02X  %s=0x%02X",
                     keys[i].name, addr, a_label, a[addr], b_label, b[addr]);
            diff_count++;
        }
    }
    if (diff_count == 0) {
        ESP_LOGW(TAG, "│ (nenhuma diferença nos regs chave)");
    }

    int other_diff = 0;
    for (int i = 0; i < 64; i++) {
        if (!key_map[i] && a[i] != b[i]) other_diff++;
    }
    if (other_diff > 0) {
        ESP_LOGW(TAG, "│ + %d diferenças em outros registradores", other_diff);
    }
    ESP_LOGW(TAG, "╚════════════════════════════════════════");
}

/* ═══════════════════════════════════════════════════════════ */
static uint8_t measure_field(void)
{
    hb_spi_direct_cmd(CMD_MEAS_AMPLITUDE);
    vTaskDelay(pdMS_TO_TICKS(5));
    uint8_t ad = 0;
    hb_spi_reg_read(REG_AD_RESULT, &ad);
    return ad;
}

static uint8_t read_aux(void)
{
    uint8_t aux = 0;
    hb_spi_reg_read(REG_AUX_DISPLAY, &aux);
    return aux;
}

/* ═══════════════════════════════════════════════════════════
 *  TEST 1: Field Detection
 * ═══════════════════════════════════════════════════════════ */
static void test_field_detection(void)
{
    ESP_LOGW(TAG, "");
    ESP_LOGW(TAG, "╔═══ TEST 1: DETECÇÃO DE CAMPO ═══");
    ESP_LOGW(TAG, "│ APROXIME O CELULAR/LEITOR AGORA!");
    ESP_LOGW(TAG, "│");

    /* A: EN only (oscillator running, needed for measurement) */
    hb_spi_reg_write(REG_OP_CTRL, 0x80);
    vTaskDelay(pdMS_TO_TICKS(50));  /* Wait for osc */
    uint8_t ad_en = measure_field();
    uint8_t aux_en = read_aux();
    ESP_LOGW(TAG, "│ [A] OP=0x80 (EN)     → AD=%3d AUX=0x%02X [osc=%d] %s",
             ad_en, aux_en, (aux_en >> 2) & 1, ad_en > 5 ? "✓" : "✗");

    /* B: EN + RX_EN */
    hb_spi_reg_write(REG_OP_CTRL, 0xC0);
    vTaskDelay(pdMS_TO_TICKS(10));
    uint8_t ad_rx = measure_field();
    uint8_t aux_rx = read_aux();
    ESP_LOGW(TAG, "│ [B] OP=0xC0 (EN+RX)  → AD=%3d AUX=0x%02X [osc=%d] %s",
             ad_rx, aux_rx, (aux_rx >> 2) & 1, ad_rx > 5 ? "✓" : "✗");

    /* D: Multiple reads over 5 seconds */
    ESP_LOGW(TAG, "│");
    ESP_LOGW(TAG, "│ Leitura contínua por 5s:");
    uint8_t max_ad = 0;
    for (int i = 0; i < 50; i++) {
        uint8_t ad = measure_field();
        if (ad > max_ad) max_ad = ad;
        if ((i % 10) == 0) {
            uint8_t a = read_aux();
            ESP_LOGW(TAG, "│   t=%dms: AD=%3d AUX=0x%02X [efd=%d osc=%d]",
                     i * 100, ad, a, a & 1, (a >> 2) & 1);
        }
        vTaskDelay(pdMS_TO_TICKS(100));
    }

    ESP_LOGW(TAG, "│ AD máximo: %d", max_ad);
    if (max_ad < 5) {
        ESP_LOGE(TAG, "│ ⚠ NENHUM CAMPO EXTERNO DETECTADO!");
        ESP_LOGE(TAG, "│   → Verifique se o leitor NFC está ligado e próximo");
        ESP_LOGE(TAG, "│   → A antena pode não captar campo externo (só TX)");
    }
    ESP_LOGW(TAG, "╚════════════════════════════════════════");
}

/* ═══════════════════════════════════════════════════════════
 *  TEST 2: Target Config + GOTO_SENSE + IRQ Monitor
 * ═══════════════════════════════════════════════════════════ */
static bool test_target_config(int cfg_num, uint8_t op_ctrl,
                                uint8_t fld_act, uint8_t fld_deact,
                                uint8_t pt_mod, uint8_t passive_target)
{
    ESP_LOGW(TAG, "");
    ESP_LOGW(TAG, "╔═══ TEST 2.%d: CONFIG (OP=0x%02X PT=0x%02X ACT=0x%02X DEACT=0x%02X MOD=0x%02X) ═══",
             cfg_num, op_ctrl, passive_target, fld_act, fld_deact, pt_mod);

    /* Full reset */
    hb_spi_reg_write(REG_OP_CTRL, 0x00);
    vTaskDelay(pdMS_TO_TICKS(2));
    hb_spi_direct_cmd(CMD_SET_DEFAULT);
    vTaskDelay(pdMS_TO_TICKS(10));

    uint8_t ic = 0;
    hb_spi_reg_read(REG_IC_IDENTITY, &ic);
    if (ic == 0x00 || ic == 0xFF) {
        ESP_LOGE(TAG, "│ CHIP MORTO! IC=0x%02X", ic);
        ESP_LOGW(TAG, "╚════════════════════════════════════════");
        return false;
    }

    /* START OSCILLATOR — must be done before anything else! */
    hb_spi_reg_write(REG_OP_CTRL, 0x80);  /* EN → oscillator starts */
    bool osc = false;
    for (int i = 0; i < 100; i++) {
        uint8_t aux = 0;
        hb_spi_reg_read(REG_AUX_DISPLAY, &aux);
        if (aux & 0x04) { osc = true; break; }
        vTaskDelay(1);
    }
    ESP_LOGW(TAG, "│ Oscilador: %s", osc ? "✓ OK" : "✗ NÃO ESTÁVEL");

    /* Calibrate regulators */
    hb_spi_direct_cmd(CMD_ADJUST_REGULATORS);
    vTaskDelay(pdMS_TO_TICKS(5));

    /* Target NFC-A */
    hb_spi_reg_write(REG_MODE, 0x88);
    hb_spi_reg_write(REG_BIT_RATE, 0x00);
    hb_spi_reg_write(REG_ISO14443A, 0x00);
    hb_spi_reg_write(REG_PASSIVE_TARGET, passive_target);

    /* Thresholds + modulation */
    hb_spi_reg_write(REG_FIELD_THRESH_ACT, fld_act);
    hb_spi_reg_write(REG_FIELD_THRESH_DEACT, fld_deact);
    hb_spi_reg_write(REG_PT_MOD, pt_mod);

    /* Load PT Memory */
    mfc_emu_load_pt_memory();

    /* Unmask ALL interrupts */
    hb_spi_reg_write(REG_MASK_MAIN_INT, 0x00);
    hb_spi_reg_write(REG_MASK_TIMER_NFC_INT, 0x00);
    hb_spi_reg_write(REG_MASK_ERROR_WUP_INT, 0x00);
    hb_spi_reg_write(REG_MASK_TARGET_INT, 0x00);

    /* Clear pending IRQs */
    st25r_irq_read();

    /* Enable chip */
    hb_spi_reg_write(REG_OP_CTRL, op_ctrl);
    vTaskDelay(pdMS_TO_TICKS(5));

    /* Verify */
    uint8_t mode_rb = 0, op_rb = 0;
    hb_spi_reg_read(REG_MODE, &mode_rb);
    hb_spi_reg_read(REG_OP_CTRL, &op_rb);
    uint8_t aux0 = read_aux();
    ESP_LOGW(TAG, "│ Pre-SENSE: MODE=0x%02X OP=0x%02X AUX=0x%02X [osc=%d efd=%d]",
             mode_rb, op_rb, aux0, (aux0 >> 2) & 1, aux0 & 1);

    /* GOTO_SENSE */
    hb_spi_direct_cmd(CMD_GOTO_SENSE);
    vTaskDelay(pdMS_TO_TICKS(10));

    uint8_t pt_sts = 0;
    hb_spi_reg_read(REG_PASSIVE_TARGET_STS, &pt_sts);
    uint8_t aux1 = read_aux();
    ESP_LOGW(TAG, "│ Pós-SENSE: PT_STS=0x%02X AUX=0x%02X [osc=%d efd=%d tgt=%d]",
             pt_sts, aux1, (aux1 >> 2) & 1, aux1 & 1, (aux1 >> 7) & 1);

    /* Monitor IRQs for 10 seconds */
    ESP_LOGW(TAG, "│ Monitorando 10s (LEITOR PERTO!)...");

    bool wu_a = false, sdd_c = false, any_irq = false;
    int64_t t0 = esp_timer_get_time();
    int last_report = -1;

    while ((esp_timer_get_time() - t0) < 10000000LL) {
        uint8_t tgt_irq = 0, main_irq = 0, err_irq = 0;
        hb_spi_reg_read(REG_TARGET_INT, &tgt_irq);
        hb_spi_reg_read(REG_MAIN_INT, &main_irq);
        hb_spi_reg_read(REG_ERROR_INT, &err_irq);

        if (tgt_irq || main_irq || err_irq) {
            int ms = (int)((esp_timer_get_time() - t0) / 1000);
            ESP_LOGW(TAG, "│ [%dms] TGT=0x%02X MAIN=0x%02X ERR=0x%02X",
                     ms, tgt_irq, main_irq, err_irq);
            any_irq = true;
            if (tgt_irq & 0x80) { ESP_LOGI(TAG, "│  → WU_A!"); wu_a = true; }
            if (tgt_irq & 0x40) { ESP_LOGI(TAG, "│  → WU_A_X (anti-col done)!"); }
            if (tgt_irq & 0x04) { ESP_LOGI(TAG, "│  → SDD_C (SELECTED)!"); sdd_c = true; }
            if (tgt_irq & 0x08) { ESP_LOGI(TAG, "│  → OSCF (osc stable)"); }
            if (main_irq & 0x04) {
                ESP_LOGI(TAG, "│  → RXE (data received)!");
                uint8_t fs1 = 0;
                hb_spi_reg_read(REG_FIFO_STATUS1, &fs1);
                ESP_LOGI(TAG, "│    FIFO: %d bytes", fs1);
            }
        }

        int sec = (int)((esp_timer_get_time() - t0) / 1000000);
        if (sec != last_report && (sec % 3) == 0) {
            last_report = sec;
            uint8_t ad = measure_field();
            uint8_t a = read_aux();
            /* Re-enter SENSE after measurement disruption */
            hb_spi_direct_cmd(CMD_GOTO_SENSE);
            ESP_LOGW(TAG, "│ [%ds] AD=%d AUX=0x%02X [efd=%d osc=%d]",
                     sec, ad, a, a & 1, (a >> 2) & 1);
        }

        vTaskDelay(1);
    }

    /* Result */
    ESP_LOGW(TAG, "│");
    if (sdd_c) {
        ESP_LOGI(TAG, "│ ✓✓✓ CONFIG %d: SUCESSO — SELECIONADO!", cfg_num);
    } else if (wu_a) {
        ESP_LOGI(TAG, "│ ✓✓  CONFIG %d: Campo visto, anti-col falhou", cfg_num);
    } else if (any_irq) {
        ESP_LOGW(TAG, "│ ✓   CONFIG %d: IRQ vista mas sem WU_A", cfg_num);
    } else {
        ESP_LOGE(TAG, "│ ✗   CONFIG %d: NENHUMA IRQ em 10s", cfg_num);
    }
    ESP_LOGW(TAG, "╚════════════════════════════════════════");

    return sdd_c;
}

/* ═══════════════════════════════════════════════════════════
 *  TEST 3: PT Memory Verification
 * ═══════════════════════════════════════════════════════════ */
static void test_pt_memory(void)
{
    ESP_LOGW(TAG, "");
    ESP_LOGW(TAG, "╔═══ TEST 3: PT MEMORY ═══");

    uint8_t ptm[15] = {0};
    hb_spi_pt_mem_read(ptm, 15);

    ESP_LOGW(TAG, "│ PT Memory: %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X",
             ptm[0], ptm[1], ptm[2], ptm[3], ptm[4], ptm[5], ptm[6], ptm[7],
             ptm[8], ptm[9], ptm[10], ptm[11], ptm[12], ptm[13], ptm[14]);
    ESP_LOGW(TAG, "│ ATQA=%02X%02X  UID=%02X%02X%02X%02X  BCC=%02X(calc:%02X)  SAK=%02X",
             ptm[0], ptm[1], ptm[2], ptm[3], ptm[4], ptm[5],
             ptm[6], ptm[2] ^ ptm[3] ^ ptm[4] ^ ptm[5], ptm[7]);

    bool bcc_ok = (ptm[6] == (ptm[2] ^ ptm[3] ^ ptm[4] ^ ptm[5]));
    ESP_LOGW(TAG, "│ BCC: %s", bcc_ok ? "✓ OK" : "✗ ERRADO!");

    /* Write test pattern + readback */
    uint8_t test[15] = {0x04, 0x00, 0xDE, 0xAD, 0xBE, 0xEF,
                         0xDE ^ 0xAD ^ 0xBE ^ 0xEF, 0x08, 0,0,0,0,0,0,0};
    hb_spi_pt_mem_write(SPI_PT_MEM_A_WRITE, test, 15);
    vTaskDelay(1);
    uint8_t rb[15] = {0};
    hb_spi_pt_mem_read(rb, 15);
    bool match = (memcmp(test, rb, 15) == 0);
    ESP_LOGW(TAG, "│ Write/Read test: %s", match ? "✓ OK" : "✗ FALHOU!");
    if (!match) {
        ESP_LOGW(TAG, "│  Escrito: %02X %02X %02X %02X %02X %02X %02X %02X",
                 test[0],test[1],test[2],test[3],test[4],test[5],test[6],test[7]);
        ESP_LOGW(TAG, "│  Lido:    %02X %02X %02X %02X %02X %02X %02X %02X",
                 rb[0],rb[1],rb[2],rb[3],rb[4],rb[5],rb[6],rb[7]);
    }

    /* Restore */
    mfc_emu_load_pt_memory();
    ESP_LOGW(TAG, "╚════════════════════════════════════════");
}

/* ═══════════════════════════════════════════════════════════
 *  TEST 4: Oscillator/Regulator
 * ═══════════════════════════════════════════════════════════ */
static void test_oscillator(void)
{
    ESP_LOGW(TAG, "");
    ESP_LOGW(TAG, "╔═══ TEST 4: OSCILADOR ═══");

    /* First check current state */
    uint8_t aux = read_aux();
    ESP_LOGW(TAG, "│ AUX_DISPLAY=0x%02X (antes de ligar EN)", aux);
    ESP_LOGW(TAG, "│   osc_ok=%d  efd_o=%d  rx_on=%d  tgt=%d",
             (aux>>2)&1, (aux>>0)&1, (aux>>4)&1, (aux>>7)&1);

    /* Enable EN to start oscillator */
    hb_spi_reg_write(REG_OP_CTRL, 0x80);
    ESP_LOGW(TAG, "│ OP_CTRL=0x80 (EN) → Ligando oscilador...");

    /* Wait and poll for osc_ok */
    bool osc_started = false;
    for (int i = 0; i < 100; i++) {
        uint8_t a = 0;
        hb_spi_reg_read(REG_AUX_DISPLAY, &a);
        if (a & 0x04) {
            ESP_LOGI(TAG, "│ ✓ Oscilador estável em %dms! AUX=0x%02X", i * 10, a);
            osc_started = true;
            break;
        }
        vTaskDelay(1);
    }

    if (!osc_started) {
        aux = read_aux();
        ESP_LOGE(TAG, "│ ✗ Oscilador NÃO iniciou após 1s. AUX=0x%02X", aux);
        ESP_LOGE(TAG, "│   Bits: efd_o=%d efd_i=%d osc=%d nfc_t=%d rx_on=%d",
                 (aux>>0)&1, (aux>>1)&1, (aux>>2)&1, (aux>>3)&1, (aux>>4)&1);
    }

    /* Calibrate regulators (needs oscillator) */
    hb_spi_direct_cmd(CMD_ADJUST_REGULATORS);
    vTaskDelay(pdMS_TO_TICKS(10));

    uint8_t rc = 0;
    hb_spi_reg_read(REG_REGULATOR_CTRL, &rc);
    aux = read_aux();
    ESP_LOGW(TAG, "│ Após calibração: AUX=0x%02X REG_CTRL=0x%02X", aux, rc);
    ESP_LOGW(TAG, "╚════════════════════════════════════════");
}

/* ──────────────────────────────────────────────────────────────
 *  TEST X: AUX_DEF sweep (try enabling EFD/field detect bits)
 * ────────────────────────────────────────────────────────────── */
static void test_aux_def_sweep(void)
{
    static const uint8_t vals[] = {
        0x00, 0x01, 0x02, 0x04, 0x08,
        0x10, 0x20, 0x40, 0x80, 0xFF
    };

    ESP_LOGW(TAG, "");
    ESP_LOGW(TAG, "╔═══ TEST X: AUX_DEF SWEEP ═══");
    ESP_LOGW(TAG, "│ (procure AD>0 ou efd=1 com o leitor próximo)");

    hb_spi_reg_write(REG_OP_CTRL, OP_CTRL_EN | OP_CTRL_RX_EN);
    vTaskDelay(pdMS_TO_TICKS(5));

    for (size_t i = 0; i < sizeof(vals) / sizeof(vals[0]); i++) {
        uint8_t v = vals[i];
        hb_spi_reg_write(REG_AUX_DEF, v);
        vTaskDelay(1);
        hb_spi_direct_cmd(CMD_MEAS_AMPLITUDE);
        vTaskDelay(2);
        uint8_t ad = 0;
        hb_spi_reg_read(REG_AD_RESULT, &ad);
        uint8_t aux = read_aux();
        ESP_LOGW(TAG, "│ AUX_DEF=0x%02X -> AD=%3u AUX=0x%02X [efd_o=%d efd_i=%d]",
                 v, ad, aux, aux & 1, (aux >> 1) & 1);
    }

    hb_spi_reg_write(REG_AUX_DEF, 0x00);
    hb_spi_reg_write(REG_OP_CTRL, 0x00);
    ESP_LOGW(TAG, "╚════════════════════════════════════════");
}
/* ──────────────────────────────────────────────────────────────
 *  TEST 0: Poller vs Target register diff
 * ────────────────────────────────────────────────────────────── */
static void test_poller_vs_target_regs(void)
{
    ESP_LOGW(TAG, "");
    ESP_LOGW(TAG, "╔═══ TEST 0: DIFF POLLER vs TARGET ═══");

    static uint8_t poller[64];
    static uint8_t target[64];
    static mfc_emu_card_data_t emu;
    memset(poller, 0, sizeof(poller));
    memset(target, 0, sizeof(target));
    memset(&emu, 0, sizeof(emu));

    /* Poller baseline (known working for reads/writes) */
    st25r_set_mode_nfca();
    st25r_field_on();
    vTaskDelay(pdMS_TO_TICKS(5));
    read_regs(poller);
    st25r_field_off();

    /* Target config (same path as emulation) */
    emu.uid_len = 4;
    emu.uid[0] = 0x04; emu.uid[1] = 0x11; emu.uid[2] = 0x22; emu.uid[3] = 0x33;
    emu.atqa[0] = 0x44; emu.atqa[1] = 0x00;
    emu.sak = 0x04;
    emu.type = MF_CLASSIC_1K;
    emu.sector_count = 0;
    emu.total_blocks = 0;

    (void)mfc_emu_init(&emu);
    (void)mfc_emu_configure_target();
    read_regs(target);

    diff_key_regs("POLL", poller, "TGT", target);
    ESP_LOGW(TAG, "╚════════════════════════════════════════");
}

/* ──────────────────────────────────────────────────────────────
 *  TEST Y: RSSI monitor (look for any RF activity)
 * ────────────────────────────────────────────────────────────── */
static void test_rssi_monitor(int seconds)
{
    ESP_LOGW(TAG, "");
    ESP_LOGW(TAG, "╔═══ TEST Y: RSSI MONITOR (%ds) ═══", seconds);
    ESP_LOGW(TAG, "│ (leitor NFC deve ficar encostado)");

    hb_spi_reg_write(REG_OP_CTRL, OP_CTRL_EN | OP_CTRL_RX_EN);
    vTaskDelay(pdMS_TO_TICKS(5));
    hb_spi_direct_cmd(CMD_CLEAR_RSSI);
    vTaskDelay(pdMS_TO_TICKS(2));

    for (int i = 0; i < seconds; i++) {
        uint8_t rssi = 0, aux = 0;
        hb_spi_reg_read(REG_RSSI_RESULT, &rssi);
        hb_spi_reg_read(REG_AUX_DISPLAY, &aux);
        ESP_LOGW(TAG, "│ t=%ds RSSI=0x%02X AUX=0x%02X [efd=%d osc=%d]",
                 i, rssi, aux, aux & 1, (aux >> 2) & 1);
        vTaskDelay(pdMS_TO_TICKS(1000));
    }

    hb_spi_reg_write(REG_OP_CTRL, 0x00);
    ESP_LOGW(TAG, "╚════════════════════════════════════════");
}

/* ──────────────────────────────────────────────────────────────
 *  TEST Z: NFC RF Collision commands
 * ────────────────────────────────────────────────────────────── */
static void test_rf_collision(void)
{
    ESP_LOGW(TAG, "");
    ESP_LOGW(TAG, "╔═══ TEST Z: RF COLLISION (NFC INITIAL) ═══");
    ESP_LOGW(TAG, "│ (leitor NFC encostado, aguardando IRQ)");

    /* Target config baseline */
    hb_spi_reg_write(REG_MODE, MODE_TARGET_NFCA);
    hb_spi_reg_write(REG_BIT_RATE, 0x00);
    hb_spi_reg_write(REG_ISO14443A, 0x00);
    hb_spi_reg_write(REG_PASSIVE_TARGET, 0x00);
    hb_spi_reg_write(REG_FIELD_THRESH_ACT, 0x33);
    hb_spi_reg_write(REG_FIELD_THRESH_DEACT, 0x22);
    hb_spi_reg_write(REG_PT_MOD, 0x60);
    mfc_emu_load_pt_memory();

    hb_spi_reg_write(REG_MASK_MAIN_INT, 0x00);
    hb_spi_reg_write(REG_MASK_TIMER_NFC_INT, 0x00);
    hb_spi_reg_write(REG_MASK_ERROR_WUP_INT, 0x00);
    hb_spi_reg_write(REG_MASK_TARGET_INT, 0x00);
    st25r_irq_read();

    hb_spi_reg_write(REG_OP_CTRL, OP_CTRL_EN | OP_CTRL_RX_EN);
    vTaskDelay(pdMS_TO_TICKS(5));

    hb_spi_direct_cmd(CMD_NFC_INITIAL_RF_COL);
    vTaskDelay(pdMS_TO_TICKS(2));
    hb_spi_direct_cmd(CMD_GOTO_SENSE);

    /* Monitor for 5s */
    int64_t t0 = esp_timer_get_time();
    while ((esp_timer_get_time() - t0) < 5000000LL) {
        uint8_t tgt = 0, main = 0, err = 0;
        hb_spi_reg_read(REG_TARGET_INT, &tgt);
        hb_spi_reg_read(REG_MAIN_INT, &main);
        hb_spi_reg_read(REG_ERROR_INT, &err);
        if (tgt || main || err) {
            int ms = (int)((esp_timer_get_time() - t0) / 1000);
            ESP_LOGW(TAG, "│ [%dms] TGT=0x%02X MAIN=0x%02X ERR=0x%02X",
                     ms, tgt, main, err);
        }
        vTaskDelay(pdMS_TO_TICKS(50));
    }

    hb_spi_reg_write(REG_OP_CTRL, 0x00);
    ESP_LOGW(TAG, "╚════════════════════════════════════════");
}
/* ═══════════════════════════════════════════════════════════
 *  MAIN DIAGNOSTIC
 * ═══════════════════════════════════════════════════════════ */
hb_nfc_err_t emu_diag_full(void)
{
    ESP_LOGW(TAG, "");
    ESP_LOGW(TAG, "╔══════════════════════════════════════════════════╗");
    ESP_LOGW(TAG, "║  🔍 DIAGNÓSTICO DE EMULAÇÃO v2                   ║");
    ESP_LOGW(TAG, "║                                                  ║");
    ESP_LOGW(TAG, "║  ⚡ MANTENHA O LEITOR NFC PRÓXIMO DURANTE       ║");
    ESP_LOGW(TAG, "║     TODO O DIAGNÓSTICO (~60s total)              ║");
    ESP_LOGW(TAG, "╚══════════════════════════════════════════════════╝");
    ESP_LOGW(TAG, "");
    ESP_LOGW(TAG, "Aguardando 5s... Aproxime o leitor NFC agora!");
    vTaskDelay(pdMS_TO_TICKS(5000));

    /* State before any changes */
    dump_key_regs("ESTADO INICIAL");

    /* Poller vs Target register diff */
    test_poller_vs_target_regs();

    /* Oscillator check */
    test_oscillator();

    /* AUX_DEF sweep */
    test_aux_def_sweep();

    /* RSSI monitor */
    test_rssi_monitor(5);

    /* PT Memory check */
    test_pt_memory();

    /* Field detection (5s of measurement) */
    test_field_detection();

    /* RF collision test */
    test_rf_collision();

    /* ── Try 4 different target configurations, 10s each ── */

    /* Config 1: Our current approach (EN only, moderate thresholds) */
    bool ok1 = test_target_config(1, 0xC0, 0x33, 0x22, 0x60, 0x00);
    if (ok1) goto done;

    /* Config 2: EN + RX_EN + WU */
    bool ok2 = test_target_config(2, 0xC4, 0x33, 0x22, 0x60, 0x00);
    if (ok2) goto done;

    /* Config 3: EN only (poller-like thresholds) */
    bool ok3 = test_target_config(3, 0x80, 0x33, 0x22, 0x60, 0x00);
    if (ok3) goto done;

    /* Config 4: old low-threshold setup */
    test_target_config(4, 0xC0, 0x03, 0x01, 0x17, 0x00);

done:
    dump_key_regs("ESTADO FINAL");

    ESP_LOGW(TAG, "");
    ESP_LOGW(TAG, "╔══════════════════════════════════════════════════╗");
    ESP_LOGW(TAG, "║  📋 DIAGNÓSTICO COMPLETO                         ║");
    ESP_LOGW(TAG, "║                                                  ║");
    ESP_LOGW(TAG, "║  Se AD sempre = 0:                               ║");
    ESP_LOGW(TAG, "║    → Antena não capta campo externo              ║");
    ESP_LOGW(TAG, "║    → Precisa circuito matching p/ RX passivo     ║");
    ESP_LOGW(TAG, "║                                                  ║");
    ESP_LOGW(TAG, "║  Se AD > 0 mas sem WU_A:                         ║");
    ESP_LOGW(TAG, "║    → GOTO_SENSE não está ativando corretamente   ║");
    ESP_LOGW(TAG, "║    → Ou threshold precisa ser ajustado           ║");
    ESP_LOGW(TAG, "║                                                  ║");
    ESP_LOGW(TAG, "║  Se WU_A ok mas sem SDD_C:                       ║");
    ESP_LOGW(TAG, "║    → PT Memory ou anti-collision com problema    ║");
    ESP_LOGW(TAG, "║                                                  ║");
    ESP_LOGW(TAG, "║  ⚡ COPIE TODA A SAÍDA SERIAL E COMPARTILHE!    ║");
    ESP_LOGW(TAG, "╚══════════════════════════════════════════════════╝");

    return HB_NFC_OK;
}

void emu_diag_monitor(int seconds)
{
    ESP_LOGW(TAG, "Monitor %ds...", seconds);
    int64_t t0 = esp_timer_get_time();
    while ((esp_timer_get_time() - t0) < (int64_t)seconds * 1000000LL) {
        uint8_t tgt = 0, mi = 0, ei = 0;
        hb_spi_reg_read(REG_TARGET_INT, &tgt);
        hb_spi_reg_read(REG_MAIN_INT, &mi);
        hb_spi_reg_read(REG_ERROR_INT, &ei);
        if (tgt || mi || ei) {
            ESP_LOGW(TAG, "[%dms] TGT=0x%02X MAIN=0x%02X ERR=0x%02X",
                     (int)((esp_timer_get_time() - t0) / 1000), tgt, mi, ei);
        }
        vTaskDelay(1);
    }
}
#undef TAG

