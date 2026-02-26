/* === main\iso14443a.c === */
/**
 * @file iso14443a.c
 * @brief ISO14443A — CRC_A calculation.
 */
#include "iso14443a.h"

void iso14443a_crc(const uint8_t* data, size_t len, uint8_t crc[2])
{
    uint32_t wCrc = 0x6363;
    for (size_t i = 0; i < len; i++) {
        uint8_t bt = data[i];
        bt = (bt ^ (uint8_t)(wCrc & 0x00FF));
        bt = (bt ^ (bt << 4));
        wCrc = (wCrc >> 8) ^
               ((uint32_t)bt << 8) ^
               ((uint32_t)bt << 3) ^
               ((uint32_t)bt >> 4);
    }
    crc[0] = (uint8_t)(wCrc & 0xFF);
    crc[1] = (uint8_t)((wCrc >> 8) & 0xFF);
}

bool iso14443a_check_crc(const uint8_t* data, size_t len)
{
    if (len < 3) return false;
    uint8_t crc[2];
    iso14443a_crc(data, len - 2, crc);
    return (crc[0] == data[len - 2]) && (crc[1] == data[len - 1]);
}

/* === main\poller.c === */
/**
 * @file poller.c
 * @brief ISO14443A Poller — exact refactor of working code.
 *
 * Every function maps 1:1 to the working code. Comments show
 * the original function name and the exact byte values used.
 */
#include "poller.h"
#include "iso14443a.h"
#include "nfc_poller.h"
#include "nfc_common.h"
#include "st25r3916_cmd.h"
#include "st25r3916_core.h"
#include "st25r3916_reg.h"
#include "st25r3916_fifo.h"
#include "st25r3916_irq.h"
#include "hb_nfc_spi.h"
#include "hb_nfc_timer.h"

#include "esp_log.h"

#define TAG TAG_14443A
static const char* TAG = "14443a";

/* ═══════════════════════════════════════════════════════ */
/*  Anti-collision control                                  */
/* ═══════════════════════════════════════════════════════ */

/**
 * Enable/disable anti-collision — from working code st25r_set_antcl():
 *   Read REG_ISO14443A, set or clear bit 0.
 */
static void set_antcl(bool enable)
{
    uint8_t v;
    hb_spi_reg_read(REG_ISO14443A, &v);
    if (enable) v |= ISO14443A_ANTCL;
    else        v &= (uint8_t)~ISO14443A_ANTCL;
    hb_spi_reg_write(REG_ISO14443A, v);
}

/* ═══════════════════════════════════════════════════════ */
/*  REQA / WUPA                                             */
/* ═══════════════════════════════════════════════════════ */

/**
 * Internal REQA/WUPA — from working code st25r_req_cmd():
 *   1. set_antcl(false)
 *   2. CMD_CLEAR_FIFO
 *   3. Direct command (CMD_TX_REQA or CMD_TX_WUPA)
 *   4. Wait TXE (50us × 400)
 *   5. Wait FIFO ≥ 2 bytes, timeout 10ms
 *   6. Read 2 bytes → ATQA
 */
static int req_cmd(uint8_t cmd, uint8_t atqa[2])
{
    set_antcl(false);
    st25r_fifo_clear();
    hb_spi_direct_cmd(cmd);

    /* Wait TXE */
    if (!st25r_irq_wait_txe()) return 0;

    /* Wait FIFO */
    uint16_t count = 0;
    if (st25r_fifo_wait(2, 10, &count) < 2) {
        st25r_irq_log((cmd == CMD_TX_REQA) ? "REQA fail" : "WUPA fail", count);
        return 0;
    }
    st25r_fifo_read(atqa, 2);
    return 2;
}

int iso14443a_poller_reqa(uint8_t atqa[2])
{
    return req_cmd(CMD_TX_REQA, atqa);
}

int iso14443a_poller_wupa(uint8_t atqa[2])
{
    return req_cmd(CMD_TX_WUPA, atqa);
}

/**
 * Activate — from working code st25r_reqA_or_wupa():
 *   Try REQA first. If no response, wait 5ms and try WUPA.
 */
hb_nfc_err_t iso14443a_poller_activate(uint8_t atqa[2])
{
    if (req_cmd(CMD_TX_REQA, atqa) == 2) return HB_NFC_OK;
    hb_delay_us(5000);
    if (req_cmd(CMD_TX_WUPA, atqa) == 2) return HB_NFC_OK;
    return HB_NFC_ERR_NO_CARD;
}

/* ═══════════════════════════════════════════════════════ */
/*  Anti-collision + SELECT                                 */
/* ═══════════════════════════════════════════════════════ */

/**
 * Anti-collision — from working code st25r_anticollision():
 *   cmd = { sel, 0x20 }
 *   set_antcl(true)
 *   transceive(cmd, 2, no_crc, rx, 5, 5, 20ms)
 *   set_antcl(false)
 *   Retry up to 3 times with 5ms delay.
 */
int iso14443a_poller_anticoll(uint8_t sel, uint8_t uid_cl[5])
{
    uint8_t cmd[2] = { sel, 0x20 };

    for (int attempt = 0; attempt < 3; attempt++) {
        set_antcl(true);
        int len = nfc_poller_transceive(cmd, 2, false, uid_cl, 5, 5, 20);
        set_antcl(false);

        if (len == 5) return 5;
        hb_delay_us(5000);
    }
    return 0;
}

/**
 * SELECT — from working code st25r_select():
 *   cmd = { sel, 0x70, uid[0..4] }
 *   transceive(cmd, 7, with_crc, rx, 4, 1, 10ms)
 *   sak = rx[0]
 */
int iso14443a_poller_sel(uint8_t sel, const uint8_t uid_cl[5], uint8_t* sak)
{
    uint8_t cmd[7] = {
        sel, 0x70,
        uid_cl[0], uid_cl[1], uid_cl[2], uid_cl[3], uid_cl[4]
    };
    uint8_t rx[4] = { 0 };
    int len = nfc_poller_transceive(cmd, 7, true, rx, sizeof(rx), 1, 10);
    if (len < 1) return 0;
    *sak = rx[0];
    return 1;
}

/* ═══════════════════════════════════════════════════════ */
/*  Full card selection (all cascade levels)                */
/* ═══════════════════════════════════════════════════════ */

/**
 * Full SELECT — exact logic from working code app_main() UID assembly:
 *
 *   CL1: anticoll(0x93) → select(0x93)
 *     if uid_cl[0] == 0x88 → cascade tag, uid = cl[1..3]
 *     else → uid = cl[0..3]
 *     if SAK & 0x04 → more levels
 *
 *   CL2: anticoll(0x95) → select(0x95)
 *     same cascade check
 *
 *   CL3: anticoll(0x97) → select(0x97)
 *     uid = cl[0..3] (always final)
 */
hb_nfc_err_t iso14443a_poller_select(nfc_iso14443a_data_t* card)
{
    if (!card) return HB_NFC_ERR_PARAM;

    uint8_t atqa[2];
    hb_nfc_err_t err = iso14443a_poller_activate(atqa);
    if (err != HB_NFC_OK) return err;

    card->atqa[0] = atqa[0];
    card->atqa[1] = atqa[1];
    card->uid_len = 0;
    nfc_log_hex("ATQA:", atqa, 2);

    /* Cascade levels */
    static const uint8_t sel_cmds[] = { SEL_CL1, SEL_CL2, SEL_CL3 };

    for (int cl = 0; cl < 3; cl++) {
        uint8_t uid_cl[5] = { 0 };
        uint8_t sak = 0;

        /* Anti-collision */
        if (iso14443a_poller_anticoll(sel_cmds[cl], uid_cl) != 5) {
            ESP_LOGW(TAG, "Anticoll CL%d failed", cl + 1);
            return HB_NFC_ERR_COLLISION;
        }
        nfc_log_hex(cl == 0 ? "CL1:" : cl == 1 ? "CL2:" : "CL3:", uid_cl, 5);

        /* SELECT */
        if (!iso14443a_poller_sel(sel_cmds[cl], uid_cl, &sak)) {
            ESP_LOGW(TAG, "Select CL%d failed", cl + 1);
            return HB_NFC_ERR_PROTOCOL;
        }
        ESP_LOGI(TAG, "SAK CL%d: 0x%02X", cl + 1, sak);

        /* UID assembly — exact logic from working code */
        if (uid_cl[0] == 0x88) {
            /* Cascade tag: UID bytes are [1..3] */
            card->uid[card->uid_len++] = uid_cl[1];
            card->uid[card->uid_len++] = uid_cl[2];
            card->uid[card->uid_len++] = uid_cl[3];
        } else {
            /* Final level: UID bytes are [0..3] */
            card->uid[card->uid_len++] = uid_cl[0];
            card->uid[card->uid_len++] = uid_cl[1];
            card->uid[card->uid_len++] = uid_cl[2];
            card->uid[card->uid_len++] = uid_cl[3];
        }

        card->sak = sak;

        /* Check if more cascade levels needed */
        if (!(sak & 0x04)) {
            /* No more levels */
            break;
        }
    }

    nfc_log_hex("UID:", card->uid, card->uid_len);
    return HB_NFC_OK;
}

/**
 * Re-select a card after Crypto1 session.
 *
 * After Crypto1 authentication the card is in AUTHENTICATED state
 * and will NOT respond to WUPA/REQA. We must power-cycle the RF field
 * to force the card back to IDLE state, then do full activation.
 *
 * Flow: field OFF → field ON → REQA/WUPA → anticoll → select (all CLs)
 */
hb_nfc_err_t iso14443a_poller_reselect(nfc_iso14443a_data_t* card)
{
    /* Power-cycle the RF field to reset card state */
    st25r_field_cycle();

    /* Now do full activation (REQA/WUPA → anticoll → select) */
    uint8_t atqa[2];
    hb_nfc_err_t err = iso14443a_poller_activate(atqa);
    if (err != HB_NFC_OK) return err;

    /* Anti-collision + SELECT for all cascade levels */
    static const uint8_t sel_cmds[] = { SEL_CL1, SEL_CL2, SEL_CL3 };

    for (int cl = 0; cl < 3; cl++) {
        uint8_t uid_cl[5] = { 0 };
        uint8_t sak = 0;

        if (iso14443a_poller_anticoll(sel_cmds[cl], uid_cl) != 5) {
            return HB_NFC_ERR_COLLISION;
        }
        if (!iso14443a_poller_sel(sel_cmds[cl], uid_cl, &sak)) {
            return HB_NFC_ERR_PROTOCOL;
        }

        card->sak = sak;

        /* Check if more cascade levels needed */
        if (!(sak & 0x04)) break;
    }

    return HB_NFC_OK;
}
#undef TAG

/* === main\nfc_poller.c === */
/**
 * @file nfc_poller.c
 * @brief NFC Poller — transceive engine (exact copy of working code).
 */
#include "nfc_poller.h"
#include "nfc_common.h"
#include "st25r3916_core.h"
#include "st25r3916_cmd.h"
#include "st25r3916_fifo.h"
#include "st25r3916_irq.h"
#include "hb_nfc_spi.h"
#include <stdio.h>
#include "esp_log.h"

#define TAG TAG_NFC_POLL
static const char* TAG = "nfc_poll";

hb_nfc_err_t nfc_poller_start(void)
{
    hb_nfc_err_t err = st25r_set_mode_nfca();
    if (err != HB_NFC_OK) return err;
    return st25r_field_on();
}

void nfc_poller_stop(void)
{
    st25r_field_off();
}

/**
 * Transceive — line-by-line match with working code st25r_transceive().
 *
 * Working code:
 *   st25r_direct_cmd(CMD_CLEAR_FIFO);
 *   st25r_set_nbytes((uint16_t)tx_len, 0);
 *   st25r_fifo_load(tx, tx_len);
 *   st25r_direct_cmd(with_crc ? CMD_TX_WITH_CRC : CMD_TX_WO_CRC);
 *   // poll TXE: 50us × 400
 *   // wait FIFO min_bytes
 *   // read FIFO
 */
int nfc_poller_transceive(const uint8_t* tx, size_t tx_len, bool with_crc,
                           uint8_t* rx, size_t rx_max, size_t rx_min,
                           int timeout_ms)
{
    /* 1. Clear FIFO */
    st25r_fifo_clear();

    /* 2. Set TX byte count */
    st25r_set_tx_bytes((uint16_t)tx_len, 0);

    /* 3. Load TX data into FIFO */
    st25r_fifo_load(tx, tx_len);

    /* 4. Send command */
    hb_spi_direct_cmd(with_crc ? CMD_TX_WITH_CRC : CMD_TX_WO_CRC);

    /* 5. Wait for TX end (poll MAIN_INT bit 3, 50us × 400) */
    if (!st25r_irq_wait_txe()) {
        ESP_LOGW(TAG, "TX timeout");
        return 0;
    }

    /* 6. Wait for RX data in FIFO */
    uint16_t count = 0;
    int got = st25r_fifo_wait(rx_min, timeout_ms, &count);

    /* 7. Check result */
    if (count < rx_min) {
        if (count > 0) {
            size_t to_read = (count > rx_max) ? rx_max : count;
            st25r_fifo_read(rx, to_read);
            nfc_log_hex(" RX partial:", rx, to_read);
        }
        st25r_irq_log("RX fail", count);
        return 0;
    }

    if ((size_t)got > rx_max) got = (int)rx_max;
    st25r_fifo_read(rx, (size_t)got);
    return got;
}

/* ── Log utility ── */
void nfc_log_hex(const char* label, const uint8_t* data, size_t len)
{
    char buf[128];
    size_t pos = 0;
    for (size_t i = 0; i < len && pos + 3 < sizeof(buf); i++) {
        pos += (size_t)snprintf(buf + pos, sizeof(buf) - pos, "%02X%s",
                                data[i], (i + 1 < len) ? " " : "");
    }
    ESP_LOGI("nfc", "%s %s", label, buf);
}
#undef TAG

/* === main\iso_dep.c === */
/**
 * @file iso_dep.c
 * @brief ISO-DEP - basic RATS and I-Block exchange.
 *
 * TODO: PPS, chaining, WTX handling.
 */
#include "iso_dep.h"
#include "nfc_poller.h"
#include "esp_log.h"

#define TAG TAG_ISO_DEP
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

    return nfc_poller_transceive(tx, tx_len, true, rx, rx_max, 1, timeout_ms);
}
#undef TAG

