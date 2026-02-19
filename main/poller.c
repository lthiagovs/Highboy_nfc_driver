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
#include "st25r3916_reg.h"
#include "st25r3916_fifo.h"
#include "st25r3916_irq.h"
#include "hb_nfc_spi.h"
#include "hb_nfc_timer.h"

#include "esp_log.h"

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
 * Re-select — from working code reselect() macro:
 *   WUPA → anticoll CL1 → select CL1
 *
 * Note: This is a simplified re-select that only does CL1.
 * For 7/10-byte UIDs the full cascade would need to be repeated.
 */
hb_nfc_err_t iso14443a_poller_reselect(nfc_iso14443a_data_t* card)
{
    uint8_t atqa[2];
    if (req_cmd(CMD_TX_WUPA, atqa) != 2) return HB_NFC_ERR_NO_CARD;

    uint8_t uid_cl[5];
    if (iso14443a_poller_anticoll(SEL_CL1, uid_cl) != 5) return HB_NFC_ERR_COLLISION;
    if (!iso14443a_poller_sel(SEL_CL1, uid_cl, &card->sak)) return HB_NFC_ERR_PROTOCOL;

    /* For 7-byte UID, do CL2 too */
    if (card->sak & 0x04) {
        if (iso14443a_poller_anticoll(SEL_CL2, uid_cl) != 5) return HB_NFC_ERR_COLLISION;
        if (!iso14443a_poller_sel(SEL_CL2, uid_cl, &card->sak)) return HB_NFC_ERR_PROTOCOL;
    }

    return HB_NFC_OK;
}
