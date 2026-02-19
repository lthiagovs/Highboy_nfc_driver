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
