/**
 * @file mf_ultralight.c
 * @brief MIFARE Ultralight / NTAG — proven commands from working code.
 */
#include "mf_ultralight.h"
#include "nfc_poller.h"
#include "nfc_common.h"
#include "hb_nfc_timer.h"

#include "esp_log.h"

static const char* TAG = "mful";

/**
 * READ — exact copy of working code st25r_read_pages():
 *   cmd = { 0x30, page }
 *   rx_min = 1 (capture partial for diagnostics)
 *   timeout = 30ms
 */
int mful_read_pages(uint8_t page, uint8_t out[18])
{
    uint8_t cmd[2] = { 0x30, page };
    return nfc_poller_transceive(cmd, 2, true, out, 18, 1, 30);
}

/**
 * WRITE — cmd 0xA2.
 */
hb_nfc_err_t mful_write_page(uint8_t page, const uint8_t data[4])
{
    uint8_t cmd[6] = { 0xA2, page, data[0], data[1], data[2], data[3] };
    uint8_t rx[4] = { 0 };
    int len = nfc_poller_transceive(cmd, 6, true, rx, 4, 1, 20);
    /* NTAG returns ACK (4 bits = 0x0A) for successful write */
    if (len >= 1 && (rx[0] & 0x0F) == 0x0A) return HB_NFC_OK;
    return HB_NFC_ERR_NACK;
}

/**
 * GET_VERSION — exact copy of working code ntag_get_version():
 *   cmd = { 0x60 }
 *   rx_min = 1, rx_max = 8, timeout = 20ms
 */
int mful_get_version(uint8_t out[8])
{
    uint8_t cmd[1] = { 0x60 };
    return nfc_poller_transceive(cmd, 1, true, out, 8, 1, 20);
}

/**
 * PWD_AUTH — exact copy of working code ntag_pwd_auth():
 *   cmd = { 0x1B, pwd[0..3] }
 *   rx_min = 2 (PACK)
 *   timeout = 20ms
 *   Post-auth delay: 500us
 */
int mful_pwd_auth(const uint8_t pwd[4], uint8_t pack[2])
{
    uint8_t cmd[5] = { 0x1B, pwd[0], pwd[1], pwd[2], pwd[3] };
    uint8_t rx[4] = { 0 };
    int len = nfc_poller_transceive(cmd, 5, true, rx, 4, 2, 20);
    if (len >= 2) {
        pack[0] = rx[0];
        pack[1] = rx[1];
        hb_delay_us(500);  /* From working code: 500us post-auth delay */
    }
    return len;
}

/**
 * Read all pages — reads 4 pages at a time.
 */
int mful_read_all(uint8_t* data, int max_pages)
{
    int pages_read = 0;
    for (int pg = 0; pg < max_pages; pg += 4) {
        uint8_t buf[18] = { 0 };
        int len = mful_read_pages((uint8_t)pg, buf);
        if (len < 16) {
            ESP_LOGD(TAG, "Read stopped at page %d (got %d bytes)", pg, len);
            break;
        }
        /* Copy 4 pages (16 bytes) */
        int pages_in_chunk = (max_pages - pg >= 4) ? 4 : (max_pages - pg);
        for (int i = 0; i < pages_in_chunk; i++) {
            data[(pg + i) * 4 + 0] = buf[i * 4 + 0];
            data[(pg + i) * 4 + 1] = buf[i * 4 + 1];
            data[(pg + i) * 4 + 2] = buf[i * 4 + 2];
            data[(pg + i) * 4 + 3] = buf[i * 4 + 3];
        }
        pages_read = pg + pages_in_chunk;
    }
    return pages_read;
}
