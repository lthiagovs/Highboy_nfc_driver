/**
 * @file hb_nfc_spi.c
 * @brief HAL SPI — implementation for ESP32-P4.
 *
 * Every SPI transaction here is a direct refactor of the working code.
 * The byte patterns, CS timing, and mode are proven on real hardware.
 *
 * CRITICAL CONFIG (from working code):
 *   .mode = 1              (CPOL=0, CPHA=1)
 *   .cs_ena_pretrans = 1   (1 SPI clock CS setup time)
 *   .cs_ena_posttrans = 1  (1 SPI clock CS hold time)
 *   .clock_speed_hz = 500000
 */
#include "hb_nfc_spi.h"

#include <string.h>
#include "driver/spi_master.h"
#include "esp_log.h"
#include "esp_err.h"

static const char* TAG = "hb_spi";
static spi_device_handle_t s_spi = NULL;
static bool s_init = false;

/* ═══════════════════════════════════════════════════════ */
/*  Init / Deinit                                         */
/* ═══════════════════════════════════════════════════════ */

hb_nfc_err_t hb_spi_init(int spi_host, int mosi, int miso, int sclk,
                           int cs, int mode, uint32_t clock_hz)
{
    if (s_init) return HB_NFC_OK;

    spi_bus_config_t bus = {
        .mosi_io_num   = mosi,
        .miso_io_num   = miso,
        .sclk_io_num   = sclk,
        .quadwp_io_num = -1,
        .quadhd_io_num = -1,
    };
    esp_err_t ret = spi_bus_initialize(spi_host, &bus, SPI_DMA_CH_AUTO);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "bus init fail: %s", esp_err_to_name(ret));
        return HB_NFC_ERR_SPI_INIT;
    }

    spi_device_interface_config_t dev = {
        .clock_speed_hz  = clock_hz,
        .mode            = mode,
        .spics_io_num    = cs,
        .queue_size      = 1,
        .cs_ena_pretrans = 1,
        .cs_ena_posttrans = 1,
    };
    ret = spi_bus_add_device(spi_host, &dev, &s_spi);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "add device fail: %s", esp_err_to_name(ret));
        spi_bus_free(spi_host);
        return HB_NFC_ERR_SPI_INIT;
    }

    s_init = true;
    ESP_LOGI(TAG, "SPI OK: mode=%d clk=%lu cs=%d", mode, (unsigned long)clock_hz, cs);
    return HB_NFC_OK;
}

void hb_spi_deinit(void)
{
    if (!s_init) return;
    if (s_spi) {
        spi_bus_remove_device(s_spi);
        s_spi = NULL;
    }
    s_init = false;
}

/* ═══════════════════════════════════════════════════════ */
/*  Register Read / Write                                  */
/* ═══════════════════════════════════════════════════════ */

hb_nfc_err_t hb_spi_reg_read(uint8_t addr, uint8_t* value)
{
    uint8_t tx[2] = { (uint8_t)(0x40 | (addr & 0x3F)), 0x00 };
    uint8_t rx[2] = { 0 };
    spi_transaction_t t = {
        .length    = 16,
        .tx_buffer = tx,
        .rx_buffer = rx,
    };
    esp_err_t ret = spi_device_polling_transmit(s_spi, &t);
    if (ret != ESP_OK) return HB_NFC_ERR_SPI_XFER;
    *value = rx[1];
    return HB_NFC_OK;
}

hb_nfc_err_t hb_spi_reg_write(uint8_t addr, uint8_t value)
{
    uint8_t tx[2] = { (uint8_t)(addr & 0x3F), value };
    spi_transaction_t t = {
        .length    = 16,
        .tx_buffer = tx,
    };
    esp_err_t ret = spi_device_polling_transmit(s_spi, &t);
    return (ret == ESP_OK) ? HB_NFC_OK : HB_NFC_ERR_SPI_XFER;
}

hb_nfc_err_t hb_spi_reg_modify(uint8_t addr, uint8_t mask, uint8_t value)
{
    uint8_t cur;
    hb_nfc_err_t err = hb_spi_reg_read(addr, &cur);
    if (err != HB_NFC_OK) return err;
    uint8_t nv = (cur & (uint8_t)~mask) | (value & mask);
    return hb_spi_reg_write(addr, nv);
}

/* ═══════════════════════════════════════════════════════ */
/*  FIFO                                                   */
/* ═══════════════════════════════════════════════════════ */

hb_nfc_err_t hb_spi_fifo_load(const uint8_t* data, size_t len)
{
    if (!data || len == 0 || len > 32) return HB_NFC_ERR_PARAM;

    uint8_t tx[1 + 32];
    tx[0] = 0x80;
    memcpy(&tx[1], data, len);

    spi_transaction_t t = {
        .length    = (uint32_t)((len + 1) * 8),
        .tx_buffer = tx,
    };
    esp_err_t ret = spi_device_polling_transmit(s_spi, &t);
    return (ret == ESP_OK) ? HB_NFC_OK : HB_NFC_ERR_SPI_XFER;
}

hb_nfc_err_t hb_spi_fifo_read(uint8_t* data, size_t len)
{
    if (!data || len == 0 || len > 32) return HB_NFC_ERR_PARAM;

    uint8_t tx[1 + 32] = { 0 };
    uint8_t rx[1 + 32] = { 0 };
    tx[0] = 0x9F;

    spi_transaction_t t = {
        .length    = (uint32_t)((len + 1) * 8),
        .tx_buffer = tx,
        .rx_buffer = rx,
    };
    esp_err_t ret = spi_device_polling_transmit(s_spi, &t);
    if (ret != ESP_OK) return HB_NFC_ERR_SPI_XFER;
    memcpy(data, &rx[1], len);
    return HB_NFC_OK;
}

/* ═══════════════════════════════════════════════════════ */
/*  Direct Command                                         */
/* ═══════════════════════════════════════════════════════ */

hb_nfc_err_t hb_spi_direct_cmd(uint8_t cmd)
{
    spi_transaction_t t = {
        .length    = 8,
        .tx_buffer = &cmd,
    };
    esp_err_t ret = spi_device_polling_transmit(s_spi, &t);
    return (ret == ESP_OK) ? HB_NFC_OK : HB_NFC_ERR_SPI_XFER;
}

/* ═══════════════════════════════════════════════════════ */
/*  Passive Target Memory                                  */
/* ═══════════════════════════════════════════════════════ */

/**
 * PT Memory write — ST25R3916 SPI protocol:
 *   TX: [prefix_byte] [data0] [data1] ... [dataN]
 *
 * Prefix bytes:
 *   0xA0 = PT_MEM_A (NFC-A: ATQA/UID/SAK, 15 bytes max)
 *   0xA8 = PT_MEM_F (NFC-F: IDm/PMm, 19 bytes max)
 *   0xAC = PT_MEM_TSN (12 bytes max)
 */
hb_nfc_err_t hb_spi_pt_mem_write(uint8_t prefix, const uint8_t* data, size_t len)
{
    if (!data || len == 0 || len > 19) return HB_NFC_ERR_PARAM;

    uint8_t tx[1 + 19];
    tx[0] = prefix;
    memcpy(&tx[1], data, len);

    spi_transaction_t t = {
        .length    = (uint32_t)((len + 1) * 8),
        .tx_buffer = tx,
    };
    esp_err_t ret = spi_device_polling_transmit(s_spi, &t);
    return (ret == ESP_OK) ? HB_NFC_OK : HB_NFC_ERR_SPI_XFER;
}

/**
 * PT Memory read — ST25R3916 SPI protocol:
 *   TX: [0xBF] [0x00] [0x00] ... (len + 2 bytes total)
 *   RX: [xx]   [xx]   [d0]  ...  (data starts at rx[2])
 *
 * FIX: The ST25R3916 inserts TWO bytes before actual PT memory data
 * on the MISO line: one for the command phase and one turnaround byte.
 * The original code used rx[1] which produced a 1-byte offset in the
 * readback. The correct offset is rx[2], requiring len+2 total bytes
 * in the transaction.
 *
 * Note: this only affects the readback verification — the write path
 * (hb_spi_pt_mem_write) is unaffected and writes correctly.
 */
hb_nfc_err_t hb_spi_pt_mem_read(uint8_t* data, size_t len)
{
    if (!data || len == 0 || len > 19) return HB_NFC_ERR_PARAM;

    uint8_t tx[2 + 19] = { 0 };
    uint8_t rx[2 + 19] = { 0 };
    tx[0] = 0xBF;

    spi_transaction_t t = {
        .length    = (uint32_t)((len + 2) * 8),   /* +2: cmd byte + turnaround byte */
        .tx_buffer = tx,
        .rx_buffer = rx,
    };
    esp_err_t ret = spi_device_polling_transmit(s_spi, &t);
    if (ret != ESP_OK) return HB_NFC_ERR_SPI_XFER;
    memcpy(data, &rx[2], len);                     /* data starts at rx[2] */
    return HB_NFC_OK;
}

/**
 * Raw SPI transfer — for arbitrary length transactions.
 */
hb_nfc_err_t hb_spi_raw_xfer(const uint8_t* tx, uint8_t* rx, size_t len)
{
    if (len == 0 || len > 64) return HB_NFC_ERR_PARAM;

    spi_transaction_t t = {
        .length    = (uint32_t)(len * 8),
        .tx_buffer = tx,
        .rx_buffer = rx,
    };
    esp_err_t ret = spi_device_polling_transmit(s_spi, &t);
    return (ret == ESP_OK) ? HB_NFC_OK : HB_NFC_ERR_SPI_XFER;
}