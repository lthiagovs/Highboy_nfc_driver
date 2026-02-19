/**
 * @file hb_nfc_spi.h
 * @brief HAL SPI — register/FIFO/command access for ST25R3916.
 *
 * SPI protocol (proven from working code):
 *   Read:    TX [0x40 | addr] [0x00]  → data in RX[1]
 *   Write:   TX [addr & 0x3F] [data]
 *   FIFO LD: TX [0x80] [data...]
 *   FIFO RD: TX [0x9F] [0x00...] → data in RX[1+]
 *   Cmd:     TX [cmd_byte]  (single byte)
 */
#ifndef HB_NFC_SPI_H
#define HB_NFC_SPI_H

#include <stdint.h>
#include <stddef.h>
#include "highboy_nfc_error.h"

hb_nfc_err_t hb_spi_init(int spi_host, int mosi, int miso, int sclk,
                           int cs, int mode, uint32_t clock_hz);
void         hb_spi_deinit(void);

hb_nfc_err_t hb_spi_reg_read(uint8_t addr, uint8_t* value);
hb_nfc_err_t hb_spi_reg_write(uint8_t addr, uint8_t value);
hb_nfc_err_t hb_spi_reg_modify(uint8_t addr, uint8_t mask, uint8_t value);

hb_nfc_err_t hb_spi_fifo_load(const uint8_t* data, size_t len);
hb_nfc_err_t hb_spi_fifo_read(uint8_t* data, size_t len);

hb_nfc_err_t hb_spi_direct_cmd(uint8_t cmd);

#endif
