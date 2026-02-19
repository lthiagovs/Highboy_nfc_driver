/**
 * @file highboy_nfc.h
 * @brief High Boy NFC Library — Public API.
 *
 * Proven working config (ESP32-P4 + ST25R3916):
 *   MOSI=18, MISO=19, SCK=17, CS=3, IRQ=8
 *   SPI Mode 1, 500 kHz, cs_ena_pretrans=1, cs_ena_posttrans=1
 */
#ifndef HIGHBOY_NFC_H
#define HIGHBOY_NFC_H

#include "highboy_nfc_types.h"
#include "highboy_nfc_error.h"

typedef struct {
    /* SPI pins */
    int pin_mosi;       /* GPIO 18 */
    int pin_miso;       /* GPIO 19 */
    int pin_sclk;       /* GPIO 17 */
    int pin_cs;         /* GPIO 3  */
    /* Control pins */
    int pin_irq;        /* GPIO 8  */
    /* SPI config */
    int spi_host;       /* SPI2_HOST = 2 */
    int spi_mode;       /* 1 (proven) */
    uint32_t spi_clock_hz;  /* 500000 (proven) */
} highboy_nfc_config_t;

#define HIGHBOY_NFC_CONFIG_DEFAULT() { \
    .pin_mosi     = 18,                \
    .pin_miso     = 19,                \
    .pin_sclk     = 17,                \
    .pin_cs       = 3,                 \
    .pin_irq      = 8,                 \
    .spi_host     = 2,                 \
    .spi_mode     = 1,                 \
    .spi_clock_hz = 500000,            \
}

/* Lifecycle */
hb_nfc_err_t highboy_nfc_init(const highboy_nfc_config_t* config);
void         highboy_nfc_deinit(void);
hb_nfc_err_t highboy_nfc_ping(uint8_t* chip_id);

/* Field control */
hb_nfc_err_t highboy_nfc_field_on(void);
void         highboy_nfc_field_off(void);

#endif
