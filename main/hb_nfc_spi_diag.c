/**
 * @file hb_nfc_spi_diag.c
 * @brief SPI diagnostic stub (implementation to be added if needed).
 */

#include "hb_nfc_spi.h"
#include "esp_log.h"

static const char *TAG = "hb_spi_diag";

void hb_nfc_spi_diagnose(int spi_host, int cs)
{
    (void)spi_host;
    (void)cs;
    ESP_LOGW(TAG, "hb_nfc_spi_diagnose() not implemented in this build.");
}
