/**
 * @file st25r3916_irq.c
 * @brief ST25R3916 IRQ — exact polling logic from working code.
 */
#include "st25r3916_irq.h"
#include "st25r3916_reg.h"
#include "hb_nfc_spi.h"
#include "hb_nfc_timer.h"

#include "esp_log.h"

static const char* TAG = "st25r_irq";

/**
 * Read IRQ status — from working code st25r_log_irqs():
 *   Read ERROR first, then TIMER, then MAIN, then COLLISION.
 *   Reading clears the flags.
 */
st25r_irq_status_t st25r_irq_read(void)
{
    st25r_irq_status_t s = { 0 };
    hb_spi_reg_read(REG_ERROR_INT,     &s.error);
    hb_spi_reg_read(REG_TIMER_NFC_INT, &s.timer);
    hb_spi_reg_read(REG_MAIN_INT,      &s.main);
    hb_spi_reg_read(REG_TARGET_INT,    &s.target);
    hb_spi_reg_read(REG_COLLISION,      &s.collision);
    return s;
}

void st25r_irq_log(const char* ctx, uint16_t fifo_count)
{
    st25r_irq_status_t s = st25r_irq_read();
    ESP_LOGW(TAG, " %s IRQ: MAIN=0x%02X ERR=0x%02X TMR=0x%02X TGT=0x%02X COL=0x%02X FIFO=%u",
             ctx, s.main, s.error, s.timer, s.target, s.collision, fifo_count);
}

/**
 * Wait for TX end — exact logic from working code:
 *   for (int i = 0; i < 400; i++) {
 *       uint8_t irq = st25r_read_reg(REG_MAIN_INT);
 *       if (irq & 0x08) { tx_done = true; break; }
 *       esp_rom_delay_us(50);
 *   }
 */
bool st25r_irq_wait_txe(void)
{
    for (int i = 0; i < 400; i++) {
        uint8_t irq;
        hb_spi_reg_read(REG_MAIN_INT, &irq);
        if (irq & IRQ_MAIN_TXE) return true;
        hb_delay_us(50);
    }
    ESP_LOGW(TAG, "TX timeout");
    return false;
}
