/**
 * @file hb_nfc_timer.c
 * @brief HAL Timer — uses esp_rom_delay_us (proven by working code).
 */
#include "hb_nfc_timer.h"
#include "esp_rom_sys.h"

void hb_delay_us(uint32_t us)
{
    esp_rom_delay_us(us);
}

void hb_delay_ms(uint32_t ms)
{
    for (uint32_t i = 0; i < ms; i++) {
        esp_rom_delay_us(1000);
    }
}
