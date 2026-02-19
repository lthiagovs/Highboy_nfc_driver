/**
 * @file hb_nfc_gpio.c
 * @brief HAL GPIO — IRQ pin, matching working code pattern.
 *
 * Working code configures IRQ as input (no pull, no ISR)
 * and reads level at boot. We replicate this exactly.
 */
#include "hb_nfc_gpio.h"

#include "driver/gpio.h"
#include "esp_log.h"
#include "esp_rom_sys.h"

static const char* TAG = "hb_gpio";
static int s_pin_irq = -1;

hb_nfc_err_t hb_gpio_init(int pin_irq)
{
    s_pin_irq = pin_irq;

    /* Exact config from working code */
    gpio_config_t cfg = {
        .pin_bit_mask   = 1ULL << pin_irq,
        .mode           = GPIO_MODE_INPUT,
        .pull_up_en     = GPIO_PULLUP_DISABLE,
        .pull_down_en   = GPIO_PULLDOWN_DISABLE,
        .intr_type      = GPIO_INTR_DISABLE,
    };
    esp_err_t ret = gpio_config(&cfg);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "IRQ pin %d config fail", pin_irq);
        return HB_NFC_ERR_GPIO;
    }

    ESP_LOGI(TAG, "IRQ pin %d OK, level=%d", pin_irq, gpio_get_level(pin_irq));
    return HB_NFC_OK;
}

void hb_gpio_deinit(void)
{
    if (s_pin_irq >= 0) {
        gpio_reset_pin(s_pin_irq);
        s_pin_irq = -1;
    }
}

int hb_gpio_irq_level(void)
{
    if (s_pin_irq < 0) return 0;
    return gpio_get_level(s_pin_irq);
}

bool hb_gpio_irq_wait(uint32_t timeout_ms)
{
    for (uint32_t i = 0; i < timeout_ms; i++) {
        if (gpio_get_level(s_pin_irq)) return true;
        esp_rom_delay_us(1000);
    }
    return false;
}
