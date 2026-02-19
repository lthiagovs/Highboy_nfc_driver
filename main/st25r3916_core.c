/**
 * @file st25r3916_core.c
 * @brief ST25R3916 Core — init, field control, mode configuration.
 *
 * INIT SEQUENCE (copied exactly from working code app_main):
 *
 *   1. GPIO init (IRQ pin as input, no pull, no ISR)
 *   2. SPI init (mode 1, 500kHz, pretrans=1, posttrans=1)
 *   3. Wait 5ms (proven post-SPI-init stabilization)
 *   4. CMD_SET_DEFAULT (0xC0) — soft reset
 *   5. Wait 2ms
 *   6. Read REG_IC_IDENTITY (0x3F) — verify chip
 *   7. Write REG_MODE = 0x08 (NFC-A initiator)
 *   8. Write REG_BIT_RATE = 0x00 (106 kbps)
 *   9. Read/modify REG_ISO14443A — clear bits 7,6,0
 *  10. Write REG_OP_CTRL = 0xC8 (en + rx_en + tx_en → field ON)
 *  11. Wait 5ms
 *  12. CMD_RESET_RX_GAIN (0xD5)
 *
 * After this sequence the chip has the 13.56 MHz field active
 * and is ready to send REQA/WUPA.
 */
#include "st25r3916_core.h"
#include "st25r3916_reg.h"
#include "st25r3916_cmd.h"
#include "hb_nfc_spi.h"
#include "hb_nfc_gpio.h"
#include "hb_nfc_timer.h"

#include "esp_log.h"

static const char* TAG = "st25r";

static struct {
    bool init;
    bool field;
    highboy_nfc_config_t cfg;
} s_drv = { 0 };

/* ═══════════════════════════════════════════════════════ */
/*  Init                                                    */
/* ═══════════════════════════════════════════════════════ */

hb_nfc_err_t st25r_init(const highboy_nfc_config_t* cfg)
{
    if (!cfg) return HB_NFC_ERR_PARAM;
    hb_nfc_err_t err;

    s_drv.cfg = *cfg;

    ESP_LOGI(TAG, "════════════════════════════════════════");
    ESP_LOGI(TAG, " ST25R3916 Init");
    ESP_LOGI(TAG, " PINS: SCK=%d MOSI=%d MISO=%d CS=%d IRQ=%d",
             cfg->pin_sclk, cfg->pin_mosi, cfg->pin_miso, cfg->pin_cs, cfg->pin_irq);
    ESP_LOGI(TAG, " NOTE: I2C_EN must be tied to GND for SPI");
    ESP_LOGI(TAG, "════════════════════════════════════════");

    /* Step 1: GPIO */
    err = hb_gpio_init(cfg->pin_irq);
    if (err != HB_NFC_OK) return err;

    /* Step 2: SPI */
    err = hb_spi_init(cfg->spi_host, cfg->pin_mosi, cfg->pin_miso,
                       cfg->pin_sclk, cfg->pin_cs, cfg->spi_mode,
                       cfg->spi_clock_hz);
    if (err != HB_NFC_OK) {
        hb_gpio_deinit();
        return err;
    }

    /* Step 3: Post-SPI stabilization (from working code) */
    hb_delay_us(5000);

    /* Step 4: Soft Reset */
    hb_spi_direct_cmd(CMD_SET_DEFAULT);

    /* Step 5: Wait for reset to complete */
    hb_delay_us(2000);

    /* Step 6: Verify chip */
    uint8_t id, type, rev;
    err = st25r_check_id(&id, &type, &rev);
    if (err != HB_NFC_OK) {
        ESP_LOGE(TAG, "Chip ID check FAILED");
        hb_spi_deinit();
        hb_gpio_deinit();
        return err;
    }

    s_drv.init = true;
    ESP_LOGI(TAG, "Init OK (chip 0x%02X type=0x%02X rev=%u)", id, type, rev);
    return HB_NFC_OK;
}

void st25r_deinit(void)
{
    if (!s_drv.init) return;
    st25r_field_off();
    hb_spi_deinit();
    hb_gpio_deinit();
    s_drv.init = false;
    s_drv.field = false;
}

/* ═══════════════════════════════════════════════════════ */
/*  Chip ID                                                 */
/* ═══════════════════════════════════════════════════════ */

/**
 * Read and parse IC Identity — exact logic from working code:
 *   ic_type = (id >> 3) & 0x1F
 *   ic_rev  = id & 0x07
 */
hb_nfc_err_t st25r_check_id(uint8_t* id, uint8_t* type, uint8_t* rev)
{
    uint8_t val;
    hb_nfc_err_t err = hb_spi_reg_read(REG_IC_IDENTITY, &val);
    if (err != HB_NFC_OK) return HB_NFC_ERR_CHIP_ID;

    if (id)   *id   = val;
    if (type) *type = (val >> 3) & 0x1F;
    if (rev)  *rev  = val & 0x07;

    ESP_LOGI(TAG, "IC_IDENTITY: 0x%02X (type=0x%02X rev=%u)",
             val, (val >> 3) & 0x1F, val & 0x07);

    /* Sanity: type should be non-zero */
    if (val == 0x00 || val == 0xFF) {
        ESP_LOGE(TAG, "Bad IC ID 0x%02X — check SPI wiring!", val);
        return HB_NFC_ERR_CHIP_ID;
    }
    return HB_NFC_OK;
}

/* ═══════════════════════════════════════════════════════ */
/*  Field Control                                           */
/* ═══════════════════════════════════════════════════════ */

/**
 * Field ON — exact sequence from working code:
 *   1. st25r_write_reg(REG_OP_CTRL, 0xC8)
 *   2. esp_rom_delay_us(5000)
 *   3. CMD_RESET_RX_GAIN
 */
hb_nfc_err_t st25r_field_on(void)
{
    if (!s_drv.init) return HB_NFC_ERR_INTERNAL;
    if (s_drv.field) return HB_NFC_OK;

    hb_spi_reg_write(REG_OP_CTRL, OP_CTRL_FIELD_ON);
    hb_delay_us(5000);
    hb_spi_direct_cmd(CMD_RESET_RX_GAIN);

    s_drv.field = true;
    ESP_LOGI(TAG, "RF field ON");
    return HB_NFC_OK;
}

void st25r_field_off(void)
{
    if (!s_drv.init) return;
    hb_spi_reg_write(REG_OP_CTRL, 0x00);
    s_drv.field = false;
    ESP_LOGD(TAG, "RF field OFF");
}

bool st25r_field_is_on(void)
{
    return s_drv.field;
}

/* ═══════════════════════════════════════════════════════ */
/*  Mode Configuration                                     */
/* ═══════════════════════════════════════════════════════ */

/**
 * Configure for NFC-A — exact sequence from working code:
 *   1. REG_MODE = 0x08
 *   2. REG_BIT_RATE = 0x00
 *   3. Read REG_ISO14443A, clear bits 7,6,0
 */
hb_nfc_err_t st25r_set_mode_nfca(void)
{
    hb_spi_reg_write(REG_MODE, MODE_POLL_NFCA);
    hb_spi_reg_write(REG_BIT_RATE, 0x00);

    uint8_t iso_def;
    hb_spi_reg_read(REG_ISO14443A, &iso_def);
    ESP_LOGD(TAG, "ISO14443A reg default = 0x%02X", iso_def);
    iso_def &= (uint8_t)~0xC1;   /* Clear bits 7,6,0 — from working code */
    hb_spi_reg_write(REG_ISO14443A, iso_def);

    return HB_NFC_OK;
}

/* ═══════════════════════════════════════════════════════ */
/*  Debug                                                   */
/* ═══════════════════════════════════════════════════════ */

void st25r_dump_regs(void)
{
    if (!s_drv.init) return;
    uint8_t regs[64];
    for (int i = 0; i < 64; i++) {
        hb_spi_reg_read((uint8_t)i, &regs[i]);
    }
    ESP_LOGI(TAG, "── Reg Dump ──");
    for (int r = 0; r < 64; r += 16) {
        ESP_LOGI(TAG, "%02X: %02X %02X %02X %02X  %02X %02X %02X %02X  "
                       "%02X %02X %02X %02X  %02X %02X %02X %02X",
                 r,
                 regs[r+0],  regs[r+1],  regs[r+2],  regs[r+3],
                 regs[r+4],  regs[r+5],  regs[r+6],  regs[r+7],
                 regs[r+8],  regs[r+9],  regs[r+10], regs[r+11],
                 regs[r+12], regs[r+13], regs[r+14], regs[r+15]);
    }
}

/* ═══════════════════════════════════════════════════════ */
/*  Error Strings                                           */
/* ═══════════════════════════════════════════════════════ */

const char* hb_nfc_err_str(hb_nfc_err_t err)
{
    switch (err) {
    case HB_NFC_OK:             return "OK";
    case HB_NFC_ERR_SPI_INIT:   return "SPI init failed";
    case HB_NFC_ERR_SPI_XFER:   return "SPI transfer failed";
    case HB_NFC_ERR_GPIO:        return "GPIO init failed";
    case HB_NFC_ERR_TIMEOUT:     return "Timeout";
    case HB_NFC_ERR_CHIP_ID:    return "Bad chip ID";
    case HB_NFC_ERR_FIFO_OVR:   return "FIFO overflow";
    case HB_NFC_ERR_FIELD:       return "Field error";
    case HB_NFC_ERR_NO_CARD:    return "No card";
    case HB_NFC_ERR_CRC:         return "CRC error";
    case HB_NFC_ERR_COLLISION:   return "Collision";
    case HB_NFC_ERR_NACK:        return "NACK";
    case HB_NFC_ERR_AUTH:        return "Auth failed";
    case HB_NFC_ERR_PROTOCOL:    return "Protocol error";
    case HB_NFC_ERR_TX_TIMEOUT: return "TX timeout";
    case HB_NFC_ERR_PARAM:       return "Bad param";
    case HB_NFC_ERR_INTERNAL:    return "Internal error";
    default:                     return "Unknown";
    }
}
