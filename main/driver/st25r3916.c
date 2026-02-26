/* === main\st25r3916_core.c === */
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

#define TAG TAG_CORE
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

/**
 * Field cycle — briefly toggle field OFF then ON.
 *
 * After Crypto1 authentication, the card is in AUTHENTICATED state and
 * will NOT respond to WUPA. The only reliable way to reset it is to
 * power-cycle by removing the RF field briefly.
 *
 * Timing: 5ms off + 5ms on (minimum 1ms off required by ISO14443).
 */
hb_nfc_err_t st25r_field_cycle(void)
{
    if (!s_drv.init) return HB_NFC_ERR_INTERNAL;

    /* Field OFF */
    hb_spi_reg_write(REG_OP_CTRL, 0x00);
    s_drv.field = false;
    hb_delay_us(5000);   /* 5ms — card loses power */

    /* Field ON */
    hb_spi_reg_write(REG_OP_CTRL, OP_CTRL_FIELD_ON);
    hb_delay_us(5000);   /* 5ms — card boot time */
    hb_spi_direct_cmd(CMD_RESET_RX_GAIN);
    s_drv.field = true;

    return HB_NFC_OK;
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
#undef TAG

/* === main\st25r3916_fifo.c === */
/**
 * @file st25r3916_fifo.c
 * @brief ST25R3916 FIFO — all functions directly from working code.
 */
#include "st25r3916_fifo.h"
#include "st25r3916_reg.h"
#include "st25r3916_cmd.h"
#include "hb_nfc_spi.h"
#include "hb_nfc_timer.h"

/**
 * FIFO count — exact logic from working code:
 *   lsb = REG_FIFO_STATUS1
 *   msb = REG_FIFO_STATUS2
 *   count = ((msb & 0xC0) << 2) | lsb
 */
uint16_t st25r_fifo_count(void)
{
    uint8_t lsb, msb;
    hb_spi_reg_read(REG_FIFO_STATUS1, &lsb);
    hb_spi_reg_read(REG_FIFO_STATUS2, &msb);
    return (uint16_t)(((msb & 0xC0) << 2) | lsb);
}

void st25r_fifo_clear(void)
{
    /* NOTE: The ST25R3916 has NO dedicated "clear FIFO" command.
     * The old code used 0xDB (transparent mode) here as a NOP.
     * CMD_CLEAR (0xC2) would stop all activities and break
     * the target state machine during emulation.
     *
     * The FIFO is automatically flushed when new data is loaded
     * via SPI_FIFO_LOAD (0x80), so this function is a NOP.
     *
     * If you truly need to clear the FIFO, write 0x02 to
     * REG_FIFO_STATUS2 (bit 1 = flush flag on some revisions).
     */
    (void)0;  /* NOP — FIFO clears on next load */
}

hb_nfc_err_t st25r_fifo_load(const uint8_t* data, size_t len)
{
    return hb_spi_fifo_load(data, len);
}

hb_nfc_err_t st25r_fifo_read(uint8_t* data, size_t len)
{
    return hb_spi_fifo_read(data, len);
}

/**
 * Set TX byte count — exact formula from working code st25r_set_nbytes():
 *   reg1 = (nbytes >> 5) & 0xFF
 *   reg2 = ((nbytes & 0x1F) << 3) | (nbtx_bits & 0x07)
 */
void st25r_set_tx_bytes(uint16_t nbytes, uint8_t nbtx_bits)
{
    uint8_t reg1 = (uint8_t)((nbytes >> 5) & 0xFF);
    uint8_t reg2 = (uint8_t)(((nbytes & 0x1F) << 3) | (nbtx_bits & 0x07));
    hb_spi_reg_write(REG_NUM_TX_BYTES1, reg1);
    hb_spi_reg_write(REG_NUM_TX_BYTES2, reg2);
}

/**
 * Wait for FIFO — exact logic from working code st25r_wait_fifo():
 *   Poll every 1ms using esp_rom_delay_us(1000).
 */
int st25r_fifo_wait(size_t min_bytes, int timeout_ms, uint16_t* final_count)
{
    uint16_t count = 0;
    for (int i = 0; i < timeout_ms; i++) {
        count = st25r_fifo_count();
        if (count >= min_bytes) {
            if (final_count) *final_count = count;
            return (int)count;
        }
        hb_delay_us(1000);
    }
    /* Final check */
    count = st25r_fifo_count();
    if (final_count) *final_count = count;
    return (int)count;
}

/* === main\st25r3916_irq.c === */
/**
 * @file st25r3916_irq.c
 * @brief ST25R3916 IRQ — exact polling logic from working code.
 */
#include "st25r3916_irq.h"
#include "st25r3916_reg.h"
#include "hb_nfc_spi.h"
#include "hb_nfc_timer.h"

#include "esp_log.h"

#define TAG TAG_IRQ
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
#undef TAG

/* === main\st25r3916_aat.c === */
/**
 * @file st25r3916_aat.c
 * @brief ST25R3916 AAT - basic calibration (default DACs + measurement).
 *
 * TODO: Implement full DAC sweep and real optimization.
 */
#include "st25r3916_aat.h"
#include "st25r3916_cmd.h"
#include "st25r3916_reg.h"
#include "hb_nfc_spi.h"
#include "esp_log.h"

#define TAG TAG_AAT
static const char* TAG = "st25r_aat";

hb_nfc_err_t st25r_aat_calibrate(st25r_aat_result_t* result)
{
    if (!result) return HB_NFC_ERR_PARAM;

    /* Default mid-scale DACs */
    hb_nfc_err_t err = hb_spi_reg_write(REG_ANT_TUNE_A, 0x80);
    if (err != HB_NFC_OK) return err;
    err = hb_spi_reg_write(REG_ANT_TUNE_B, 0x80);
    if (err != HB_NFC_OK) return err;

    /* Basic amplitude/phase readback */
    uint8_t amp = 0;
    uint8_t phase = 0;
    (void)hb_spi_direct_cmd(CMD_MEAS_AMPLITUDE);
    (void)hb_spi_reg_read(REG_AD_RESULT, &amp);
    (void)hb_spi_direct_cmd(CMD_MEAS_PHASE);
    (void)hb_spi_reg_read(REG_AD_RESULT, &phase);

    result->dac_a = 0x80;
    result->dac_b = 0x80;
    result->amplitude = amp;
    result->phase = phase;
    ESP_LOGI(TAG, "AAT default set: A=0x%02X B=0x%02X AMP=%u PH=%u",
             result->dac_a, result->dac_b, result->amplitude, result->phase);
    return HB_NFC_OK;
}

hb_nfc_err_t st25r_aat_load_nvs(st25r_aat_result_t* result)
{
    if (!result) return HB_NFC_ERR_PARAM;
    /* No NVS persistence in this build: return defaults */
    result->dac_a = 0x80;
    result->dac_b = 0x80;
    result->amplitude = 0;
    result->phase = 0;
    return HB_NFC_OK;
}

hb_nfc_err_t st25r_aat_save_nvs(const st25r_aat_result_t* result)
{
    if (!result) return HB_NFC_ERR_PARAM;
    /* No-op in this build */
    return HB_NFC_OK;
}
#undef TAG

