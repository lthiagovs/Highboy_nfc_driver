/**
 * @file emu_diag.c
 * @brief Emulation Diagnostics — Find why readers can't see us.
 *
 * PROBLEM: 60 seconds of emulation with ZERO activations.
 * This means the ST25R3916 isn't detecting the external field
 * or isn't completing anti-collision.
 *
 * This module tests:
 *   1. Register state after poller → target transition
 *   2. External field detection (CMD_MEAS_AMPLITUDE)
 *   3. Multiple field thresholds
 *   4. Multiple OP_CTRL configurations
 *   5. GOTO_SENSE state verification
 *   6. IRQ monitoring with reader present
 *   7. PT Memory verification
 *   8. Oscillator status
 */
#include "emu_diag.h"
#include "mf_classic_emu.h"
#include "st25r3916_core.h"
#include "st25r3916_reg.h"
#include "st25r3916_cmd.h"
#include "st25r3916_irq.h"
#include "hb_nfc_spi.h"
#include "hb_nfc_timer.h"

#include <string.h>
#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char* TAG = "emu_diag";

/* ═══════════════════════════════════════════════════════════
 *  Helper: Dump key registers with clear labels
 * ═══════════════════════════════════════════════════════════ */
static void dump_key_regs(const char* label)
{
    uint8_t r[64];
    for (int i = 0; i < 64; i++) {
        hb_spi_reg_read((uint8_t)i, &r[i]);
    }

    ESP_LOGW(TAG, "");
    ESP_LOGW(TAG, "╔═══ REG DUMP: %s ═══", label);
    ESP_LOGW(TAG, "│ IO_CONF1(00)=%02X  IO_CONF2(01)=%02X", r[0x00], r[0x01]);
    ESP_LOGW(TAG, "│ OP_CTRL(02)=%02X   [EN=%d RX_EN=%d TX_EN=%d wu=%d]",
             r[0x02],
             (r[0x02] >> 7) & 1,
             (r[0x02] >> 6) & 1,
             (r[0x02] >> 3) & 1,
             (r[0x02] >> 2) & 1);
    ESP_LOGW(TAG, "│ MODE(03)=%02X      [targ=%d om=0x%X]",
             r[0x03],
             (r[0x03] >> 7) & 1,
             (r[0x03] >> 3) & 0x0F);
    ESP_LOGW(TAG, "│ BIT_RATE(04)=%02X  ISO14443A(05)=%02X [no_tx_par=%d no_rx_par=%d antcl=%d]",
             r[0x04], r[0x05],
             (r[0x05] >> 7) & 1, (r[0x05] >> 6) & 1, r[0x05] & 1);
    ESP_LOGW(TAG, "│ PASSIVE_TGT(08)=%02X [d_106=%d d_212=%d d_ap2p=%d]",
             r[0x08], r[0x08] & 1, (r[0x08] >> 1) & 1, (r[0x08] >> 2) & 1);
    ESP_LOGW(TAG, "│ AUX_DEF(0A)=%02X", r[0x0A]);
    ESP_LOGW(TAG, "│ RX_CONF: %02X %02X %02X %02X",
             r[0x0B], r[0x0C], r[0x0D], r[0x0E]);
    ESP_LOGW(TAG, "│ MASK: MAIN(16)=%02X TMR(17)=%02X ERR(18)=%02X TGT(19)=%02X",
             r[0x16], r[0x17], r[0x18], r[0x19]);
    ESP_LOGW(TAG, "│ IRQ:  MAIN(1A)=%02X TMR(1B)=%02X ERR(1C)=%02X TGT(1D)=%02X",
             r[0x1A], r[0x1B], r[0x1C], r[0x1D]);
    ESP_LOGW(TAG, "│ PT_STS(21)=%02X", r[0x21]);
    ESP_LOGW(TAG, "│ AD_RESULT(24)=%d  ANT_TUNE: A=%02X B=%02X",
             r[0x24], r[0x26], r[0x27]);
    ESP_LOGW(TAG, "│ TX_DRIVER(28)=%02X  PT_MOD(29)=%02X",
             r[0x28], r[0x29]);
    ESP_LOGW(TAG, "│ FLD_ACT(2A)=%02X  FLD_DEACT(2B)=%02X",
             r[0x2A], r[0x2B]);
    ESP_LOGW(TAG, "│ REG_CTRL(2C)=%02X  RSSI(2D)=%02X",
             r[0x2C], r[0x2D]);
    ESP_LOGW(TAG, "│ AUX_DISP(31)=%02X [efd_o=%d efd_i=%d osc=%d nfc_t=%d rx_on=%d rx_act=%d tx_on=%d tgt=%d]",
             r[0x31],
             (r[0x31] >> 0) & 1,
             (r[0x31] >> 1) & 1,
             (r[0x31] >> 2) & 1,
             (r[0x31] >> 3) & 1,
             (r[0x31] >> 4) & 1,
             (r[0x31] >> 5) & 1,
             (r[0x31] >> 6) & 1,
             (r[0x31] >> 7) & 1);
    ESP_LOGW(TAG, "│ IC_ID(3F)=%02X [type=%d rev=%d]",
             r[0x3F], (r[0x3F] >> 3) & 0x1F, r[0x3F] & 0x07);
    ESP_LOGW(TAG, "╚════════════════════════════════════════");
}

/* ═══════════════════════════════════════════════════════════ */
static uint8_t measure_field(void)
{
    hb_spi_direct_cmd(CMD_MEAS_AMPLITUDE);
    vTaskDelay(pdMS_TO_TICKS(5));
    uint8_t ad = 0;
    hb_spi_reg_read(REG_AD_RESULT, &ad);
    return ad;
}

static uint8_t read_aux(void)
{
    uint8_t aux = 0;
    hb_spi_reg_read(REG_AUX_DISPLAY, &aux);
    return aux;
}

/* ═══════════════════════════════════════════════════════════
 *  TEST 1: Field Detection
 * ═══════════════════════════════════════════════════════════ */
static void test_field_detection(void)
{
    ESP_LOGW(TAG, "");
    ESP_LOGW(TAG, "╔═══ TEST 1: DETECÇÃO DE CAMPO ═══");
    ESP_LOGW(TAG, "│ APROXIME O CELULAR/LEITOR AGORA!");
    ESP_LOGW(TAG, "│");

    /* A: EN only (oscillator running, needed for measurement) */
    hb_spi_reg_write(REG_OP_CTRL, 0x80);
    vTaskDelay(pdMS_TO_TICKS(50));  /* Wait for osc */
    uint8_t ad_en = measure_field();
    uint8_t aux_en = read_aux();
    ESP_LOGW(TAG, "│ [A] OP=0x80 (EN)     → AD=%3d AUX=0x%02X [osc=%d] %s",
             ad_en, aux_en, (aux_en >> 2) & 1, ad_en > 5 ? "✓" : "✗");

    /* B: EN + RX_EN */
    hb_spi_reg_write(REG_OP_CTRL, 0xC0);
    vTaskDelay(pdMS_TO_TICKS(10));
    uint8_t ad_rx = measure_field();
    uint8_t aux_rx = read_aux();
    ESP_LOGW(TAG, "│ [B] OP=0xC0 (EN+RX)  → AD=%3d AUX=0x%02X [osc=%d] %s",
             ad_rx, aux_rx, (aux_rx >> 2) & 1, ad_rx > 5 ? "✓" : "✗");

    /* D: Multiple reads over 5 seconds */
    ESP_LOGW(TAG, "│");
    ESP_LOGW(TAG, "│ Leitura contínua por 5s:");
    uint8_t max_ad = 0;
    for (int i = 0; i < 50; i++) {
        uint8_t ad = measure_field();
        if (ad > max_ad) max_ad = ad;
        if ((i % 10) == 0) {
            uint8_t a = read_aux();
            ESP_LOGW(TAG, "│   t=%dms: AD=%3d AUX=0x%02X [efd=%d osc=%d]",
                     i * 100, ad, a, a & 1, (a >> 2) & 1);
        }
        vTaskDelay(pdMS_TO_TICKS(100));
    }

    ESP_LOGW(TAG, "│ AD máximo: %d", max_ad);
    if (max_ad < 5) {
        ESP_LOGE(TAG, "│ ⚠ NENHUM CAMPO EXTERNO DETECTADO!");
        ESP_LOGE(TAG, "│   → Verifique se o leitor NFC está ligado e próximo");
        ESP_LOGE(TAG, "│   → A antena pode não captar campo externo (só TX)");
    }
    ESP_LOGW(TAG, "╚════════════════════════════════════════");
}

/* ═══════════════════════════════════════════════════════════
 *  TEST 2: Target Config + GOTO_SENSE + IRQ Monitor
 * ═══════════════════════════════════════════════════════════ */
static bool test_target_config(int cfg_num, uint8_t op_ctrl,
                                uint8_t fld_act, uint8_t fld_deact,
                                uint8_t pt_mod)
{
    ESP_LOGW(TAG, "");
    ESP_LOGW(TAG, "╔═══ TEST 2.%d: CONFIG (OP=0x%02X ACT=0x%02X DEACT=0x%02X MOD=0x%02X) ═══",
             cfg_num, op_ctrl, fld_act, fld_deact, pt_mod);

    /* Full reset */
    hb_spi_reg_write(REG_OP_CTRL, 0x00);
    vTaskDelay(pdMS_TO_TICKS(2));
    hb_spi_direct_cmd(CMD_SET_DEFAULT);
    vTaskDelay(pdMS_TO_TICKS(10));

    uint8_t ic = 0;
    hb_spi_reg_read(REG_IC_IDENTITY, &ic);
    if (ic == 0x00 || ic == 0xFF) {
        ESP_LOGE(TAG, "│ CHIP MORTO! IC=0x%02X", ic);
        ESP_LOGW(TAG, "╚════════════════════════════════════════");
        return false;
    }

    /* START OSCILLATOR — must be done before anything else! */
    hb_spi_reg_write(REG_OP_CTRL, 0x80);  /* EN → oscillator starts */
    bool osc = false;
    for (int i = 0; i < 100; i++) {
        uint8_t aux = 0;
        hb_spi_reg_read(REG_AUX_DISPLAY, &aux);
        if (aux & 0x04) { osc = true; break; }
        vTaskDelay(1);
    }
    ESP_LOGW(TAG, "│ Oscilador: %s", osc ? "✓ OK" : "✗ NÃO ESTÁVEL");

    /* Calibrate regulators */
    hb_spi_direct_cmd(CMD_ADJUST_REGULATORS);
    vTaskDelay(pdMS_TO_TICKS(5));

    /* Target NFC-A */
    hb_spi_reg_write(REG_MODE, 0x88);
    hb_spi_reg_write(REG_BIT_RATE, 0x00);
    hb_spi_reg_write(REG_ISO14443A, 0x00);
    hb_spi_reg_write(REG_PASSIVE_TARGET, 0x00);

    /* Thresholds + modulation */
    hb_spi_reg_write(REG_FIELD_THRESH_ACT, fld_act);
    hb_spi_reg_write(REG_FIELD_THRESH_DEACT, fld_deact);
    hb_spi_reg_write(REG_PT_MOD, pt_mod);

    /* Load PT Memory */
    mfc_emu_load_pt_memory();

    /* Unmask ALL interrupts */
    hb_spi_reg_write(REG_MASK_MAIN_INT, 0x00);
    hb_spi_reg_write(REG_MASK_TIMER_NFC_INT, 0x00);
    hb_spi_reg_write(REG_MASK_ERROR_WUP_INT, 0x00);
    hb_spi_reg_write(REG_MASK_TARGET_INT, 0x00);

    /* Clear pending IRQs */
    st25r_irq_read();

    /* Enable chip */
    hb_spi_reg_write(REG_OP_CTRL, op_ctrl);
    vTaskDelay(pdMS_TO_TICKS(5));

    /* Verify */
    uint8_t mode_rb = 0, op_rb = 0;
    hb_spi_reg_read(REG_MODE, &mode_rb);
    hb_spi_reg_read(REG_OP_CTRL, &op_rb);
    uint8_t aux0 = read_aux();
    ESP_LOGW(TAG, "│ Pre-SENSE: MODE=0x%02X OP=0x%02X AUX=0x%02X [osc=%d efd=%d]",
             mode_rb, op_rb, aux0, (aux0 >> 2) & 1, aux0 & 1);

    /* GOTO_SENSE */
    hb_spi_direct_cmd(CMD_GOTO_SENSE);
    vTaskDelay(pdMS_TO_TICKS(10));

    uint8_t pt_sts = 0;
    hb_spi_reg_read(REG_PASSIVE_TARGET_STS, &pt_sts);
    uint8_t aux1 = read_aux();
    ESP_LOGW(TAG, "│ Pós-SENSE: PT_STS=0x%02X AUX=0x%02X [osc=%d efd=%d tgt=%d]",
             pt_sts, aux1, (aux1 >> 2) & 1, aux1 & 1, (aux1 >> 7) & 1);

    /* Monitor IRQs for 10 seconds */
    ESP_LOGW(TAG, "│ Monitorando 10s (LEITOR PERTO!)...");

    bool wu_a = false, sdd_c = false, any_irq = false;
    int64_t t0 = esp_timer_get_time();
    int last_report = -1;

    while ((esp_timer_get_time() - t0) < 10000000LL) {
        uint8_t tgt_irq = 0, main_irq = 0, err_irq = 0;
        hb_spi_reg_read(REG_TARGET_INT, &tgt_irq);
        hb_spi_reg_read(REG_MAIN_INT, &main_irq);
        hb_spi_reg_read(REG_ERROR_INT, &err_irq);

        if (tgt_irq || main_irq || err_irq) {
            int ms = (int)((esp_timer_get_time() - t0) / 1000);
            ESP_LOGW(TAG, "│ [%dms] TGT=0x%02X MAIN=0x%02X ERR=0x%02X",
                     ms, tgt_irq, main_irq, err_irq);
            any_irq = true;
            if (tgt_irq & 0x80) { ESP_LOGI(TAG, "│  → WU_A!"); wu_a = true; }
            if (tgt_irq & 0x40) { ESP_LOGI(TAG, "│  → WU_A_X (anti-col done)!"); }
            if (tgt_irq & 0x04) { ESP_LOGI(TAG, "│  → SDD_C (SELECTED)!"); sdd_c = true; }
            if (tgt_irq & 0x08) { ESP_LOGI(TAG, "│  → OSCF (osc stable)"); }
            if (main_irq & 0x04) {
                ESP_LOGI(TAG, "│  → RXE (data received)!");
                uint8_t fs1 = 0;
                hb_spi_reg_read(REG_FIFO_STATUS1, &fs1);
                ESP_LOGI(TAG, "│    FIFO: %d bytes", fs1);
            }
        }

        int sec = (int)((esp_timer_get_time() - t0) / 1000000);
        if (sec != last_report && (sec % 3) == 0) {
            last_report = sec;
            uint8_t ad = measure_field();
            uint8_t a = read_aux();
            /* Re-enter SENSE after measurement disruption */
            hb_spi_direct_cmd(CMD_GOTO_SENSE);
            ESP_LOGW(TAG, "│ [%ds] AD=%d AUX=0x%02X [efd=%d osc=%d]",
                     sec, ad, a, a & 1, (a >> 2) & 1);
        }

        vTaskDelay(1);
    }

    /* Result */
    ESP_LOGW(TAG, "│");
    if (sdd_c) {
        ESP_LOGI(TAG, "│ ✓✓✓ CONFIG %d: SUCESSO — SELECIONADO!", cfg_num);
    } else if (wu_a) {
        ESP_LOGI(TAG, "│ ✓✓  CONFIG %d: Campo visto, anti-col falhou", cfg_num);
    } else if (any_irq) {
        ESP_LOGW(TAG, "│ ✓   CONFIG %d: IRQ vista mas sem WU_A", cfg_num);
    } else {
        ESP_LOGE(TAG, "│ ✗   CONFIG %d: NENHUMA IRQ em 10s", cfg_num);
    }
    ESP_LOGW(TAG, "╚════════════════════════════════════════");

    return sdd_c;
}

/* ═══════════════════════════════════════════════════════════
 *  TEST 3: PT Memory Verification
 * ═══════════════════════════════════════════════════════════ */
static void test_pt_memory(void)
{
    ESP_LOGW(TAG, "");
    ESP_LOGW(TAG, "╔═══ TEST 3: PT MEMORY ═══");

    uint8_t ptm[15] = {0};
    hb_spi_pt_mem_read(ptm, 15);

    ESP_LOGW(TAG, "│ PT Memory: %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X",
             ptm[0], ptm[1], ptm[2], ptm[3], ptm[4], ptm[5], ptm[6], ptm[7],
             ptm[8], ptm[9], ptm[10], ptm[11], ptm[12], ptm[13], ptm[14]);
    ESP_LOGW(TAG, "│ ATQA=%02X%02X  UID=%02X%02X%02X%02X  BCC=%02X(calc:%02X)  SAK=%02X",
             ptm[0], ptm[1], ptm[2], ptm[3], ptm[4], ptm[5],
             ptm[6], ptm[2] ^ ptm[3] ^ ptm[4] ^ ptm[5], ptm[7]);

    bool bcc_ok = (ptm[6] == (ptm[2] ^ ptm[3] ^ ptm[4] ^ ptm[5]));
    ESP_LOGW(TAG, "│ BCC: %s", bcc_ok ? "✓ OK" : "✗ ERRADO!");

    /* Write test pattern + readback */
    uint8_t test[15] = {0x04, 0x00, 0xDE, 0xAD, 0xBE, 0xEF,
                         0xDE ^ 0xAD ^ 0xBE ^ 0xEF, 0x08, 0,0,0,0,0,0,0};
    hb_spi_pt_mem_write(SPI_PT_MEM_A_WRITE, test, 15);
    vTaskDelay(1);
    uint8_t rb[15] = {0};
    hb_spi_pt_mem_read(rb, 15);
    bool match = (memcmp(test, rb, 15) == 0);
    ESP_LOGW(TAG, "│ Write/Read test: %s", match ? "✓ OK" : "✗ FALHOU!");
    if (!match) {
        ESP_LOGW(TAG, "│  Escrito: %02X %02X %02X %02X %02X %02X %02X %02X",
                 test[0],test[1],test[2],test[3],test[4],test[5],test[6],test[7]);
        ESP_LOGW(TAG, "│  Lido:    %02X %02X %02X %02X %02X %02X %02X %02X",
                 rb[0],rb[1],rb[2],rb[3],rb[4],rb[5],rb[6],rb[7]);
    }

    /* Restore */
    mfc_emu_load_pt_memory();
    ESP_LOGW(TAG, "╚════════════════════════════════════════");
}

/* ═══════════════════════════════════════════════════════════
 *  TEST 4: Oscillator/Regulator
 * ═══════════════════════════════════════════════════════════ */
static void test_oscillator(void)
{
    ESP_LOGW(TAG, "");
    ESP_LOGW(TAG, "╔═══ TEST 4: OSCILADOR ═══");

    /* First check current state */
    uint8_t aux = read_aux();
    ESP_LOGW(TAG, "│ AUX_DISPLAY=0x%02X (antes de ligar EN)", aux);
    ESP_LOGW(TAG, "│   osc_ok=%d  efd_o=%d  rx_on=%d  tgt=%d",
             (aux>>2)&1, (aux>>0)&1, (aux>>4)&1, (aux>>7)&1);

    /* Enable EN to start oscillator */
    hb_spi_reg_write(REG_OP_CTRL, 0x80);
    ESP_LOGW(TAG, "│ OP_CTRL=0x80 (EN) → Ligando oscilador...");

    /* Wait and poll for osc_ok */
    bool osc_started = false;
    for (int i = 0; i < 100; i++) {
        uint8_t a = 0;
        hb_spi_reg_read(REG_AUX_DISPLAY, &a);
        if (a & 0x04) {
            ESP_LOGI(TAG, "│ ✓ Oscilador estável em %dms! AUX=0x%02X", i * 10, a);
            osc_started = true;
            break;
        }
        vTaskDelay(1);
    }

    if (!osc_started) {
        aux = read_aux();
        ESP_LOGE(TAG, "│ ✗ Oscilador NÃO iniciou após 1s. AUX=0x%02X", aux);
        ESP_LOGE(TAG, "│   Bits: efd_o=%d efd_i=%d osc=%d nfc_t=%d rx_on=%d",
                 (aux>>0)&1, (aux>>1)&1, (aux>>2)&1, (aux>>3)&1, (aux>>4)&1);
    }

    /* Calibrate regulators (needs oscillator) */
    hb_spi_direct_cmd(CMD_ADJUST_REGULATORS);
    vTaskDelay(pdMS_TO_TICKS(10));

    uint8_t rc = 0;
    hb_spi_reg_read(REG_REGULATOR_CTRL, &rc);
    aux = read_aux();
    ESP_LOGW(TAG, "│ Após calibração: AUX=0x%02X REG_CTRL=0x%02X", aux, rc);
    ESP_LOGW(TAG, "╚════════════════════════════════════════");
}

/* ═══════════════════════════════════════════════════════════
 *  MAIN DIAGNOSTIC
 * ═══════════════════════════════════════════════════════════ */
hb_nfc_err_t emu_diag_full(void)
{
    ESP_LOGW(TAG, "");
    ESP_LOGW(TAG, "╔══════════════════════════════════════════════════╗");
    ESP_LOGW(TAG, "║  🔍 DIAGNÓSTICO DE EMULAÇÃO v2                   ║");
    ESP_LOGW(TAG, "║                                                  ║");
    ESP_LOGW(TAG, "║  ⚡ MANTENHA O LEITOR NFC PRÓXIMO DURANTE       ║");
    ESP_LOGW(TAG, "║     TODO O DIAGNÓSTICO (~60s total)              ║");
    ESP_LOGW(TAG, "╚══════════════════════════════════════════════════╝");
    ESP_LOGW(TAG, "");
    ESP_LOGW(TAG, "Aguardando 5s... Aproxime o leitor NFC agora!");
    vTaskDelay(pdMS_TO_TICKS(5000));

    /* State before any changes */
    dump_key_regs("ESTADO INICIAL");

    /* Oscillator check */
    test_oscillator();

    /* PT Memory check */
    test_pt_memory();

    /* Field detection (5s of measurement) */
    test_field_detection();

    /* ── Try 4 different target configurations, 10s each ── */

    /* Config 1: Our current approach (EN only, moderate thresholds) */
    bool ok1 = test_target_config(1, 0x80, 0x03, 0x01, 0x17);
    if (ok1) goto done;

    /* Config 2: EN + RX_EN */
    bool ok2 = test_target_config(2, 0xC0, 0x03, 0x01, 0x17);
    if (ok2) goto done;

    /* Config 3: Maximum sensitivity, max modulation */
    bool ok3 = test_target_config(3, 0xC0, 0x00, 0x00, 0x3F);
    if (ok3) goto done;

    /* Config 4: EN only + minimum thresholds */
    test_target_config(4, 0x80, 0x00, 0x00, 0x3F);

done:
    dump_key_regs("ESTADO FINAL");

    ESP_LOGW(TAG, "");
    ESP_LOGW(TAG, "╔══════════════════════════════════════════════════╗");
    ESP_LOGW(TAG, "║  📋 DIAGNÓSTICO COMPLETO                         ║");
    ESP_LOGW(TAG, "║                                                  ║");
    ESP_LOGW(TAG, "║  Se AD sempre = 0:                               ║");
    ESP_LOGW(TAG, "║    → Antena não capta campo externo              ║");
    ESP_LOGW(TAG, "║    → Precisa circuito matching p/ RX passivo     ║");
    ESP_LOGW(TAG, "║                                                  ║");
    ESP_LOGW(TAG, "║  Se AD > 0 mas sem WU_A:                         ║");
    ESP_LOGW(TAG, "║    → GOTO_SENSE não está ativando corretamente   ║");
    ESP_LOGW(TAG, "║    → Ou threshold precisa ser ajustado           ║");
    ESP_LOGW(TAG, "║                                                  ║");
    ESP_LOGW(TAG, "║  Se WU_A ok mas sem SDD_C:                       ║");
    ESP_LOGW(TAG, "║    → PT Memory ou anti-collision com problema    ║");
    ESP_LOGW(TAG, "║                                                  ║");
    ESP_LOGW(TAG, "║  ⚡ COPIE TODA A SAÍDA SERIAL E COMPARTILHE!    ║");
    ESP_LOGW(TAG, "╚══════════════════════════════════════════════════╝");

    return HB_NFC_OK;
}

void emu_diag_monitor(int seconds)
{
    ESP_LOGW(TAG, "Monitor %ds...", seconds);
    int64_t t0 = esp_timer_get_time();
    while ((esp_timer_get_time() - t0) < (int64_t)seconds * 1000000LL) {
        uint8_t tgt = 0, mi = 0, ei = 0;
        hb_spi_reg_read(REG_TARGET_INT, &tgt);
        hb_spi_reg_read(REG_MAIN_INT, &mi);
        hb_spi_reg_read(REG_ERROR_INT, &ei);
        if (tgt || mi || ei) {
            ESP_LOGW(TAG, "[%dms] TGT=0x%02X MAIN=0x%02X ERR=0x%02X",
                     (int)((esp_timer_get_time() - t0) / 1000), tgt, mi, ei);
        }
        vTaskDelay(1);
    }
}
