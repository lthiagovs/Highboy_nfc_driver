/**
 * @file st25r3916_reg.h
 * @brief ST25R3916 Register Map.
 *
 * All addresses verified against the working code that
 * successfully reads IC Identity = 0x15 and communicates
 * with ISO14443A cards.
 */
#ifndef ST25R3916_REG_H
#define ST25R3916_REG_H

/* ── Main Register Space (0x00 – 0x3F) ── */
#define REG_IO_CONF1              0x00
#define REG_IO_CONF2              0x01
#define REG_OP_CTRL               0x02
#define REG_MODE                  0x03
#define REG_BIT_RATE              0x04
#define REG_ISO14443A             0x05
#define REG_ISO14443B             0x06
#define REG_ISO14443B_FELICA      0x07
#define REG_PASSIVE_TARGET        0x08
#define REG_STREAM_MODE           0x09
#define REG_AUX_DEF               0x0A
#define REG_RX_CONF1              0x0B
#define REG_RX_CONF2              0x0C
#define REG_RX_CONF3              0x0D
#define REG_RX_CONF4              0x0E
#define REG_MASK_RX_TIMER         0x0F
#define REG_NO_RESPONSE_TIMER1    0x10
#define REG_NO_RESPONSE_TIMER2    0x11
#define REG_TIMER_EMV_CTRL        0x12
#define REG_GPT1                  0x13
#define REG_GPT2                  0x14
#define REG_PPON2                 0x15
#define REG_MASK_MAIN_INT         0x16
#define REG_MASK_TIMER_NFC_INT    0x17
#define REG_MASK_ERROR_WUP_INT    0x18
#define REG_MASK_TARGET_INT       0x19
#define REG_MAIN_INT              0x1A
#define REG_TIMER_NFC_INT         0x1B
#define REG_ERROR_INT             0x1C
#define REG_TARGET_INT            0x1D
#define REG_FIFO_STATUS1          0x1E
#define REG_FIFO_STATUS2          0x1F
#define REG_COLLISION             0x20
#define REG_PASSIVE_TARGET_STS    0x21
#define REG_NUM_TX_BYTES1         0x22
#define REG_NUM_TX_BYTES2         0x23
#define REG_AD_RESULT             0x24
#define REG_ANT_TUNE_CTRL         0x25
#define REG_ANT_TUNE_A            0x26
#define REG_ANT_TUNE_B            0x27
#define REG_TX_DRIVER             0x28
#define REG_PT_MOD                0x29
#define REG_FIELD_THRESH_ACT      0x2A
#define REG_FIELD_THRESH_DEACT    0x2B
#define REG_REGULATOR_CTRL        0x2C
#define REG_RSSI_RESULT           0x2D
#define REG_GAIN_RED_STATE        0x2E
#define REG_CAP_SENSOR_CTRL       0x2F
#define REG_CAP_SENSOR_RESULT     0x30
#define REG_AUX_DISPLAY           0x31
#define REG_OVERSHOOT_CONF1       0x32
#define REG_OVERSHOOT_CONF2       0x33
#define REG_UNDERSHOOT_CONF1      0x34
#define REG_UNDERSHOOT_CONF2      0x35
#define REG_IC_IDENTITY           0x3F

/* ── Key Bit Definitions ── */

/* REG_OP_CTRL (0x02) — from working code: 0xC8 = en|rx_en|tx_en */
#define OP_CTRL_EN              (1 << 7)  /* bit 7 */
#define OP_CTRL_RX_EN           (1 << 6)  /* bit 6 */
#define OP_CTRL_TX_EN           (1 << 3)  /* bit 3 */
#define OP_CTRL_FIELD_ON        0xC8      /* EN + RX_EN + TX_EN */

/* REG_MODE (0x03) — from working code: 0x08 = NFC-A initiator */
#define MODE_POLL_NFCA          0x08
#define MODE_POLL_NFCB          0x10
#define MODE_POLL_NFCF          0x20
#define MODE_POLL_NFCV          0x30

/* REG_ISO14443A (0x05) — anti-collision bit */
#define ISO14443A_ANTCL         0x01

/* REG_MAIN_INT (0x1A) bits */
#define IRQ_MAIN_OSC            (1 << 7)
#define IRQ_MAIN_FWL            (1 << 4)
#define IRQ_MAIN_TXE            (1 << 3)  /* TX end — from working code poll */
#define IRQ_MAIN_RXS            (1 << 5)
#define IRQ_MAIN_RXE            (1 << 2)
#define IRQ_MAIN_COL            (1 << 1)

/* IC Identity parsing (from working code) */
#define IC_TYPE_MASK            0xF8
#define IC_TYPE_SHIFT           3
#define IC_REV_MASK             0x07

#endif
