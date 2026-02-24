/**
 * @file st25r3916_cmd.h
 * @brief ST25R3916 Direct Commands.
 *
 * v5 FIX: Command codes verified against ST25R3916
 * datasheet DocID 031020 Rev 3, Table 19.
 *
 * BUGS FIXED from v4:
 *   - CMD_MEAS_AMPLITUDE was 0xD8, correct = 0xD3
 *   - CMD_CALIBRATE_DRIVER was 0xD7, correct = 0xD8
 *   - Several other measurement/timer codes off-by-one
 *   - Added missing target-mode commands
 *
 * NOTE: These are for ST25R3916 (IC type 0x05).
 * ST25R3916B (IC type 0x06) has different command table.
 */
#ifndef ST25R3916_CMD_H
#define ST25R3916_CMD_H

/* ── Core Commands (0xC0-0xCE) ── */
#define CMD_SET_DEFAULT         0xC0  /* Soft reset: all regs to defaults */
#define CMD_CLEAR               0xC2  /* Stop all activities + clear FIFO */
#define CMD_TX_WITH_CRC         0xC4  /* Transmit + append CRC */
#define CMD_TX_WO_CRC           0xC5  /* Transmit without CRC */
#define CMD_TX_REQA             0xC6  /* Transmit REQA (7 bits) */
#define CMD_TX_WUPA             0xC7  /* Transmit WUPA (7 bits) */
#define CMD_NFC_INITIAL_RF_COL  0xC8  /* NFC Initial RF Collision Avoidance */
#define CMD_NFC_RESPONSE_RF_COL 0xC9  /* NFC Response RF Collision n=0 */
#define CMD_NFC_RESPONSE_RF_N   0xCA  /* NFC Response RF Collision n>0 */
#define CMD_GOTO_SENSE          0xCD  /* Target: go to Sense state */
#define CMD_GOTO_SLEEP          0xCE  /* Target: go to Sleep state */

/* Legacy aliases */
#define CMD_STOP_ALL            CMD_CLEAR
#define CMD_CLEAR_FIFO          CMD_CLEAR  /* ST25R3916 has no dedicated FIFO-clear; CLEAR does both */

/* ── Data/Modulation Commands (0xD0-0xD6) ── */
#define CMD_MASK_RX_DATA        0xD0  /* Mask receive data */
#define CMD_UNMASK_RX_DATA      0xD1  /* Unmask receive data */
#define CMD_AM_MOD_STATE_CHG    0xD2  /* AM Modulation state change */
#define CMD_MEAS_AMPLITUDE      0xD3  /* Measure RF field amplitude */
#define CMD_RESET_RX_GAIN       0xD5  /* Reset RX gain */
#define CMD_ADJUST_REGULATORS   0xD6  /* Calibrate voltage regulators */

/* ── Calibration/Measurement (0xD8-0xDE) ── */
#define CMD_CALIBRATE_DRIVER    0xD8  /* Calibrate antenna driver timing */
#define CMD_MEAS_PHASE          0xD9  /* Measure RF phase */
#define CMD_CLEAR_RSSI          0xDA  /* Clear RSSI measurement */
#define CMD_TRANSPARENT_MODE    0xDB  /* Enter transparent mode */
#define CMD_CALIBRATE_C_SENSOR  0xDC  /* Calibrate capacitive sensor */
#define CMD_MEAS_CAPACITANCE    0xDD  /* Measure capacitance */
#define CMD_MEAS_VDD            0xDE  /* Measure supply voltage */

/* ── Timer Commands (0xDF-0xE3) ── */
#define CMD_START_GP_TIMER      0xDF  /* Start General Purpose Timer */
#define CMD_START_WU_TIMER      0xE0  /* Start Wakeup Timer */
#define CMD_START_MASK_RX_TIMER 0xE1  /* Start Mask Receive Timer */
#define CMD_START_NRT           0xE2  /* Start No-Response Timer */
#define CMD_START_PPON2_TIMER   0xE3  /* Start PPON2 Timer */

/* ── Special Commands ── */
#define CMD_TEST_ACCESS         0xFC  /* Enable test register access */

/* ── SPI FIFO Prefixes ── */
#define SPI_FIFO_LOAD           0x80
#define SPI_FIFO_READ           0x9F

/* ── Anti-collision SELECT commands (ISO14443-3) ── */
#define SEL_CL1                 0x93
#define SEL_CL2                 0x95
#define SEL_CL3                 0x97

#endif
