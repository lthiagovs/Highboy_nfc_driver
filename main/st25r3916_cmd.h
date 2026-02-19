/**
 * @file st25r3916_cmd.h
 * @brief ST25R3916 Direct Commands.
 *
 * These are single-byte SPI transactions. Values taken directly
 * from working code where they are proven on real hardware.
 */
#ifndef ST25R3916_CMD_H
#define ST25R3916_CMD_H

/* ── Direct Commands (proven values) ── */
#define CMD_SET_DEFAULT         0xC0  /* Soft reset: all regs to defaults */
#define CMD_STOP_ALL            0xC2  /* Stop all activities */
#define CMD_TX_WITH_CRC         0xC4  /* Transmit + append CRC */
#define CMD_TX_WO_CRC           0xC5  /* Transmit without CRC */
#define CMD_TX_REQA             0xC6  /* Transmit REQA (7 bits) */
#define CMD_TX_WUPA             0xC7  /* Transmit WUPA (7 bits) */
#define CMD_NFC_INITIAL_RF_COL  0xC8  /* NFC Initial RF Collision Avoidance */
#define CMD_NFC_RESPONSE_RF_COL 0xC9  /* NFC Response RF Collision Avoidance */
#define CMD_GOTO_SENSE          0xCD  /* Target: go to Sense state */
#define CMD_GOTO_SLEEP          0xCE  /* Target: go to Sleep state */
#define CMD_ADJUST_REGULATORS   0xD6  /* Calibrate regulators */
#define CMD_RESET_RX_GAIN       0xD5  /* Reset RX gain */
#define CMD_CALIBRATE_DRIVER    0xD7  /* Calibrate antenna driver timing */
#define CMD_MEAS_AMPLITUDE      0xD8  /* Measure RF amplitude */
#define CMD_MEAS_PHASE          0xD9  /* Measure RF phase */
#define CMD_CLEAR_FIFO          0xDB  /* Clear FIFO */
#define CMD_TRANSPARENT_MODE    0xDC  /* Enter transparent mode */
#define CMD_CALIBRATE_C_SENSOR  0xDD  /* Calibrate capacitive sensor */
#define CMD_MEAS_CAPACITANCE    0xDE  /* Measure capacitance */
#define CMD_MEAS_VDD            0xDF  /* Measure VDD */
#define CMD_START_GP_TIMER      0xE0  /* Start General Purpose Timer */
#define CMD_START_WU_TIMER      0xE1  /* Start Wakeup Timer */
#define CMD_START_MASK_RX_TIMER 0xE2  /* Start Mask Receive Timer */
#define CMD_START_NRT           0xE3  /* Start No-Response Timer */

/* ── SPI FIFO Prefixes ── */
#define SPI_FIFO_LOAD           0x80
#define SPI_FIFO_READ           0x9F

/* ── Anti-collision SELECT commands ── */
#define SEL_CL1                 0x93
#define SEL_CL2                 0x95
#define SEL_CL3                 0x97

#endif
