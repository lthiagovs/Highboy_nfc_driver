/**
 * @file nfc_listener.h
 * @brief NFC Listener — card emulation control (Phase 9).
 */
#ifndef NFC_LISTENER_H
#define NFC_LISTENER_H

#include "highboy_nfc_error.h"
#include "highboy_nfc_types.h"

hb_nfc_err_t nfc_listener_start(const hb_nfc_card_data_t* card);
void         nfc_listener_stop(void);

#endif
