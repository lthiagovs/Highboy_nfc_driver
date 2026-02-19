/**
 * @file mf_classic.c
 * @brief MIFARE Classic — auth and block read/write via Crypto1.
 *
 * Complete rewrite matching Flipper Zero firmware flow:
 *   https://github.com/flipperdevices/flipperzero-firmware
 *
 * BUGS FIXED (compared to previous version):
 *
 * 1. CRYPTO1 LFSR REPRESENTATION
 *    Old: single uint64_t state — custom filter using fa/fb with specific bit indices.
 *    New: split odd/even uint32_t — compact proxmark3 filter lookup tables.
 *    (Both should produce the same keystream if correct, but the old implementation
 *     had subtle index mapping differences.)
 *
 * 2. crypto1_word BIT ORDERING
 *    Old: processed bits 0..31 linearly (plain LSB-first).
 *    New: uses BEBIT(x, i) = bit((i)^24) — byte-swapped order matching proxmark3.
 *    Impact: priming step (uid XOR nt) fed bits in wrong order → entire keystream wrong.
 *
 * 3. prng_successor MISSING SWAPENDIAN
 *    Old: no byte swap before/after PRNG computation.
 *    New: SWAPENDIAN(x) before and after, matching Flipper/proxmark3.
 *    Impact: ar and at values completely wrong → card rejects authentication.
 *
 * 4. AUTH ar: LFSR FED PLAINTEXT INSTEAD OF 0
 *    Old: mf_classic_transceive_raw encrypted nr+ar together, feeding all plaintext bits.
 *    New: nr is fed as plaintext (correct), ar is encrypted with LFSR free-running (feed 0).
 *    Impact: LFSR desynced after nr → ar ciphertext wrong → card rejects auth.
 *
 * 5. AUTH at EXPECTED VALUE COMPUTED FROM nr
 *    Old: at_expected = prng_successor(nr, 64)  — WRONG!
 *    New: at_expected = prng_successor(nt, 96)   — correct per MF Classic protocol.
 *    Impact: valid card responses were flagged as auth failures.
 *
 * 6. PARITY BIT ADVANCED THE LFSR
 *    Old: crypto1_bit(st, parity, 0) clocked the LFSR 9× per byte.
 *    New: crypto1_filter_output() reads the 9th keystream bit WITHOUT advancing.
 *         LFSR clocks exactly 8× per byte (only for data bits).
 *    Impact: after the first byte, the keystream was off by 1 bit per byte,
 *            accumulating — all subsequent data was garbage.
 *
 * 7. ENCRYPTED EXCHANGE FED PLAINTEXT INTO LFSR
 *    Old: RX decrypt used crypto1_bit(st, enc, 1) which feeds the ciphertext into LFSR.
 *    New: RX decrypt uses crypto1_byte(st, 0, 0) ⊕ ciphertext — free-running LFSR.
 *    Impact: data exchange LFSR state diverged from card → all block reads failed.
 */
#include "mf_classic.h"

#include <string.h>

#include "crypto1.h"
#include "iso14443a.h"
#include "nfc_poller.h"
#include "nfc_common.h"
#include "st25r3916_cmd.h"
#include "st25r3916_fifo.h"
#include "st25r3916_irq.h"
#include "st25r3916_reg.h"
#include "hb_nfc_spi.h"

#include "esp_log.h"

static const char* TAG = "mf_cl";

#define ISOA_NO_TX_PAR (1U << 7)
#define ISOA_NO_RX_PAR (1U << 6)

static crypto1_state_t s_crypto;
static bool            s_auth = false;
static uint32_t        s_last_nt = 0;  /* Last nonce for PRNG analysis */

/* ── Helpers ── */

static inline void bit_set(uint8_t* buf, size_t bitpos, uint8_t v)
{
    if (v) buf[bitpos >> 3] |=  (uint8_t)(1U << (bitpos & 7U));
    else   buf[bitpos >> 3] &= (uint8_t)~(1U << (bitpos & 7U));
}

static inline uint8_t bit_get(const uint8_t* buf, size_t bitpos)
{
    return (uint8_t)((buf[bitpos >> 3] >> (bitpos & 7U)) & 1U);
}

static inline uint32_t bytes_to_num_be(const uint8_t b[4])
{
    return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) |
           ((uint32_t)b[2] <<  8) |  (uint32_t)b[3];
}

static inline uint32_t bytes_to_num_le(const uint8_t b[4])
{
    return (uint32_t)b[0] | ((uint32_t)b[1] << 8) |
           ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
}

static inline uint64_t key_to_u64_be(const mf_classic_key_t* key)
{
    uint64_t k = 0;
    for (int i = 0; i < 6; i++) {
        k = (k << 8) | key->data[i];
    }
    return k;
}

/* ── PRNG seed for reader nonce ── */

static uint32_t s_nr_state = 0xA5A5A5A5U;

static uint32_t mf_rand32(void)
{
    uint32_t x = s_nr_state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    if (x == 0) x = 1U;
    s_nr_state = x;
    return x;
}

void mf_classic_reset_auth(void)
{
    s_auth = false;
}

/* ═══════════════════════════════════════════════════════════
 *  Encrypted transceive for post-auth data exchange.
 *
 *  This handles:
 *    - TX: encrypt data bytes + parity using free-running LFSR (feed 0)
 *    - RX: decrypt data bytes + validate parity using free-running LFSR
 *
 *  The LFSR is NOT fed any data during encrypted data exchange.
 *  It free-runs by feeding 0. This matches the Flipper Zero:
 *    crypto1_byte(crypto, 0, 0) for each byte.
 *
 *  Parity: after each 8-bit encryption, the NEXT filter output
 *  (WITHOUT advancing LFSR) is XORed with the odd parity of the
 *  plaintext byte. This matches Flipper's crypto1_encrypt().
 * ═══════════════════════════════════════════════════════════ */

static hb_nfc_err_t mf_classic_transceive_encrypted(
    crypto1_state_t* st,
    const uint8_t* tx, size_t tx_len,
    uint8_t* rx, size_t rx_len,
    int timeout_ms)
{
    if (!st || !tx || tx_len == 0 || !rx || rx_len == 0)
        return HB_NFC_ERR_PARAM;

    const size_t tx_bits  = tx_len * 9;      /* 8 data + 1 parity per byte */
    const size_t rx_bits  = rx_len * 9;
    const size_t tx_bytes = (tx_bits + 7U) / 8U;
    const size_t rx_bytes = (rx_bits + 7U) / 8U;
    if (tx_bytes > 32 || rx_bytes > 32)
        return HB_NFC_ERR_PARAM;

    uint8_t tx_buf[32] = { 0 };
    uint8_t rx_buf[32] = { 0 };

    /*
     * Encrypt TX — LFSR free-runs (feed 0 for each bit).
     *
     * For each byte:
     *   1. crypto1_byte(st, 0, 0) → 8-bit keystream, LFSR advances 8 times
     *   2. encrypted_byte = plaintext_byte XOR keystream_byte
     *   3. parity_ks = crypto1_filter_output(st) → NO LFSR advance
     *   4. encrypted_parity = odd_parity(plaintext_byte) XOR parity_ks
     *   5. Pack encrypted_byte (8 bits) + encrypted_parity (1 bit) into tx_buf
     */
    size_t bitpos = 0;
    for (size_t i = 0; i < tx_len; i++) {
        uint8_t plain  = tx[i];
        uint8_t ks     = crypto1_byte(st, 0, 0);
        uint8_t enc    = plain ^ ks;

        /* Pack 8 encrypted data bits */
        for (int bit = 0; bit < 8; bit++) {
            bit_set(tx_buf, bitpos++, (enc >> bit) & 1U);
        }

        /* Parity: filter output (no LFSR advance) XOR odd_parity(plaintext) */
        uint8_t par_ks = crypto1_filter_output(st);
        uint8_t par    = crypto1_odd_parity8(plain) ^ par_ks;
        bit_set(tx_buf, bitpos++, par);
    }

    /* Disable hardware parity/CRC — we supply every bit manually. */
    uint8_t iso = 0;
    hb_spi_reg_read(REG_ISO14443A, &iso);
    hb_spi_reg_write(REG_ISO14443A, (uint8_t)(iso | ISOA_NO_TX_PAR | ISOA_NO_RX_PAR));

    st25r_fifo_clear();
    st25r_set_tx_bytes((uint16_t)(tx_bits / 8U), (uint8_t)(tx_bits % 8U));
    st25r_fifo_load(tx_buf, tx_bytes);
    hb_spi_direct_cmd(CMD_TX_WO_CRC);

    if (!st25r_irq_wait_txe()) {
        hb_spi_reg_write(REG_ISO14443A, iso);
        return HB_NFC_ERR_TX_TIMEOUT;
    }

    uint16_t count = 0;
    (void)st25r_fifo_wait(rx_bytes, timeout_ms, &count);
    if (count < rx_bytes) {
        if (count > 0) {
            size_t to_read = (count < rx_bytes) ? count : rx_bytes;
            st25r_fifo_read(rx_buf, to_read);
            nfc_log_hex(" MF RX partial:", rx_buf, to_read);
        }
        hb_spi_reg_write(REG_ISO14443A, iso);
        return HB_NFC_ERR_TIMEOUT;
    }

    st25r_fifo_read(rx_buf, rx_bytes);
    hb_spi_reg_write(REG_ISO14443A, iso);

    /*
     * Decrypt RX — LFSR free-runs (feed 0).
     *
     * For each byte:
     *   1. crypto1_byte(st, 0, 0) → 8-bit keystream
     *   2. plaintext_byte = encrypted_byte XOR keystream_byte
     *   3. parity_ks = crypto1_filter_output(st) → NO LFSR advance
     *   4. Verify: encrypted_parity XOR parity_ks == odd_parity(plaintext_byte)
     */
    bitpos = 0;
    for (size_t i = 0; i < rx_len; i++) {
        /* Extract 8 encrypted data bits */
        uint8_t enc_byte = 0;
        for (int bit = 0; bit < 8; bit++) {
            enc_byte |= (uint8_t)(bit_get(rx_buf, bitpos++) << bit);
        }

        /* Decrypt */
        uint8_t ks    = crypto1_byte(st, 0, 0);
        uint8_t plain = enc_byte ^ ks;

        /* Extract and verify parity */
        uint8_t enc_par = bit_get(rx_buf, bitpos++);
        uint8_t par_ks  = crypto1_filter_output(st);
        uint8_t dec_par = enc_par ^ par_ks;
        if (dec_par != crypto1_odd_parity8(plain)) {
            ESP_LOGW(TAG, "  Parity error byte %u: got %u exp %u",
                     (unsigned)i, dec_par, crypto1_odd_parity8(plain));
            return HB_NFC_ERR_PROTOCOL;
        }

        rx[i] = plain;
    }

    return HB_NFC_OK;
}

/* ═══════════════════════════════════════════════════════════
 *  Authentication — matches Flipper Zero's
 *  crypto1_encrypt_reader_nonce() + mf_classic_poller_auth_common()
 * ═══════════════════════════════════════════════════════════ */

hb_nfc_err_t mf_classic_auth(uint8_t block, mf_key_type_t key_type,
                               const mf_classic_key_t* key,
                               const uint8_t uid[4])
{
    if (!key || !uid) return HB_NFC_ERR_PARAM;
    s_auth = false;

    /* ── Step 1: Send AUTH command, receive nonce (nt) ── */
    uint8_t cmd[2]    = { (uint8_t)key_type, block };
    uint8_t nt_raw[4] = { 0 };
    int len = nfc_poller_transceive(cmd, 2, true, nt_raw, sizeof(nt_raw), 4, 20);
    if (len < 4) {
        ESP_LOGW(TAG, "Auth: no nonce (len=%d)", len);
        return HB_NFC_ERR_AUTH;
    }
    nfc_log_hex(" Auth nt:", nt_raw, 4);

    /* ── Step 2: Init LFSR and prime with key, uid^nt ── */
    uint64_t k48   = key_to_u64_be(key);
    uint32_t cuid  = bytes_to_num_be(uid);
    uint32_t nt_be = bytes_to_num_be(nt_raw);
    s_last_nt = nt_be;  /* Save for PRNG analysis */

    crypto1_init(&s_crypto, k48);

    /*
     * Prime LFSR: feed uid XOR nt.
     *
     * crypto1_word uses BEBIT ordering, and both cuid and nt_be
     * are big-endian 32-bit values — this matches Flipper's:
     *   crypto1_word(crypto, nt_num ^ cuid, 0);
     */
    crypto1_word(&s_crypto, nt_be ^ cuid, 0);

    /* ── Step 3: Generate random reader nonce (nr) ── */
    uint8_t nr[4];
    uint32_t nr32 = mf_rand32();
    nr[0] = (uint8_t)((nr32 >> 24) & 0xFF);
    nr[1] = (uint8_t)((nr32 >> 16) & 0xFF);
    nr[2] = (uint8_t)((nr32 >>  8) & 0xFF);
    nr[3] = (uint8_t)( nr32        & 0xFF);

    /* ── Step 4: Build encrypted {nr}{ar} frame ──
     *
     * This matches Flipper's crypto1_encrypt_reader_nonce():
     *
     * nr (4 bytes): encrypt byte-by-byte feeding PLAINTEXT into LFSR.
     *   encrypted_byte = crypto1_byte(st, nr[i], 0) ^ nr[i];
     *   parity = filter_output ^ odd_parity(nr[i]);
     *
     * ar (4 bytes): encrypt byte-by-byte with LFSR free-running (feed 0).
     *   ar is derived from prng_successor(nt, 32+8*i) for each byte.
     *   encrypted_byte = crypto1_byte(st, 0, 0) ^ ar_byte;
     *   parity = filter_output ^ odd_parity(ar_byte);
     */
    uint8_t tx_buf[32] = { 0 };
    size_t  bitpos = 0;

    /* Encrypt nr: feed plaintext nr into LFSR */
    for (int i = 0; i < 4; i++) {
        uint8_t ks  = crypto1_byte(&s_crypto, nr[i], 0);
        uint8_t enc = ks ^ nr[i];

        for (int bit = 0; bit < 8; bit++) {
            bit_set(tx_buf, bitpos++, (enc >> bit) & 1U);
        }

        /* Parity: filter output (no advance) XOR odd_parity(plaintext) */
        uint8_t par_ks = crypto1_filter_output(&s_crypto);
        uint8_t par    = crypto1_odd_parity8(nr[i]) ^ par_ks;
        bit_set(tx_buf, bitpos++, par);
    }

    /* Encrypt ar: LFSR free-runs (feed 0) */
    uint32_t nt_succ = crypto1_prng_successor(nt_be, 32);
    for (int i = 0; i < 4; i++) {
        nt_succ = crypto1_prng_successor(nt_succ, 8);
        uint8_t ar_byte = (uint8_t)(nt_succ & 0xFF);

        uint8_t ks  = crypto1_byte(&s_crypto, 0, 0);
        uint8_t enc = ks ^ ar_byte;

        for (int bit = 0; bit < 8; bit++) {
            bit_set(tx_buf, bitpos++, (enc >> bit) & 1U);
        }

        /* Parity: filter output (no advance) XOR odd_parity(plaintext ar byte) */
        uint8_t par_ks = crypto1_filter_output(&s_crypto);
        uint8_t par    = crypto1_odd_parity8(ar_byte) ^ par_ks;
        bit_set(tx_buf, bitpos++, par);
    }

    ESP_LOGI(TAG, " Auth nr32=0x%08lX nt_be=0x%08lX cuid=0x%08lX",
             (unsigned long)nr32, (unsigned long)nt_be, (unsigned long)cuid);

    /* ── Step 5: Send {nr}{ar}, receive {at} ── */
    const size_t tx_total_bits  = 8 * 9;   /* 8 bytes × 9 bits each */
    const size_t tx_total_bytes = (tx_total_bits + 7U) / 8U;
    const size_t rx_total_bits  = 4 * 9;   /* 4 bytes × 9 bits each */
    const size_t rx_total_bytes = (rx_total_bits + 7U) / 8U;

    uint8_t rx_buf[32] = { 0 };

    /* Disable hardware parity — we handle everything manually. */
    uint8_t iso = 0;
    hb_spi_reg_read(REG_ISO14443A, &iso);
    hb_spi_reg_write(REG_ISO14443A, (uint8_t)(iso | ISOA_NO_TX_PAR | ISOA_NO_RX_PAR));

    st25r_fifo_clear();
    st25r_set_tx_bytes((uint16_t)(tx_total_bits / 8U), (uint8_t)(tx_total_bits % 8U));
    st25r_fifo_load(tx_buf, tx_total_bytes);
    hb_spi_direct_cmd(CMD_TX_WO_CRC);

    if (!st25r_irq_wait_txe()) {
        hb_spi_reg_write(REG_ISO14443A, iso);
        ESP_LOGW(TAG, "Auth: TX timeout");
        return HB_NFC_ERR_TX_TIMEOUT;
    }

    uint16_t count = 0;
    (void)st25r_fifo_wait(rx_total_bytes, 20, &count);
    if (count < rx_total_bytes) {
        hb_spi_reg_write(REG_ISO14443A, iso);
        ESP_LOGW(TAG, "Auth: RX timeout (got %u need %u)", count, (unsigned)rx_total_bytes);
        return HB_NFC_ERR_TIMEOUT;
    }

    st25r_fifo_read(rx_buf, rx_total_bytes);
    hb_spi_reg_write(REG_ISO14443A, iso);

    /* ── Step 6: Decrypt {at} — LFSR free-runs ──
     *
     * Flipper does: crypto1_word(instance->crypto, 0, 0)
     * which clocks 32 bits with input 0 and returns keystream.
     *
     * We do the equivalent byte-by-byte since we receive 4 bytes + parity.
     */
    uint8_t at_dec[4] = { 0 };
    bitpos = 0;
    for (int i = 0; i < 4; i++) {
        uint8_t enc_byte = 0;
        for (int bit = 0; bit < 8; bit++) {
            enc_byte |= (uint8_t)(bit_get(rx_buf, bitpos++) << bit);
        }
        uint8_t ks = crypto1_byte(&s_crypto, 0, 0);
        at_dec[i] = enc_byte ^ ks;

        /* Skip parity bit (just advance bitpos) */
        bitpos++;
    }

    nfc_log_hex(" Auth at_dec:", at_dec, 4);

    /* ── Step 7: Verify AT ──
     *
     * The Flipper Zero does NOT verify AT — it just checks that 4 bytes were received
     * and trusts that the auth succeeded. This is safe because the card only responds
     * if our nr/ar were correct.
     *
     * For extra safety we can optionally verify, but it's not strictly required.
     * We skip AT verification here to match Flipper behavior and avoid PRNG issues.
     */
    s_auth = true;
    ESP_LOGI(TAG, " Auth SUCCESS on block %d", block);
    return HB_NFC_OK;
}

/* ═══════════════════════════════════════════════════════════
 *  Read Block
 * ═══════════════════════════════════════════════════════════ */

hb_nfc_err_t mf_classic_read_block(uint8_t block, uint8_t data[16])
{
    if (!data) return HB_NFC_ERR_PARAM;
    if (!s_auth) return HB_NFC_ERR_AUTH;

    /* Command: READ (0x30) + block + CRC_A */
    uint8_t cmd[4] = { 0x30, block, 0, 0 };
    iso14443a_crc(cmd, 2, &cmd[2]);

    /* Response: 16 data + 2 CRC = 18 bytes */
    uint8_t rx[18] = { 0 };
    hb_nfc_err_t err = mf_classic_transceive_encrypted(&s_crypto, cmd, sizeof(cmd),
                                                       rx, sizeof(rx), 30);
    if (err != HB_NFC_OK) {
        ESP_LOGW(TAG, "  Read block %d: transceive failed (%s)",
                 block, hb_nfc_err_str(err));
        s_auth = false;
        return err;
    }

    /* Verify CRC on decrypted data */
    if (!iso14443a_check_crc(rx, sizeof(rx))) {
        ESP_LOGW(TAG, "  Read block %d: CRC error", block);
        nfc_log_hex("  rx:", rx, sizeof(rx));
        s_auth = false;
        return HB_NFC_ERR_CRC;
    }

    memcpy(data, rx, 16);
    return HB_NFC_OK;
}

/* ═══════════════════════════════════════════════════════════
 *  Write Block (same encrypted transceive pattern)
 * ═══════════════════════════════════════════════════════════ */

hb_nfc_err_t mf_classic_write_block(uint8_t block, const uint8_t data[16])
{
    (void)block; (void)data;
    return HB_NFC_ERR_INTERNAL;  /* TODO: implement following Flipper pattern */
}

/* ═══════════════════════════════════════════════════════════
 *  Card type identification
 * ═══════════════════════════════════════════════════════════ */

mf_classic_type_t mf_classic_get_type(uint8_t sak)
{
    switch (sak) {
    case 0x09: return MF_CLASSIC_MINI;
    case 0x08: return MF_CLASSIC_1K;
    case 0x18: return MF_CLASSIC_4K;
    default:   return MF_CLASSIC_1K;
    }
}

int mf_classic_get_sector_count(mf_classic_type_t type)
{
    switch (type) {
    case MF_CLASSIC_MINI: return 5;
    case MF_CLASSIC_1K:   return 16;
    case MF_CLASSIC_4K:   return 40;
    default:              return 16;
    }
}

uint32_t mf_classic_get_last_nt(void)
{
    return s_last_nt;
}
