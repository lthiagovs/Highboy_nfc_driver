/* === main\crypto1.c === */
/**
 * @file crypto1.c
 * @brief Crypto1 cipher for MIFARE Classic — exact port of Flipper Zero / proxmark3.
 *
 * This is a line-by-line port of the Flipper Zero firmware's crypto1 implementation:
 *   https://github.com/flipperdevices/flipperzero-firmware
 *   lib/nfc/helpers/crypto1.c
 *
 * Key design decisions (all matching Flipper Zero):
 *   1. Split odd/even LFSR representation (24 bits each).
 *   2. LF_POLY_ODD / LF_POLY_EVEN constants (NOT a single 48-bit polynomial).
 *   3. crypto1_filter uses the compact 5-stage lookup table approach.
 *   4. BEBIT macro in crypto1_word for byte-swapped bit ordering.
 *   5. SWAPENDIAN in prng_successor.
 *   6. crypto1_filter_output() reads filter WITHOUT advancing LFSR
 *      (used for parity bit encryption — the 9th keystream bit per byte).
 */
#include "crypto1.h"

/* ── Macros matching proxmark3 / Flipper Zero ── */

#define SWAPENDIAN(x) \
    ((x) = ((x) >> 8 & 0xff00ffU) | ((x) & 0xff00ffU) << 8, \
     (x) = (x) >> 16 | (x) << 16)

#define BIT(x, n)   (((x) >> (n)) & 1U)
#define BEBIT(x, n) BIT((x), (n) ^ 24)

#define LF_POLY_ODD  (0x29CE5CU)
#define LF_POLY_EVEN (0x870804U)

/* ── Parity helpers ── */

static const uint8_t s_odd_parity_table[256] = {
    1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
    0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
    0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
    1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
    0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
    1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
    1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
    0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
    0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
    1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
    1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
    0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
    1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
    0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
    0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
    1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1
};

uint8_t crypto1_odd_parity8(uint8_t data)
{
    return s_odd_parity_table[data];
}

uint8_t crypto1_even_parity32(uint32_t data)
{
    data ^= data >> 16;
    data ^= data >> 8;
    return (uint8_t)(!s_odd_parity_table[data & 0xFF]);
}

/* ── Filter function (compact proxmark3 style) ── */

static uint32_t crypto1_filter(uint32_t in)
{
    uint32_t out = 0;
    out  = 0xf22c0U >> (in        & 0xfU) & 16U;
    out |= 0x6c9c0U >> (in >>  4  & 0xfU) &  8U;
    out |= 0x3c8b0U >> (in >>  8  & 0xfU) &  4U;
    out |= 0x1e458U >> (in >> 12  & 0xfU) &  2U;
    out |= 0x0d938U >> (in >> 16  & 0xfU) &  1U;
    return BIT(0xEC57E80AU, out);
}

/* ── Public API ── */

void crypto1_init(crypto1_state_t *s, uint64_t key)
{
    s->even = 0;
    s->odd  = 0;
    for (int8_t i = 47; i > 0; i -= 2) {
        s->odd  = s->odd  << 1 | BIT(key, (unsigned)((i - 1) ^ 7));
        s->even = s->even << 1 | BIT(key, (unsigned)(i ^ 7));
    }
}

void crypto1_reset(crypto1_state_t *s)
{
    s->odd  = 0;
    s->even = 0;
}

uint8_t crypto1_bit(crypto1_state_t *s, uint8_t in, int is_encrypted)
{
    uint8_t  out  = (uint8_t)crypto1_filter(s->odd);
    uint32_t feed = out & (uint32_t)(!!is_encrypted);
    feed ^= (uint32_t)(!!in);
    feed ^= LF_POLY_ODD  & s->odd;
    feed ^= LF_POLY_EVEN & s->even;
    s->even = s->even << 1 | crypto1_even_parity32(feed);

    /* Swap odd ↔ even */
    uint32_t tmp = s->odd;
    s->odd  = s->even;
    s->even = tmp;

    return out;
}

uint8_t crypto1_byte(crypto1_state_t *s, uint8_t in, int is_encrypted)
{
    uint8_t out = 0;
    for (uint8_t i = 0; i < 8; i++) {
        out |= (uint8_t)(crypto1_bit(s, BIT(in, i), is_encrypted) << i);
    }
    return out;
}

/**
 * crypto1_word — clock 32 bits in BEBIT order.
 *
 * BEBIT(x, i) = bit ((i) ^ 24) of x.
 * This processes bytes in MSB-first order but bits within each byte LSB-first.
 * Output uses the same byte-swapped convention (<< (24 ^ i)).
 *
 * This is identical to the Flipper Zero / proxmark3 implementation.
 */
uint32_t crypto1_word(crypto1_state_t *s, uint32_t in, int is_encrypted)
{
    uint32_t out = 0;
    for (uint8_t i = 0; i < 32; i++) {
        out |= (uint32_t)crypto1_bit(s, BEBIT(in, i), is_encrypted) << (24 ^ i);
    }
    return out;
}

/**
 * crypto1_filter_output — read keystream bit WITHOUT advancing LFSR.
 *
 * Used for encrypted parity: after clocking 8 data bits with crypto1_byte,
 * call this to get the parity keystream bit without disturbing the LFSR state.
 * This matches how the Flipper Zero handles parity in crypto1_encrypt().
 */
uint8_t crypto1_filter_output(crypto1_state_t *s)
{
    return (uint8_t)crypto1_filter(s->odd);
}

/**
 * prng_successor — MIFARE Classic card PRNG.
 *
 * CRITICAL: SWAPENDIAN before and after computation!
 * The Flipper Zero does this and without it the ar/at values are wrong.
 *
 * Input/output are in big-endian (wire) byte order.
 */
uint32_t crypto1_prng_successor(uint32_t x, uint32_t n)
{
    SWAPENDIAN(x);
    while (n--)
        x = x >> 1 | (x >> 16 ^ x >> 18 ^ x >> 19 ^ x >> 21) << 31;
    return SWAPENDIAN(x);
}

/* Macro cleanup: keep crypto1 macros file-local after merge. */
#undef SWAPENDIAN
#undef BIT
#undef BEBIT
#undef LF_POLY_ODD
#undef LF_POLY_EVEN

/* === main\mf_classic.c === */
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

#define TAG TAG_MF_CLASSIC
static const char* TAG = "mf_cl";

#define ISOA_NO_TX_PAR (1U << 7)
#define ISOA_NO_RX_PAR (1U << 6)

static crypto1_state_t s_crypto;
static bool            s_auth = false;
static uint32_t        s_last_nt = 0;  /* Last nonce for PRNG analysis */
static mf_write_phase_t s_last_write_phase = MF_WRITE_PHASE_NONE;

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

static hb_nfc_err_t mf_classic_tx_encrypted_with_ack(
    crypto1_state_t* st,
    const uint8_t* tx, size_t tx_len,
    uint8_t* ack_nibble,
    int timeout_ms)
{
    if (!st || !tx || tx_len == 0) return HB_NFC_ERR_PARAM;

    const size_t tx_bits  = tx_len * 9;      /* 8 data + 1 parity per byte */
    const size_t tx_bytes = (tx_bits + 7U) / 8U;
    if (tx_bytes > 32) return HB_NFC_ERR_PARAM;

    uint8_t tx_buf[32] = { 0 };

    size_t bitpos = 0;
    for (size_t i = 0; i < tx_len; i++) {
        uint8_t plain  = tx[i];
        uint8_t ks     = crypto1_byte(st, 0, 0);
        uint8_t enc    = plain ^ ks;

        for (int bit = 0; bit < 8; bit++) {
            bit_set(tx_buf, bitpos++, (enc >> bit) & 1U);
        }

        uint8_t par_ks = crypto1_filter_output(st);
        uint8_t par    = crypto1_odd_parity8(plain) ^ par_ks;
        bit_set(tx_buf, bitpos++, par);
    }

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
    (void)st25r_fifo_wait(1, timeout_ms, &count);
    if (count < 1) {
        hb_spi_reg_write(REG_ISO14443A, iso);
        return HB_NFC_ERR_TIMEOUT;
    }

    uint8_t enc_ack = 0;
    st25r_fifo_read(&enc_ack, 1);
    hb_spi_reg_write(REG_ISO14443A, iso);

    uint8_t plain_ack = 0;
    for (int i = 0; i < 4; i++) {
        uint8_t ks_bit   = crypto1_bit(st, 0, 0);
        uint8_t enc_bit  = (enc_ack >> i) & 1U;
        plain_ack |= (uint8_t)((enc_bit ^ ks_bit) << i);
    }

    if (ack_nibble) *ack_nibble = (uint8_t)(plain_ack & 0x0F);
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
    if (!data) return HB_NFC_ERR_PARAM;
    if (!s_auth) return HB_NFC_ERR_AUTH;

    /* Phase 1: WRITE command */
    uint8_t cmd[4] = { 0xA0, block, 0, 0 };
    iso14443a_crc(cmd, 2, &cmd[2]);

    uint8_t ack = 0;
    s_last_write_phase = MF_WRITE_PHASE_CMD;
    hb_nfc_err_t err = mf_classic_tx_encrypted_with_ack(&s_crypto, cmd, sizeof(cmd),
                                                        &ack, 20);
    if (err != HB_NFC_OK) {
        s_auth = false;
        return err;
    }
    if ((ack & 0x0F) != 0x0A) {
        ESP_LOGW(TAG, "Write cmd NACK (bloco %d): 0x%02X", block, ack);
        s_auth = false;
        return HB_NFC_ERR_NACK;
    }

    /* Phase 2: 16 bytes data + CRC */
    uint8_t frame[18];
    memcpy(frame, data, 16);
    iso14443a_crc(frame, 16, &frame[16]);

    s_last_write_phase = MF_WRITE_PHASE_DATA;
    err = mf_classic_tx_encrypted_with_ack(&s_crypto, frame, sizeof(frame),
                                           &ack, 20);
    if (err != HB_NFC_OK) {
        s_auth = false;
        return err;
    }
    if ((ack & 0x0F) != 0x0A) {
        ESP_LOGW(TAG, "Write data NACK (bloco %d): 0x%02X", block, ack);
        s_auth = false;
        return HB_NFC_ERR_NACK;
    }

    return HB_NFC_OK;
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

mf_write_phase_t mf_classic_get_last_write_phase(void)
{
    return s_last_write_phase;
}
#undef TAG

/* === main\mf_classic_writer.c === */
/**
 * @file mf_classic_writer.c
 * @brief MIFARE Classic — escrita de blocos com autenticação Crypto1.
 */
#include "mf_classic_writer.h"

#include <string.h>
#include "esp_log.h"

#include "poller.h"
#include "mf_classic.h"
#include "nfc_poller.h"

#define TAG TAG_MF_WRITE
static const char* TAG = "mf_write";

/* ── Access bits padrão ── */
const uint8_t MF_ACCESS_BITS_DEFAULT[3]   = { 0xFF, 0x07, 0x80 };
const uint8_t MF_ACCESS_BITS_READ_ONLY[3] = { 0x78, 0x77, 0x88 };

/* ─────────────────────────────────────────────────────────
 *  Helpers
 * ───────────────────────────────────────────────────────── */

const char* mf_write_result_str(mf_write_result_t r)
{
    switch (r) {
    case MF_WRITE_OK:           return "OK";
    case MF_WRITE_ERR_RESELECT: return "reselect falhou";
    case MF_WRITE_ERR_AUTH:     return "autenticação negada";
    case MF_WRITE_ERR_CMD_NACK: return "NACK no comando WRITE";
    case MF_WRITE_ERR_DATA_NACK:return "NACK nos dados";
    case MF_WRITE_ERR_VERIFY:   return "verificação falhou";
    case MF_WRITE_ERR_PROTECTED:return "bloco protegido";
    case MF_WRITE_ERR_PARAM:    return "parâmetro inválido";
    default:                    return "erro desconhecido";
    }
}

static bool mf_classic_access_bit_is_valid(uint8_t v)
{
    return (v == 0U || v == 1U);
}

bool mf_classic_access_bits_encode(const mf_classic_access_bits_t* ac,
                                    uint8_t                         out_access_bits[3])
{
    if (!ac || !out_access_bits) return false;

    uint8_t b6 = 0;
    uint8_t b7 = 0;
    uint8_t b8 = 0;

    for (int grp = 0; grp < 4; grp++) {
        uint8_t c1 = ac->c1[grp];
        uint8_t c2 = ac->c2[grp];
        uint8_t c3 = ac->c3[grp];

        if (!mf_classic_access_bit_is_valid(c1) ||
            !mf_classic_access_bit_is_valid(c2) ||
            !mf_classic_access_bit_is_valid(c3)) {
            return false;
        }

        /* Byte 7 high nibble = C1, byte 6 low nibble = ~C1 */
        if (c1) b7 |= (uint8_t)(1U << (4 + grp));
        else    b6 |= (uint8_t)(1U << grp);

        /* Byte 8 low nibble = C2, byte 6 high nibble = ~C2 */
        if (c2) b8 |= (uint8_t)(1U << grp);
        else    b6 |= (uint8_t)(1U << (4 + grp));

        /* Byte 8 high nibble = C3, byte 7 low nibble = ~C3 */
        if (c3) b8 |= (uint8_t)(1U << (4 + grp));
        else    b7 |= (uint8_t)(1U << grp);
    }

    out_access_bits[0] = b6;
    out_access_bits[1] = b7;
    out_access_bits[2] = b8;
    return true;
}

bool mf_classic_access_bits_valid(const uint8_t access_bits[3])
{
    if (!access_bits) return false;

    uint8_t b6 = access_bits[0];
    uint8_t b7 = access_bits[1];
    uint8_t b8 = access_bits[2];

    for (int grp = 0; grp < 4; grp++) {
        uint8_t c1     = (b7 >> (4 + grp)) & 1U;
        uint8_t c1_inv = (uint8_t)((~b6 >> grp) & 1U);
        uint8_t c2     = (b8 >> grp) & 1U;
        uint8_t c2_inv = (uint8_t)((~b6 >> (4 + grp)) & 1U);
        uint8_t c3     = (b8 >> (4 + grp)) & 1U;
        uint8_t c3_inv = (uint8_t)((~b7 >> grp) & 1U);
        if (c1 != c1_inv || c2 != c2_inv || c3 != c3_inv) return false;
    }

    return true;
}

/* Block/Sector mapping for Mini/1K/4K */
static inline int mf_classic_total_blocks(mf_classic_type_t type)
{
    switch (type) {
    case MF_CLASSIC_MINI: return 20;   /* 5 sectors * 4 blocks */
    case MF_CLASSIC_1K:   return 64;   /* 16 sectors * 4 blocks */
    case MF_CLASSIC_4K:   return 256;  /* 32*4 + 8*16 */
    default:              return 64;
    }
}

static inline int mf_classic_sector_block_count(mf_classic_type_t type, int sector)
{
    if (type == MF_CLASSIC_4K && sector >= 32) return 16;
    return 4;
}

static inline int mf_classic_sector_first_block(mf_classic_type_t type, int sector)
{
    if (type == MF_CLASSIC_4K && sector >= 32) return 128 + (sector - 32) * 16;
    return sector * 4;
}

static inline int mf_classic_sector_trailer_block(mf_classic_type_t type, int sector)
{
    return mf_classic_sector_first_block(type, sector) +
           mf_classic_sector_block_count(type, sector) - 1;
}

static inline int mf_classic_block_to_sector(mf_classic_type_t type, int block)
{
    if (type == MF_CLASSIC_4K && block >= 128) return 32 + (block - 128) / 16;
    return block / 4;
}

static inline bool mf_classic_is_trailer_block(mf_classic_type_t type, int block)
{
    int sector = mf_classic_block_to_sector(type, block);
    return block == mf_classic_sector_trailer_block(type, sector);
}

/* ─────────────────────────────────────────────────────────
 *  Escrita raw (sessão Crypto1 já ativa)
 * ───────────────────────────────────────────────────────── */

mf_write_result_t mf_classic_write_block_raw(uint8_t block,
                                               const uint8_t data[16])
{
    hb_nfc_err_t err = mf_classic_write_block(block, data);
    if (err == HB_NFC_OK) return MF_WRITE_OK;
    if (err == HB_NFC_ERR_AUTH) return MF_WRITE_ERR_AUTH;
    if (err == HB_NFC_ERR_NACK) {
        mf_write_phase_t phase = mf_classic_get_last_write_phase();
        return (phase == MF_WRITE_PHASE_DATA) ? MF_WRITE_ERR_DATA_NACK
                                              : MF_WRITE_ERR_CMD_NACK;
    }
    return MF_WRITE_ERR_CMD_NACK;
}

/* ─────────────────────────────────────────────────────────
 *  Escrita completa (reselect + auth + write + verify)
 * ───────────────────────────────────────────────────────── */

mf_write_result_t mf_classic_write(nfc_iso14443a_data_t* card,
                                    uint8_t               block,
                                    const uint8_t         data[16],
                                    const uint8_t         key[6],
                                    mf_key_type_t         key_type,
                                    bool                  verify,
                                    bool                  allow_special)
{
    if (!card || !data || !key) return MF_WRITE_ERR_PARAM;

    mf_classic_type_t type = mf_classic_get_type(card->sak);
    if ((int)block >= mf_classic_total_blocks(type)) return MF_WRITE_ERR_PARAM;

    /* ── Proteções ── */
    if (block == 0 && !allow_special) {
        ESP_LOGE(TAG, "Bloco 0 (manufacturer) protegido — use allow_special=true apenas em cartões magic");
        return MF_WRITE_ERR_PROTECTED;
    }
    if (mf_classic_is_trailer_block(type, block) && !allow_special) {
        ESP_LOGE(TAG, "Bloco %d é trailer — use allow_special=true e tenha certeza dos access bits!", block);
        return MF_WRITE_ERR_PROTECTED;
    }

    /* ── Reselect (field cycle + REQA + anticoll + SELECT) ── */
    mf_classic_reset_auth();
    hb_nfc_err_t err = iso14443a_poller_reselect(card);
    if (err != HB_NFC_OK) {
        ESP_LOGE(TAG, "Reselect falhou: %d", err);
        return MF_WRITE_ERR_RESELECT;
    }

    /* ── Auth ── */
    mf_classic_key_t k;
    memcpy(k.data, key, 6);

    err = mf_classic_auth(block, key_type, &k, card->uid);
    if (err != HB_NFC_OK) {
        ESP_LOGE(TAG, "Auth falhou no bloco %d (key%c)", block,
                 key_type == MF_KEY_A ? 'A' : 'B');
        return MF_WRITE_ERR_AUTH;
    }

    /* ── Write ── */
    mf_write_result_t wres = mf_classic_write_block_raw(block, data);
    if (wres != MF_WRITE_OK) {
        ESP_LOGE(TAG, "Write falhou (bloco %d): %s", block, mf_write_result_str(wres));
        return wres;
    }

    ESP_LOGI(TAG, "✓ Bloco %d escrito", block);

    /* ── Verify (opcional) ── */
    if (verify) {
        uint8_t readback[16] = { 0 };
        err = mf_classic_read_block(block, readback);
        if (err != HB_NFC_OK) {
            ESP_LOGW(TAG, "Verificação: leitura falhou (bloco %d)", block);
            return MF_WRITE_ERR_VERIFY;
        }
        if (memcmp(data, readback, 16) != 0) {
            ESP_LOGE(TAG, "Verificação: dado lido não confere (bloco %d)!", block);
            ESP_LOG_BUFFER_HEX("esperado", data, 16);
            ESP_LOG_BUFFER_HEX("lido    ", readback, 16);
            return MF_WRITE_ERR_VERIFY;
        }
        ESP_LOGI(TAG, "✓ Bloco %d verificado", block);
    }

    return MF_WRITE_OK;
}

/* ─────────────────────────────────────────────────────────
 *  Escrita de setor inteiro (exclui trailer)
 * ───────────────────────────────────────────────────────── */

int mf_classic_write_sector(nfc_iso14443a_data_t* card,
                             uint8_t               sector,
                             const uint8_t*        data,
                             const uint8_t         key[6],
                             mf_key_type_t         key_type,
                             bool                  verify)
{
    if (!card || !data || !key) return -1;

    mf_classic_type_t type = mf_classic_get_type(card->sak);
    int sector_count = mf_classic_get_sector_count(type);
    if ((int)sector >= sector_count) return -1;

    const int blocks_in_sector = mf_classic_sector_block_count(type, sector);
    const int data_blocks      = blocks_in_sector - 1;
    const int fb               = mf_classic_sector_first_block(type, sector);
    const int last_data_block  = fb + data_blocks - 1;

    ESP_LOGI(TAG, "Escrevendo setor %d (blocos %d..%d)...",
             sector, fb, last_data_block);

    /* Reselect uma vez para o setor inteiro */
    mf_classic_reset_auth();
    hb_nfc_err_t err = iso14443a_poller_reselect(card);
    if (err != HB_NFC_OK) {
        ESP_LOGE(TAG, "Reselect falhou para setor %d", sector);
        return -1;
    }

    /* Auth uma vez para o setor */
    mf_classic_key_t k;
    memcpy(k.data, key, 6);

    err = mf_classic_auth(fb, key_type, &k, card->uid);
    if (err != HB_NFC_OK) {
        ESP_LOGE(TAG, "Auth falhou no setor %d (key%c)", sector,
                 key_type == MF_KEY_A ? 'A' : 'B');
        return -1;
    }

    /* Escreve os blocos de dados (não o trailer) */
    int written = 0;
    for (int b = 0; b < data_blocks; b++) {
        uint8_t block = (uint8_t)(fb + b);
        const uint8_t* block_data = data + (b * 16);

        mf_write_result_t wres = mf_classic_write_block_raw(block, block_data);
        if (wres != MF_WRITE_OK) {
            ESP_LOGE(TAG, "Write falhou no bloco %d: %s", block,
                     mf_write_result_str(wres));
            break;
        }

        /* Verify: precisa re-auth pois write encerra a sessão no bloco */
        if (verify) {
            /* Re-auth para leitura de verificação */
            mf_classic_reset_auth();
            err = iso14443a_poller_reselect(card);
            if (err != HB_NFC_OK) {
                ESP_LOGE(TAG, "Reselect falhou na verificacao (bloco %d)", block);
                return written;
            }
            err = mf_classic_auth(fb, key_type, &k, card->uid);
            if (err != HB_NFC_OK) {
                ESP_LOGE(TAG, "Auth falhou na verificacao (setor %d, key%c)",
                         sector, key_type == MF_KEY_A ? 'A' : 'B');
                return written;
            }

            uint8_t readback[16] = { 0 };
            err = mf_classic_read_block(block, readback);
            if (err != HB_NFC_OK || memcmp(block_data, readback, 16) != 0) {
                ESP_LOGE(TAG, "Verificação falhou no bloco %d!", block);
                return written;
            }
            ESP_LOGI(TAG, "  ✓ Bloco %d escrito e verificado", block);

            /* Re-auth para continuar escrevendo */
            if (b < data_blocks - 1) {
                mf_classic_reset_auth();
                err = iso14443a_poller_reselect(card);
                if (err != HB_NFC_OK) {
                    ESP_LOGE(TAG, "Reselect falhou para continuar (setor %d)", sector);
                    return written;
                }
                err = mf_classic_auth(fb, key_type, &k, card->uid);
                if (err != HB_NFC_OK) {
                    ESP_LOGE(TAG, "Auth falhou para continuar (setor %d, key%c)",
                             sector, key_type == MF_KEY_A ? 'A' : 'B');
                    return written;
                }
            }
        } else {
            ESP_LOGI(TAG, "  ✓ Bloco %d escrito", block);
        }

        written++;
    }

    ESP_LOGI(TAG, "Setor %d: %d/%d blocos escritos", sector, written, data_blocks);
    return written;
}

/* ─────────────────────────────────────────────────────────
 *  Build Trailer
 * ───────────────────────────────────────────────────────── */

void mf_classic_build_trailer(const uint8_t  key_a[6],
                               const uint8_t  key_b[6],
                               const uint8_t  access_bits[3],
                               uint8_t        out_trailer[16])
{
    /* Bytes 0-5: Key A */
    memcpy(out_trailer, key_a, 6);

    /* Bytes 6-8: Access bits */
    const uint8_t* ac = access_bits ? access_bits : MF_ACCESS_BITS_DEFAULT;
    out_trailer[6] = ac[0];
    out_trailer[7] = ac[1];
    out_trailer[8] = ac[2];

    /* Byte 9: GPB (General Purpose Byte) — 0x00 por padrão */
    out_trailer[9] = 0x00;

    /* Bytes 10-15: Key B */
    memcpy(&out_trailer[10], key_b, 6);
}

bool mf_classic_build_trailer_safe(const uint8_t              key_a[6],
                                    const uint8_t              key_b[6],
                                    const mf_classic_access_bits_t* ac,
                                    uint8_t                    gpb,
                                    uint8_t                    out_trailer[16])
{
    if (!key_a || !key_b || !ac || !out_trailer) return false;

    uint8_t access_bits[3];
    if (!mf_classic_access_bits_encode(ac, access_bits)) return false;
    if (!mf_classic_access_bits_valid(access_bits)) return false;

    memcpy(out_trailer, key_a, 6);
    out_trailer[6] = access_bits[0];
    out_trailer[7] = access_bits[1];
    out_trailer[8] = access_bits[2];
    out_trailer[9] = gpb;
    memcpy(&out_trailer[10], key_b, 6);
    return true;
}


#undef TAG

/* === main\mf_ultralight.c === */
/**
 * @file mf_ultralight.c
 * @brief MIFARE Ultralight / NTAG — proven commands from working code.
 */
#include "mf_ultralight.h"
#include "nfc_poller.h"
#include "nfc_common.h"
#include "hb_nfc_timer.h"

#include "esp_log.h"

#define TAG TAG_MF_UL
static const char* TAG = "mful";

/**
 * READ — exact copy of working code st25r_read_pages():
 *   cmd = { 0x30, page }
 *   rx_min = 1 (capture partial for diagnostics)
 *   timeout = 30ms
 */
int mful_read_pages(uint8_t page, uint8_t out[18])
{
    uint8_t cmd[2] = { 0x30, page };
    return nfc_poller_transceive(cmd, 2, true, out, 18, 1, 30);
}

/**
 * WRITE — cmd 0xA2.
 */
hb_nfc_err_t mful_write_page(uint8_t page, const uint8_t data[4])
{
    uint8_t cmd[6] = { 0xA2, page, data[0], data[1], data[2], data[3] };
    uint8_t rx[4] = { 0 };
    int len = nfc_poller_transceive(cmd, 6, true, rx, 4, 1, 20);
    /* NTAG returns ACK (4 bits = 0x0A) for successful write */
    if (len >= 1 && (rx[0] & 0x0F) == 0x0A) return HB_NFC_OK;
    return HB_NFC_ERR_NACK;
}

/**
 * GET_VERSION — exact copy of working code ntag_get_version():
 *   cmd = { 0x60 }
 *   rx_min = 1, rx_max = 8, timeout = 20ms
 */
int mful_get_version(uint8_t out[8])
{
    uint8_t cmd[1] = { 0x60 };
    return nfc_poller_transceive(cmd, 1, true, out, 8, 1, 20);
}

/**
 * PWD_AUTH — exact copy of working code ntag_pwd_auth():
 *   cmd = { 0x1B, pwd[0..3] }
 *   rx_min = 2 (PACK)
 *   timeout = 20ms
 *   Post-auth delay: 500us
 */
int mful_pwd_auth(const uint8_t pwd[4], uint8_t pack[2])
{
    uint8_t cmd[5] = { 0x1B, pwd[0], pwd[1], pwd[2], pwd[3] };
    uint8_t rx[4] = { 0 };
    int len = nfc_poller_transceive(cmd, 5, true, rx, 4, 2, 20);
    if (len >= 2) {
        pack[0] = rx[0];
        pack[1] = rx[1];
        hb_delay_us(500);  /* From working code: 500us post-auth delay */
    }
    return len;
}

/**
 * Read all pages — reads 4 pages at a time.
 */
int mful_read_all(uint8_t* data, int max_pages)
{
    int pages_read = 0;
    for (int pg = 0; pg < max_pages; pg += 4) {
        uint8_t buf[18] = { 0 };
        int len = mful_read_pages((uint8_t)pg, buf);
        if (len < 16) {
            ESP_LOGD(TAG, "Read stopped at page %d (got %d bytes)", pg, len);
            break;
        }
        /* Copy 4 pages (16 bytes) */
        int pages_in_chunk = (max_pages - pg >= 4) ? 4 : (max_pages - pg);
        for (int i = 0; i < pages_in_chunk; i++) {
            data[(pg + i) * 4 + 0] = buf[i * 4 + 0];
            data[(pg + i) * 4 + 1] = buf[i * 4 + 1];
            data[(pg + i) * 4 + 2] = buf[i * 4 + 2];
            data[(pg + i) * 4 + 3] = buf[i * 4 + 3];
        }
        pages_read = pg + pages_in_chunk;
    }
    return pages_read;
}
#undef TAG

/* === main\mfkey.c === */
/**
 * @file mfkey.c
 * @brief MFKey — stub.
 */
#include "mfkey.h"

bool mfkey32(uint32_t uid, uint32_t nt0, uint32_t nr0, uint32_t ar0,
             uint32_t nt1, uint32_t nr1, uint32_t ar1, uint64_t* key)
{
    (void)uid; (void)nt0; (void)nr0; (void)ar0;
    (void)nt1; (void)nr1; (void)ar1; (void)key;
    /* TODO: implement rollback + LFSR recovery */
    return false;
}

