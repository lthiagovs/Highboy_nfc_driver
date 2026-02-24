/**
 * @file mf_classic_writer.h
 * @brief MIFARE Classic — escrita de blocos com autenticação Crypto1.
 *
 * Fluxo para escrita num bloco de dados:
 *   1. Reselect (field cycle + REQA + anticoll + SELECT)
 *   2. Auth (Crypto1, Key A ou B)
 *   3. WRITE cmd (0xA0 + block) → espera ACK (0x0A)
 *   4. Envia 16 bytes de dados → espera ACK (0x0A)
 *
 * ATENÇÃO: Nunca escreva no bloco 0 (manufacturer) e tenha
 * cuidado extremo com trailers — access bits errados bloqueiam
 * o setor permanentemente.
 */
#ifndef MF_CLASSIC_WRITER_H
#define MF_CLASSIC_WRITER_H

#include <stdint.h>
#include <stdbool.h>
#include "highboy_nfc_types.h"
#include "highboy_nfc_error.h"
#include "mf_classic.h"

/* ── Resultado de uma operação de escrita ── */
typedef enum {
    MF_WRITE_OK           = 0,
    MF_WRITE_ERR_RESELECT,   /* Falhou ao re-selecionar o cartão */
    MF_WRITE_ERR_AUTH,       /* Autenticação negada */
    MF_WRITE_ERR_CMD_NACK,   /* Cartão recusou o comando WRITE */
    MF_WRITE_ERR_DATA_NACK,  /* Cartão recusou os dados */
    MF_WRITE_ERR_VERIFY,     /* Dado lido após escrita não confere */
    MF_WRITE_ERR_PROTECTED,  /* Bloco protegido (bloco 0 ou trailer) */
    MF_WRITE_ERR_PARAM,      /* Parâmetro inválido */
} mf_write_result_t;

/* Retorna string legível do resultado */
const char* mf_write_result_str(mf_write_result_t r);

/**
 * @brief Escreve 16 bytes num bloco já autenticado (sessão ativa).
 *
 * Chame esta função IMEDIATAMENTE após mf_classic_auth() —
 * a sessão Crypto1 deve estar ativa.
 *
 * @param block  Número absoluto do bloco (0–63 para 1K).
 * @param data   16 bytes a escrever.
 * @return MF_WRITE_OK ou código de erro.
 */
mf_write_result_t mf_classic_write_block_raw(uint8_t block,
                                               const uint8_t data[16]);

/**
 * @brief Autentica e escreve num bloco de dados (fluxo completo).
 *
 * Faz reselect → auth → write → verify (opcional).
 * Recusa blocos 0 e trailers automaticamente a menos que
 * allow_special seja true.
 *
 * @param card          Dados do cartão (UID necessário para auth).
 * @param block         Bloco absoluto a escrever.
 * @param data          16 bytes a escrever.
 * @param key           Chave de 6 bytes.
 * @param key_type      MF_KEY_A ou MF_KEY_B.
 * @param verify        Se true, lê o bloco após escrita para confirmar.
 * @param allow_special Se true, permite escrever em trailers (perigoso!).
 * @return mf_write_result_t
 */
mf_write_result_t mf_classic_write(nfc_iso14443a_data_t* card,
                                    uint8_t               block,
                                    const uint8_t         data[16],
                                    const uint8_t         key[6],
                                    mf_key_type_t         key_type,
                                    bool                  verify,
                                    bool                  allow_special);

/**
 * @brief Escreve um setor inteiro (blocos de dados, exclui trailer).
 *
 * Itera pelos blocos de dados do setor (não escreve no trailer).
 * Faz apenas UM reselect + auth por setor (eficiente).
 *
 * @param card      Dados do cartão.
 * @param sector    Número do setor (0–15 para 1K).
 * @param data      Buffer com (blocks_in_sector - 1) * 16 bytes.
 *                  Para 1K: 3 blocos × 16 = 48 bytes por setor.
 * @param key       Chave de 6 bytes.
 * @param key_type  MF_KEY_A ou MF_KEY_B.
 * @param verify    Verifica cada bloco após escrita.
 * @return Número de blocos escritos com sucesso, ou negativo em erro fatal.
 */
int mf_classic_write_sector(nfc_iso14443a_data_t* card,
                             uint8_t               sector,
                             const uint8_t*        data,
                             const uint8_t         key[6],
                             mf_key_type_t         key_type,
                             bool                  verify);

/**
 * @brief Gera um trailer válido a partir de chaves e access bits.
 *
 * Calcula os bytes de paridade automaticamente.
 * Access bits padrão seguros: FF 07 80 (todos os blocos leitura/escrita
 * por Key A e B, trailer protegido por Key B).
 *
 * @param key_a       6 bytes da Key A.
 * @param key_b       6 bytes da Key B.
 * @param access_bits 3 bytes de access bits (bytes 6, 7, 8 do trailer).
 *                    Passe NULL para usar os bits padrão seguros.
 * @param out_trailer Buffer de 16 bytes de saída.
 */
void mf_classic_build_trailer(const uint8_t  key_a[6],
                               const uint8_t  key_b[6],
                               const uint8_t  access_bits[3],
                               uint8_t        out_trailer[16]);

/* ── Access bits padrão seguros (FF 07 80) ──
 * Blk 0-2: rd:AB  wr:AB  inc:AB  dec:AB  (C000)
 * Trailer: KeyA:wr_B  AC:rd_AB/wr_B  KeyB:wr_B  (C011)
 */
extern const uint8_t MF_ACCESS_BITS_DEFAULT[3];

/* ── Access bits somente leitura ──
 * Blk 0-2: rd:AB  wr:--  inc:--  dec:--  (C100)
 * Trailer: KeyA:--  AC:rd_AB  KeyB:--  (C110)
 */
extern const uint8_t MF_ACCESS_BITS_READ_ONLY[3];

#endif /* MF_CLASSIC_WRITER_H */
