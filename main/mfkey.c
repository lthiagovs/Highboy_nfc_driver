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
