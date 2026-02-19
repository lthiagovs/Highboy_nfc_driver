/**
 * @file iso14443a.c
 * @brief ISO14443A — CRC_A calculation.
 */
#include "iso14443a.h"

void iso14443a_crc(const uint8_t* data, size_t len, uint8_t crc[2])
{
    uint32_t wCrc = 0x6363;
    for (size_t i = 0; i < len; i++) {
        uint8_t bt = data[i];
        bt = (bt ^ (uint8_t)(wCrc & 0x00FF));
        bt = (bt ^ (bt << 4));
        wCrc = (wCrc >> 8) ^
               ((uint32_t)bt << 8) ^
               ((uint32_t)bt << 3) ^
               ((uint32_t)bt >> 4);
    }
    crc[0] = (uint8_t)(wCrc & 0xFF);
    crc[1] = (uint8_t)((wCrc >> 8) & 0xFF);
}

bool iso14443a_check_crc(const uint8_t* data, size_t len)
{
    if (len < 3) return false;
    uint8_t crc[2];
    iso14443a_crc(data, len - 2, crc);
    return (crc[0] == data[len - 2]) && (crc[1] == data[len - 1]);
}
