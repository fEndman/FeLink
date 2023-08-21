#include "tea.h"

#define MX (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^ ((sum ^ y) + (key[(p & 3) ^ e] ^ z))
#define DELTA 0x9e3779b9

FLRESULT fl_xxtea_encrypt(FLU32 *plaintext, FLUINT dword_len, FLU32 *key)
{
    FLU32 *buf = plaintext;
    FLUINT n = dword_len - 1, p, q = 6 + 52 / (n + 1);
    FLU32 z, y, sum = 0, e;

    if (n < 1)
        return RES_ERR;

    z = buf[n];
    while (0 < q--)
    {
        sum += DELTA;
        e = sum >> 2 & 3;

        for (p = 0; p < n; p++)
        {
            y = buf[p + 1];
            z = buf[p] += MX;
        }

        y = buf[0];
        z = buf[n] += MX;
    }

    return RES_OK;
}

FLRESULT fl_xxtea_decrypt(FLU32 *ciphetext, FLUINT dword_len, FLU32 *key)
{
    FLU32 *buf = ciphetext;
    FLUINT n = dword_len - 1, p, q = 6 + 52 / (n + 1);
    FLU32 z, y, sum = q * DELTA, e;

    if (n < 1)
        return RES_ERR;

    y = buf[0];
    while (sum != 0)
    {
        e = sum >> 2 & 3;

        for (p = n; p > 0; p--)
        {
            z = buf[p - 1];
            y = buf[p] -= MX;
        }

        z = buf[n];
        y = buf[0] -= MX;
        sum -= DELTA;
    }

    return RES_OK;
}

#ifdef FELINK_BIG_ENDIAN
void fl_endian_convert(FLU32 *buf, FLUINT len)
{
    FLU32 temp;
    while (len--)
    {
        temp = *buf;
        *buf = ((temp & 0x000000FF) << 24) |
               ((temp & 0x0000FF00) << 8) |
               ((temp & 0x00FF0000) >> 8) |
               ((temp & 0xFF000000) >> 24);
        buf++;
    }
}
#endif

FLRESULT fl_xxtea_byte_array_encrypt(FLU8 *plaintext, FLUINT byte_len, FLU32 *key)
{
    FLRESULT res;
    FLUINT dword_len;

    if (byte_len % 4 != 0)
        return RES_ERR;
#if FELINK_ARCH != FELINK_C51
    if (((int)(FLU32 *)plaintext & 0x3) != 0)
        return RES_ERR;
#endif

    dword_len = byte_len / 4;
#ifdef FELINK_BIG_ENDIAN
    fl_endian_convert((FLU32 *)plaintext, dword_len);
#endif
    res = fl_xxtea_encrypt((FLU32 *)plaintext, dword_len, key);
#ifdef FELINK_BIG_ENDIAN
    fl_endian_convert((FLU32 *)plaintext, dword_len);
#endif

    return res;
}

FLRESULT fl_xxtea_byte_array_decrypt(FLU8 *ciphetext, FLUINT byte_len, FLU32 *key)
{
    FLRESULT res;
    FLUINT dword_len;

    if (byte_len % 4 != 0)
        return RES_ERR;
#if FELINK_ARCH != FELINK_C51
    if (((int)(FLU32 *)ciphetext & 0x3) != 0)
        return RES_ERR;
#endif

    dword_len = byte_len / 4;
#ifdef FELINK_BIG_ENDIAN
    fl_endian_convert((FLU32 *)ciphetext, dword_len);
#endif
    res = fl_xxtea_decrypt((FLU32 *)ciphetext, dword_len, key);
#ifdef FELINK_BIG_ENDIAN
    fl_endian_convert((FLU32 *)ciphetext, dword_len);
#endif

    return res;
}
