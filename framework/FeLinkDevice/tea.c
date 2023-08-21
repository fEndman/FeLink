#include "tea.h"

#define MX (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^ ((sum ^ y) + (key[(p & 3) ^ e] ^ z))
#define DELTA 0x9e3779b9

flresult fl_xxtea_encrypt(flu32 *plaintext, fluint dword_len, flu32 *key)
{
    flu32 *buf = plaintext;
    fluint n = dword_len - 1, p, q = 6 + 52 / (n + 1);
    flu32 z, y, sum = 0, e;

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

flresult fl_xxtea_decrypt(flu32 *ciphetext, fluint dword_len, flu32 *key)
{
    flu32 *buf = ciphetext;
    fluint n = dword_len - 1, p, q = 6 + 52 / (n + 1);
    flu32 z, y, sum = q * DELTA, e;

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
void fl_endian_convert(flu32 *buf, fluint len);
#endif
flresult fl_xxtea_byte_array_encrypt(flu8 *plaintext, fluint byte_len, flu32 *key)
{
    flresult res;
    fluint dword_len;

    if (byte_len % 4 != 0)
        return RES_ERR;
#if FELINK_ARCH != FELINK_C51
    if (((int)(flu32 *)plaintext & 0x3) != 0)
        return RES_ERR;
#endif

    dword_len = byte_len / 4;
#ifdef FELINK_BIG_ENDIAN
    fl_endian_convert((flu32 *)plaintext, dword_len);
#endif
    res = fl_xxtea_encrypt((flu32 *)plaintext, dword_len, key);
#ifdef FELINK_BIG_ENDIAN
    fl_endian_convert((flu32 *)plaintext, dword_len);
#endif

    return res;
}

flresult fl_xxtea_byte_array_decrypt(flu8 *ciphetext, fluint byte_len, flu32 *key)
{
    flresult res;
    fluint dword_len;

    if (byte_len % 4 != 0)
        return RES_ERR;
#if FELINK_ARCH != FELINK_C51
    if (((int)(flu32 *)ciphetext & 0x3) != 0)
        return RES_ERR;
#endif

    dword_len = byte_len / 4;
#ifdef FELINK_BIG_ENDIAN
    fl_endian_convert((flu32 *)ciphetext, dword_len);
#endif
    res = fl_xxtea_decrypt((flu32 *)ciphetext, dword_len, key);
#ifdef FELINK_BIG_ENDIAN
    fl_endian_convert((flu32 *)ciphetext, dword_len);
#endif

    return res;
}
