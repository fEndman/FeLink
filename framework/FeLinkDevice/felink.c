#include "felink.h"
#include "userio.h"
#include "tea.h"

#define FELINK_SIGN 0xFE

#define FELINK_PCMD 0xAA
#define FELINK_CCMD 0xCC
#define FELINK_DCMD 0xDD

#define FELINK_PCMD_BASE_SEARCH 0xAA
#define FELINK_PCMD_DEV_HANDSHAKE 0xBA
#define FELINK_PCMD_BASE_PAIR 0xAB
#define FELINK_PCMD_DEV_PAIR 0xBB
#define FELINK_PCMD_BASE_ID_INVALID 0xAE
#define FELINK_PCMD_DEV_ID_CHANGE 0xBE

#define FELINK_CCMD_DEV_ACK 0xBA
#define FELINK_CCMD_BASE_CONNECT 0xAC

#define FELINK_DCMD_DATA 0xAD

FLU16 fl_rd16(const FLU8 *p)
{
    FLU16 rv;
    rv = p[1];
    rv = rv << 8 | p[0];
    return rv;
}

FLU32 fl_rd32(const FLU8 *p)
{
    FLU32 rv;
    rv = p[3];
    rv = rv << 8 | p[2];
    rv = rv << 8 | p[1];
    rv = rv << 8 | p[0];
    return rv;
}

void fl_wr16(FLU8 *p, FLU16 val)
{
    *p++ = (FLU8)val;
    val >>= 8;
    *p++ = (FLU8)val;
}

void fl_wr32(FLU8 *p, FLU32 val)
{
    *p++ = (FLU8)val;
    val >>= 8;
    *p++ = (FLU8)val;
    val >>= 8;
    *p++ = (FLU8)val;
    val >>= 8;
    *p++ = (FLU8)val;
}

FLU8 fl_chksum8(const FLU8 *bytes, FLUINT len)
{
    FLU8 chksum8 = 0;
    while (len--)
        chksum8 += *(bytes++);
    return ~chksum8;
}

void fl_memcpy(void *dst, const void *src, FLUINT size)
{
    FLU8 *d = (FLU8 *)dst;
    const FLU8 *s = (const FLU8 *)src;
    if (dst < src)
    {
        while (size--)
            *d++ = *s++;
    }
    else
    {
        d += size;
        s += size;
        while (size--)
            *--d = *--s;
    }
}

void fl_strcpy(void *dst, const char *src)
{
    char *dest = (char *)dst;
    do
    {
        *dest++ = *src;
    } while (*src++ != '\0');
}

FLUINT fl_strlen(const char *str)
{
    FLUINT l = 0;
    while (str[l] != '\0')
        l++;
    return l;
}

int fl_rng(uint8_t *dest, unsigned size) FELINK_C51_REENTRANT
{
    return fl_random(dest, size) == RES_OK ? 1 : 0;
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

static void fl_get_key(
    struct fldev *dev,
    FLU32 *key)
{
    FLU8 *key_le = (FLU8 *)key;
    const FLU8 *keys = dev->sav.tea_key;
    FLU32 ev = dev->salt;
    FLU32 ev_rev = ~ev;
    FLU32 ev_m2 = ev + ev;
    FLU32 ev_rev_m2 = ev_rev + ev_rev;
    FLUINT i;

    for (i = 0; i < 16; i += 4)
    {
        key_le[i] = keys[ev & 0xF];
        key_le[i + 1] = keys[ev_rev & 0xF];
        key_le[i + 2] = keys[ev_m2 & 0xF];
        key_le[i + 3] = keys[ev_rev_m2 & 0xF];
        ev >>= 4;
        ev_rev >>= 4;
        ev_m2 >>= 4;
        ev_rev_m2 >>= 4;
    }

#ifdef FELINK_BIG_ENDIAN
    fl_endian_convert(key, 4)
#endif
}

static FLRESULT fl_pcmd_dev_handshake(
    struct fldev *dev)
{
    FLUINT len = 14 + fl_strlen(dev->sav.name) + 1;
    FLRESULT res;

    if (len > FELINK_BUF_SIZE)
        return RES_ERR_NOMEM;

    dev->valid_data_len = 0;
    dev->buf[0] = FELINK_SIGN;
    dev->buf[1] = 0;
    dev->buf[2] = FELINK_PCMD;
    dev->buf[3] = FELINK_PCMD_DEV_HANDSHAKE;
    fl_wr32(&dev->buf[4], dev->id);
    fl_wr32(&dev->buf[8], dev->type);
    fl_wr16(&dev->buf[12], FELINK_DEV_VERSION);
    fl_strcpy(&dev->buf[14], dev->sav.name);
    dev->buf[1] = fl_chksum8(dev->buf, len);

    res = fl_transmit(dev, dev->buf, len);
    if (res)
        return res;
    dev->state = STATE_HANDSHAKED;

    return RES_OK;
}

static FLRESULT fl_pcmd_dev_pair(
    struct fldev *dev,
    const FLU8 *bytes,
    FLUINT count)
{
#if FELINK_ARCH == FELINK_C51
    volatile struct fldev *dev_temp = dev;
#endif
    FLU8 keylen = bytes[8];
    FLRESULT res;

    if (keylen != uECC_BYTES * 2)
        return RES_ERR_ECC_UNSUPPORT;

    if (count < 9 + keylen)
        return RES_ERR_TRANSMIT;

    dev->valid_data_len = 0;
    uECC_shared_secret(
        (uint8_t *)&bytes[9],
        (uint8_t *)dev->sav.ecdh_pri_key,
        dev->buf);
#if FELINK_ARCH == FELINK_C51
    dev = dev_temp;
#endif
    fl_save(dev, dev->buf, uECC_BYTES, SAVE_TEA_KEY);

    dev->buf[0] = FELINK_SIGN;
    dev->buf[1] = 0;
    dev->buf[2] = FELINK_PCMD;
    dev->buf[3] = FELINK_PCMD_DEV_PAIR;
    fl_wr32(&dev->buf[4], dev->id);
    keylen = uECC_BYTES * 2;
    dev->buf[8] = keylen;
    fl_memcpy(&dev->buf[9], dev->sav.ecdh_pub_key, keylen);
    dev->buf[1] = fl_chksum8(dev->buf, 9 + keylen);

    res = fl_transmit(dev, dev->buf, 9 + keylen);
    if (res)
        return res;
    dev->state = STATE_PAIRED;

    return RES_OK;
}

static FLRESULT fl_pcmd_dev_id_change(
    struct fldev *dev,
    const FLU8 *bytes,
    FLUINT count)
{
    FLU32 nid = fl_rd32(&bytes[8]);
    FLUINT len = 18 + fl_strlen(dev->sav.name) + 1;
    FLRESULT res;

    if (count < 12)
        return RES_ERR;
    if (len > FELINK_BUF_SIZE)
        return RES_ERR_NOMEM;

    dev->valid_data_len = 0;
    dev->buf[0] = FELINK_SIGN;
    dev->buf[1] = 0;
    dev->buf[2] = FELINK_PCMD;
    dev->buf[3] = FELINK_PCMD_DEV_ID_CHANGE;
    fl_wr32(&dev->buf[4], nid);
    fl_wr32(&dev->buf[8], dev->id);
    dev->id = nid;
    fl_wr32(&dev->buf[12], dev->type);
    fl_wr16(&dev->buf[16], FELINK_DEV_VERSION);
    fl_strcpy(&dev->buf[18], dev->sav.name);
    dev->buf[1] = fl_chksum8(dev->buf, len);

    res = fl_transmit(dev, dev->buf, len);
    if (res)
        return res;

    return fl_save(dev, &bytes[6], 4, SAVE_ID);
}

static FLRESULT fl_ccmd_dev_ack(
    struct fldev *dev,
    FLU8 ack_sign)
{
    FLU8 buf[9];
    buf[0] = FELINK_SIGN;
    buf[1] = 0;
    buf[2] = FELINK_CCMD;
    buf[3] = FELINK_CCMD_DEV_ACK;
    fl_wr32(&buf[4], dev->id);
    buf[8] = ack_sign;
    buf[1] = fl_chksum8(buf, 9);
    return fl_transmit(dev, buf, 9);
}

static FLRESULT fl_ccmd_base_connect_handler(
    struct fldev *dev,
    const FLU8 *bytes,
    FLUINT count)
{
    FLU8 ack_chksum8;
    FLU32 key[4];
    FLRESULT res;

    if (count < 16)
        return RES_ERR_TRANSMIT;

    dev->valid_data_len = 0;
    fl_memcpy(dev->buf, &bytes[8], 8);
    ack_chksum8 = fl_chksum8(dev->buf, 8);

    dev->salt = 0x76543210;
    fl_get_key(dev, key);
    res = fl_xxtea_byte_array_decrypt(dev->buf, 8, key);
    if (res)
        return res;

    if (fl_chksum8(dev->buf, 8) != 0)
        return RES_ERR_CRYPT;

    res = fl_ccmd_dev_ack(dev, ack_chksum8);
    if (res)
        return res;
    dev->salt = fl_rd32(&dev->buf[0]);
    dev->state = STATE_CONNECTED;

    return RES_OK;
}

static FLRESULT fl_dcmd_data_handler(
    struct fldev *dev,
    const FLU8 *bytes,
    FLUINT count)
{
    FLU8 ack_chksum8;
    FLS32 l = (FLS32)fl_rd32(&bytes[8]);
    FLU32 n;
    FLU32 key[4];
    FLRESULT res;
    char is_plaintext_transmit = 0;

    if (l < 0)
    {
        is_plaintext_transmit = 1;
        l = -l;
    }

    if (count < 12 + l)
        return RES_ERR_TRANSMIT;
    if (l > FELINK_BUF_SIZE)
        return RES_ERR_NOMEM;

    dev->valid_data_len = 0;
    fl_memcpy(dev->buf, &bytes[12], l);
    ack_chksum8 = fl_chksum8(dev->buf, l);

    if (!is_plaintext_transmit)
    {
        fl_get_key(dev, key);
        res = fl_xxtea_byte_array_decrypt(dev->buf, l, key);
        if (res)
            return res;
    }

    if (fl_chksum8(dev->buf, l) != 0)
        return RES_ERR_CRYPT;

    n = fl_rd16(&dev->buf[0]);
    n += 1;
    if (n > l - 6)
        return RES_ERR_TRANSMIT;

    res = fl_ccmd_dev_ack(dev, ack_chksum8);
    if (res)
        return res;

    if (!is_plaintext_transmit)
        dev->salt = fl_rd32(&dev->buf[2]);

    fl_memcpy(dev->buf, &dev->buf[6], n);
    dev->valid_data_len = n;

    return RES_DATA_AVAILABLE;
}

static FLRESULT fl_pcmd_handler(
    struct fldev *dev,
    const FLU8 *bytes,
    FLUINT count)
{
    FLU8 minor_cmd = bytes[3];
    FLU32 id = fl_rd32(&bytes[4]);

    switch (minor_cmd)
    {
    case FELINK_PCMD_BASE_SEARCH:
//        if (dev->state == STATE_PAIRED || dev->state == STATE_CONNECTED)
//            break;
		    dev->state = STATE_UNPAIRED;
        return fl_pcmd_dev_handshake(dev);
    case FELINK_PCMD_BASE_PAIR:
        if (dev->id != id || dev->state != STATE_HANDSHAKED)
            break;
        return fl_pcmd_dev_pair(dev, bytes, count);
    case FELINK_PCMD_BASE_ID_INVALID:
        if (dev->id != id || dev->state != STATE_HANDSHAKED)
            break;
        return fl_pcmd_dev_id_change(dev, bytes, count);
    case FELINK_PCMD_DEV_HANDSHAKE:
    case FELINK_PCMD_DEV_PAIR:
    case FELINK_PCMD_DEV_ID_CHANGE:
        break;
    default:
        return RES_ERR_CMD_INVALID;
    }

    return RES_OK;
}

static FLRESULT fl_ccmd_handler(
    struct fldev *dev,
    const FLU8 *bytes,
    FLUINT count)
{
    FLU8 minor_cmd = bytes[3];
    FLU32 id = fl_rd32(&bytes[4]);

    switch (minor_cmd)
    {
    case FELINK_CCMD_BASE_CONNECT:
        if (dev->id != id || dev->state == STATE_UNPAIRED || dev->state == STATE_HANDSHAKED)
            break;
        return fl_ccmd_base_connect_handler(dev, bytes, count);
    case FELINK_CCMD_DEV_ACK:
        break;
    default:
        return RES_ERR_CMD_INVALID;
    }

    return RES_OK;
}

static FLRESULT fl_dcmd_handler(
    struct fldev *dev,
    const FLU8 *bytes,
    FLUINT count)
{
    FLU8 minor_cmd = bytes[3];
    FLU32 id = fl_rd32(&bytes[4]);

    switch (minor_cmd)
    {
    case FELINK_DCMD_DATA:
        if (dev->id != id || dev->state != STATE_CONNECTED)
            break;
        return fl_dcmd_data_handler(dev, bytes, count);
    default:
        return RES_ERR_CMD_INVALID;
    }

    return RES_OK;
}

FLRESULT fl_receive_handler(
    struct fldev *dev,
    const FLU8 *bytes,
    FLUINT count)
{
    FLU8 major_cmd = bytes[2];
    FLU8 minor_cmd = bytes[3];

    if (bytes[0] != FELINK_SIGN)
        return RES_ERR_CMD_INVALID;

    if (count < 4)
        return RES_ERR_TRANSMIT;
    if (minor_cmd != FELINK_PCMD_BASE_SEARCH)
        if (count < 8)
            return RES_ERR_TRANSMIT;

    if (fl_chksum8(bytes, count) != 0)
        return RES_ERR_CHKSUM;

    switch (major_cmd)
    {
    case FELINK_PCMD:
        return fl_pcmd_handler(dev, bytes, count);
    case FELINK_CCMD:
        return fl_ccmd_handler(dev, bytes, count);
    case FELINK_DCMD:
        return fl_dcmd_handler(dev, bytes, count);
    default:
        return RES_ERR_CMD_INVALID;
    }
}

FLRESULT fl_init(
    struct fldev *dev)
{
    FLRESULT res;

    uECC_set_rng(&fl_rng);

    dev->state = STATE_UNPAIRED;
    res = fl_reload(dev);
    if (res)
        return res;
    if (dev->id == 0)
        return RES_ERR;
    dev->salt = 0;
    dev->valid_data_len = 0;

    return RES_OK;
}
