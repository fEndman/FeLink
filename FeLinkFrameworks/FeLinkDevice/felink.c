#include "felink.h"
#include "userio.h"
#include "tea.h"

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

static FLU16 fl_rd16(const FLU8 *p)
{
    FLU16 rv;
    rv = p[1];
    rv = rv << 8 | p[0];
    return rv;
}

static FLU32 fl_rd32(const FLU8 *p)
{
    FLU32 rv;
    rv = p[3];
    rv = rv << 8 | p[2];
    rv = rv << 8 | p[1];
    rv = rv << 8 | p[0];
    return rv;
}

static void fl_wr16(FLU8 *p, FLU16 val)
{
    *p++ = (FLU8)val;
    val >>= 8;
    *p++ = (FLU8)val;
}

static void fl_wr32(FLU8 *p, FLU32 val)
{
    *p++ = (FLU8)val;
    val >>= 8;
    *p++ = (FLU8)val;
    val >>= 8;
    *p++ = (FLU8)val;
    val >>= 8;
    *p++ = (FLU8)val;
}

static FLU8 fl_chksum8(const FLU8 *bytes, FLUINT len)
{
    FLU8 chksum8 = 0;
    while (len)
        chksum8 += bytes[--len];
    return chksum8;
}

static void fl_memcpy(void *dst, const void *src, FLUINT size)
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

static void fl_strcpy(void *dst, const char *src)
{
    char *dest = (char *)dst;
    do
    {
        *dest++ = *src;
    } while (*src++ != '\0');
}

static FLUINT fl_strlen(const char *str)
{
    FLUINT l = 0;
    while (str[l] != '\0')
        l++;
    return l;
}

static int fl_rng(uint8_t *dest, unsigned size) FELINK_C51_REENTRANT
{
    return fl_random(dest, size) == RES_OK ? 1 : 0;
}

static void fl_get_key(
    struct fldev *dev,
    FLU32 *key)
{
    const FLU8 *keys = dev->sav.tea_key;
    FLU32 ev = dev->eigenval;
    FLUINT cs_s4 = uECC_BYTES - 4;

    key[0] = fl_rd32(&keys[(uint8_t)(ev >> 0) % cs_s4]);
    key[1] = fl_rd32(&keys[(uint8_t)(ev >> 8) % cs_s4]);
    key[2] = fl_rd32(&keys[(uint8_t)(ev >> 16) % cs_s4]);
    key[3] = fl_rd32(&keys[(uint8_t)(ev >> 24) % cs_s4]);
}

static FLRESULT fl_pcmd_dev_handshake(
    struct fldev *dev)
{
    FLUINT len = 8 + fl_strlen(dev->sav.name) + 1;
    FLRESULT res;

    if (len > FELINK_BUF_SIZE)
        return RES_ERR_NOMEM;

    dev->buf[0] = FELINK_PCMD;
    dev->buf[1] = FELINK_PCMD_DEV_HANDSHAKE;
    fl_wr32(&dev->buf[2], dev->id);
    fl_wr16(&dev->buf[6], dev->type);
    fl_strcpy(&dev->buf[8], dev->sav.name);

    res = fl_transmit(dev, dev->buf, len);
    if (res)
        return res;
    dev->phase = HANDSHAKED;

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
    FLU8 keylen = bytes[6];
    FLU8 chksum8 = bytes[7];
    FLRESULT res;

    if (keylen != uECC_BYTES * 2)
        return RES_ERR_ECC_UNSUPPORT;

    if (count != 8 + keylen)
        return RES_ERR;

    if (fl_chksum8(&bytes[8], keylen) != chksum8)
        return RES_ERR_CHKSUM;
    uECC_shared_secret(
        (uint8_t *)&bytes[8],
        (uint8_t *)dev->sav.ecdh_pri_key,
        dev->buf);
#if FELINK_ARCH == FELINK_C51
    dev = dev_temp;
#endif
    fl_save(dev, dev->buf, uECC_BYTES, TEA_KEY);

    dev->buf[0] = FELINK_PCMD;
    dev->buf[1] = FELINK_PCMD_DEV_PAIR;
    fl_wr32(&dev->buf[2], dev->id);
    keylen = uECC_BYTES * 2;
    dev->buf[6] = keylen;
    dev->buf[7] = fl_chksum8(dev->sav.ecdh_pub_key, keylen);
    fl_memcpy(&dev->buf[8], dev->sav.ecdh_pub_key, keylen);

    res = fl_transmit(dev, dev->buf, 8 + keylen);
    if (res)
        return res;
    dev->phase = PAIRED;

    return RES_OK;
}

static FLRESULT fl_pcmd_dev_id_change(
    struct fldev *dev,
    const FLU8 *bytes,
    FLUINT count)
{
    FLU32 nid = fl_rd32(&bytes[6]);
    FLUINT len = 12 + fl_strlen(dev->sav.name) + 1;
    FLRESULT res;

    if (count < 10)
        return RES_ERR;
    if (len > FELINK_BUF_SIZE)
        return RES_ERR_NOMEM;

    dev->buf[0] = FELINK_PCMD;
    dev->buf[1] = FELINK_PCMD_DEV_ID_CHANGE;
    fl_wr32(&dev->buf[2], nid);
    fl_wr32(&dev->buf[6], dev->id);
    dev->id = nid;
    fl_wr16(&dev->buf[10], dev->type);
    fl_strcpy(&dev->buf[12], dev->sav.name);

    res = fl_transmit(dev, dev->buf, len);
    if (res)
        return res;

    return fl_save(dev, &bytes[6], 4, ID);
}

static FLRESULT fl_ccmd_dev_ack(
    struct fldev *dev,
    const FLU8 *bytes,
    FLUINT count)
{
    FLU8 buf[7];
    buf[0] = FELINK_CCMD;
    buf[1] = FELINK_CCMD_DEV_ACK;
    fl_wr32(&buf[2], dev->id);
    buf[6] = fl_chksum8(bytes, count);
    return fl_transmit(dev, buf, 7);
}

static FLRESULT fl_ccmd_base_connect_handler(
    struct fldev *dev,
    const FLU8 *bytes,
    FLUINT count)
{
    FLU8 chksum8;
    FLU32 key[4];
    FLRESULT res;

    if (count < 14)
        return RES_ERR;

    fl_memcpy(dev->buf, &bytes[6], 8);

    dev->eigenval = 0;
    fl_get_key(dev, key);
    res = fl_xxtea_byte_array_decrypt(dev->buf, 8, key);
    if (res)
        return res;

    chksum8 = dev->buf[0];
    if (chksum8 != fl_chksum8(&dev->buf[1], 7))
        return RES_ERR_CHKSUM;

    res = fl_ccmd_dev_ack(dev, bytes, count);
    if (res)
        return res;
    dev->eigenval = fl_rd32(&dev->buf[0]);
    dev->phase = CONNECTED;

    return RES_OK;
}

static FLRESULT fl_dcmd_data_handler(
    struct fldev *dev,
    const FLU8 *bytes,
    FLUINT count)
{
    FLS16 l = (FLS16)fl_rd16(&bytes[6]);
    FLUINT n;
    FLU8 chksum8;
    FLU32 key[4];
    FLRESULT res;
    char is_plaintext_transmit = 0;

    if (l < 0)
    {
        is_plaintext_transmit = 1;
        l = -l;
    }

    if (count < 8 + l)
        return RES_ERR_TRANSMIT;
    if (l > FELINK_BUF_SIZE)
        return RES_ERR_NOMEM;

    fl_memcpy(dev->buf, &bytes[8], l);

    if (!is_plaintext_transmit)
    {
        fl_get_key(dev, key);
        res = fl_xxtea_byte_array_decrypt(dev->buf, l, key);
        if (res)
            return res;
    }

    n = dev->buf[0] != 0 ? dev->buf[0] : 0x100;
    if (n > l - 4)
        return RES_ERR_TRANSMIT;
    chksum8 = dev->buf[1];
    if (chksum8 != fl_chksum8(&dev->buf[2], l - 2))
        return RES_ERR_CHKSUM;

    res = fl_ccmd_dev_ack(dev, bytes, count);
    if (res)
        return res;
    dev->eigenval = fl_rd32(&dev->buf[0]);

    fl_memcpy(dev->buf, &dev->buf[4], n);
    dev->valid_data_len = n;

    return RES_DATA_VALID;
}

static FLRESULT fl_pcmd_handler(
    struct fldev *dev,
    const FLU8 *bytes,
    FLUINT count)
{
    FLU8 minor_cmd = bytes[1];
    FLU32 id;
    FLU8 v = dev->valid_data_len;

    if (minor_cmd != FELINK_PCMD_BASE_SEARCH)
    {
        if (count < 6)
            return RES_ERR_TRANSMIT;
        id = fl_rd32(&bytes[2]);
    }

    switch (minor_cmd)
    {
    case FELINK_PCMD_BASE_SEARCH:
        if (dev->phase == PAIRED || dev->phase == CONNECTED)
            break;
        if (count < 2)
            return RES_ERR;
        return fl_pcmd_dev_handshake(dev);
    case FELINK_PCMD_BASE_PAIR:
        if (dev->id != id || dev->phase != HANDSHAKED)
            break;
        return fl_pcmd_dev_pair(dev, bytes, count);
    case FELINK_PCMD_BASE_ID_INVALID:
        if (dev->id != id || dev->phase != HANDSHAKED)
            break;
        // 已经完成握手，主机收到了该从机的ID，但ID不可用
        return fl_pcmd_dev_id_change(dev, bytes, count);
    case FELINK_PCMD_DEV_HANDSHAKE:
    case FELINK_PCMD_DEV_PAIR:
    case FELINK_PCMD_DEV_ID_CHANGE:
        return RES_OK;
    default:
        dev->valid_data_len = v;
        return RES_ERR_CMD_INVALID;
    }

    return RES_OK;
}

static FLRESULT fl_ccmd_handler(
    struct fldev *dev,
    const FLU8 *bytes,
    FLUINT count)
{
    FLU8 minor_cmd = bytes[1];
    FLU32 id = fl_rd32(&bytes[2]);
    FLU8 v = dev->valid_data_len;

    switch (minor_cmd)
    {
    case FELINK_CCMD_BASE_CONNECT:
        if (dev->id != id || dev->phase == UNPAIRED || dev->phase == HANDSHAKED)
            break;
        return fl_ccmd_base_connect_handler(dev, bytes, count);
    case FELINK_CCMD_DEV_ACK:
        return RES_OK;
    default:
        dev->valid_data_len = v;
        return RES_ERR_CMD_INVALID;
    }

    return RES_OK;
}

static FLRESULT fl_dcmd_handler(
    struct fldev *dev,
    const FLU8 *bytes,
    FLUINT count)
{
    FLU8 minor_cmd = bytes[1];
    FLU32 id = fl_rd32(&bytes[2]);
    FLU8 v = dev->valid_data_len;

    switch (minor_cmd)
    {
    case FELINK_DCMD_DATA:
        if (dev->id != id || dev->phase != CONNECTED)
            break;
        return fl_dcmd_data_handler(dev, bytes, count);
    default:
        dev->valid_data_len = v;
        return RES_ERR_CMD_INVALID;
    }

    return RES_OK;
}

FLRESULT fl_receive_handler(
    struct fldev *dev,
    const FLU8 *bytes,
    FLUINT count)
{
    FLU8 major_cmd = bytes[0];
    FLU8 v = dev->valid_data_len;

    dev->valid_data_len = 0;
    switch (major_cmd)
    {
    case FELINK_PCMD:
        return fl_pcmd_handler(dev, bytes, count);
    case FELINK_CCMD:
        return fl_ccmd_handler(dev, bytes, count);
    case FELINK_DCMD:
        return fl_dcmd_handler(dev, bytes, count);
    default:
        dev->valid_data_len = v;
        return RES_ERR_CMD_INVALID;
    }
}

FLRESULT fl_init(
    struct fldev *dev)
{
    FLRESULT res;

    uECC_set_rng(&fl_rng);

    dev->phase = UNPAIRED;
    res = fl_reload(dev);
    if (res)
        return res;
    dev->eigenval = 0;
    dev->valid_data_len = 0;

    return RES_OK;
}
