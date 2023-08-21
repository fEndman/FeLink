#include "userio.h"
#include "uECC.h"

#define UNUSED(x) (x = x)

/* User Code BEGIN */
#include "adc.h"
/* User Code END */
flresult fl_random(
    flu8 *dest,
    fluint size) FELINK_C51_REENTRANT
{
    /* User Code BEGIN */
    uint8_t val;
    uint16_t init, count, i;
    // Use the least-significant bits from the ADC for an unconnected pin (or connected to a source of
    // random noise). This can take a long time to generate random data if the result of analogRead(0)
    // doesn't change very frequently.
    while (size)
    {
        for (i = 0; i < 8; ++i)
        {
            init = Get_ADCResult(14);
            count = 0;
            while (Get_ADCResult(14) == init)
                ++count;

            if (count == 0)
                val = (val << 1) | (init & 0x01);
            else
                val = (val << 1) | (count & 0x01);
        }
        *dest = val;
        ++dest;
        --size;
    }
    /* User Code END */

    return RES_OK;
}

/* User Code BEGIN */
#include "nrf24l01.h"
/* User Code END */
flresult fl_transmit(
    struct fldev *dev,
    const flu8 *bytes,
    fluint count)
{
    /* User Code BEGIN */	
    int res;

    UNUSED(dev);

    res = nrf24l01_tx_felink_package(bytes, count);
    if (res)
        return RES_ERR_TRANSMIT;
    /* User Code END */

    return RES_OK;
}

/* User Code BEGIN */
#include "eeprom.h"

struct
{
    flu8 magic_AAh;
    flu8 chksum8;
    flu32 id;
    flu32 connect_count;
    flu8 is_paired;
    const char *name;
    flu8 pri_key[uECC_BYTES];
    flu8 pub_key[uECC_BYTES * 2];
    flu8 tea_key[uECC_BYTES];
} sav;

flu32 fl_rd32(const flu8 *p);
flu8 fl_chksum8(const flu8 *bytes, fluint len);
void fl_memcpy(void *dst, const void *src, fluint size);
/* User Code END */
flresult fl_save(
    struct fldev *dev,
    const flu8 *bytes,
    fluint count,
    FLSAVETYPE type)
{
    /* User Code BEGIN */
    UNUSED(dev);
    
    switch (type)
    {
    case SAVE_ID:
        sav.id = fl_rd32(bytes);
        break;
    case SAVE_CONNECT_COUNT:
        sav.connect_count = fl_rd32(bytes);
        break;
    case SAVE_ECDH_PRI_KEY:
        sav.is_paired = 0;
        fl_memcpy(sav.pri_key, bytes, count);
        break;
    case SAVE_ECDH_PUB_KEY:
        sav.is_paired = 0;
        fl_memcpy(sav.pub_key, bytes, count);
        break;
    case SAVE_TEA_KEY:
        sav.is_paired = 1;
        fl_memcpy(sav.tea_key, bytes, count);
        break;
    case SAVE_NAME:
    default:
        break;
    }

    sav.chksum8 = 0;
    sav.chksum8 = fl_chksum8((flu8 *)&sav, sizeof(sav));
    EEPROM_SectorErase(0x0000);
    EEPROM_write_n(0x0000, (flu8 *)&sav, sizeof(sav));
    /* User Code END */

    return RES_OK;
}

/* User Code BEGIN */
static flresult create_key(
    struct fldev *dev)
{
    fluint i;
    flresult res;

    res = fl_create_key(dev);
    if (res)
        return res;

    sav.magic_AAh = 0xAA;
    for (i = 0; i < uECC_BYTES * 2 / 4; i++)
        sav.id += fl_rd32(&sav.pub_key[i * 4]);
    sav.connect_count = 0;
    sav.is_paired = 0;
    sav.name = FELINK_DEFAULT_NAME;
		sav.chksum8 = 0;
    sav.chksum8 = fl_chksum8((flu8 *)&sav, sizeof(sav));

    EEPROM_SectorErase(0x0000);
    EEPROM_write_n(0x0000, (flu8 *)&sav, sizeof(sav));
		
    /**** 空调用ramdom函数一次，避免g_rng_function函数指针造成的调用树异常 ****/
    fl_random((flu8 *)0, 0);

    return RES_OK;
}
/* User Code END */
flresult fl_load(
    struct fldev *dev)
{
    /* User Code BEGIN */
    EEPROM_read_n(0x0000, (flu8 *)&sav, sizeof(sav));

    if (sav.magic_AAh != 0xAA || fl_chksum8((flu8 *)&sav, sizeof(sav)) != 0)
        if (create_key(dev))
            return RES_ERR;

    dev->id = sav.id;
    dev->state = sav.is_paired ? STATE_PAIRED : STATE_UNPAIRED;
    dev->name = sav.name;
    dev->ecdh_pri_key = sav.pri_key;
    dev->ecdh_pub_key = sav.pub_key;
    dev->tea_key = sav.tea_key;
    /* User Code END */

    return RES_OK;
}
