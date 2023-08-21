#include "userio.h"
#include "micro-ecc\uECC.h"

/* User Code BEGIN */
#include "adc.h"
static uint32_t get_adc_value()
{
    HAL_ADC_Start(&hadc1);
    if(HAL_ADC_PollForConversion(&hadc1, 100) == HAL_OK)
        return HAL_ADC_GetValue(&hadc1);
    else 
        return 0;
}
/* User Code END */
flresult fl_random(
    flu8 *dest,
    fluint size)
{
    /* User Code BEGIN */
    flu8 val = 0;
    int init, count, i;
    // Use the least-significant bits from the ADC for an unconnected pin (or connected to a source of 
    // random noise). This can take a long time to generate random data if the result of analogRead(0) 
    // doesn't change very frequently.
    while (size)
    {
        for (i = 0; i < 8; ++i)
        {
            init = get_adc_value();
            count = 0;
            while (get_adc_value() == init)
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
    res = nrf24l01_tx_felink_package(bytes, count);
    if (res)
        return RES_ERR_TRANSMIT;
    /* User Code END */

    return RES_OK;
}

/* User Code BEGIN */
struct
{
    flu32 id;
    flu32 connect_count;
    flu8 is_paired;
    const char *name;
    flu8 pri_key[uECC_BYTES];
    flu8 pub_key[uECC_BYTES * 2];
    flu8 tea_key[uECC_BYTES];
} sav;

flu32 fl_rd32(const flu8 *p);
void fl_memcpy(void *dst, const void *src, fluint size);
/* User Code END */
flresult fl_save(
    struct fldev *dev,
    const flu8 *bytes,
    fluint count,
    FLSAVETYPE type)
{
    /* User Code BEGIN */
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
    /* User Code END */

    return RES_OK;
}

/* User Code BEGIN */

/* User Code END */
flresult fl_load(
    struct fldev *dev)
{
    /* User Code BEGIN */
    fluint i;
    flresult res;

    if (1)
    {
        res = fl_create_key(dev);
        if (res)
            return res;

        for (i = 0; i < uECC_BYTES * 2 / 4; i++)
            sav.id += fl_rd32(&sav.pub_key[i * 4]);
        sav.connect_count = 0;
        sav.is_paired = 0;
        sav.name = FELINK_DEFAULT_NAME;
    }

    dev->id = sav.id;
    dev->state = sav.is_paired ? STATE_PAIRED : STATE_UNPAIRED;
    dev->name = sav.name;
    dev->ecdh_pri_key = sav.pri_key;
    dev->ecdh_pub_key = sav.pub_key;
    dev->tea_key = sav.tea_key;
    /* User Code END */

    return RES_OK;
}
