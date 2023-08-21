#ifndef _FELINK_DEV_USERIO_
#define _FELINK_DEV_USERIO_

#include "felink.h"

typedef enum
{
    SAVE_ID,
    SAVE_NAME,
    SAVE_CONNECT_COUNT,
    SAVE_ECDH_PRI_KEY,
    SAVE_ECDH_PUB_KEY,
    SAVE_TEA_KEY,
} FLSAVETYPE;

flresult fl_random(
    flu8 *dest,
    fluint size) FELINK_C51_REENTRANT;
flresult fl_transmit(
    struct fldev *dev,
    const flu8 *bytes,
    fluint count);
flresult fl_save(
    struct fldev *dev,
    const flu8 *bytes,
    fluint count,
    FLSAVETYPE type);
flresult fl_load(
    struct fldev *dev);

#endif // !_FELINK_DEV_USERIO_
