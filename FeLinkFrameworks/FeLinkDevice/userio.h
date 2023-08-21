#ifndef _FELINK_DEV_USERIO_
#define _FELINK_DEV_USERIO_

#include "felink.h"

typedef enum
{
    ID,
    TEA_KEY,
} FLSAVETYPE;

FLRESULT fl_random(
    FLU8 *dest,
    FLUINT size) FELINK_C51_REENTRANT;
FLRESULT fl_transmit(
    struct fldev *dev,
    const FLU8 *bytes,
    FLUINT count);
FLRESULT fl_save(
    struct fldev *dev,
    const FLU8 *bytes,
    FLUINT count,
    FLSAVETYPE type);
FLRESULT fl_reload(
    struct fldev *dev);

#endif // !_FELINK_DEV_USERIO_
