#ifndef _FELINK_DEV_FELINK_
#define FELINK_DEV_VERSION 000001
#define _FELINK_DEV_FELINK_ FELINK_DEV_VERSION

#include "types.h"
#include "userconf.h"
#include "uECC.h"

#define FELINK_MINIMUM_BUF_SIZE     (8 + (uECC_BYTES * 2))
#define FELINK_RECOMMENDED_BUF_SIZE (4 + 256)
#if (FELINK_BUF_SIZE < FELINK_MINIMUM_BUF_SIZE)
  #error FeLink ERROR: buf SIZE is smaller than minimum SIZE, device cant pair properly
#endif

#define FELINK_MINIMUM_USER_RX_BUF_SIZE     (8 + (uECC_BYTES * 2))
#define FELINK_RECOMMENDED_USER_RX_BUF_SIZE (12 + 256)
#define FELINK_MINIMUM_USER_TX_BUF_SIZE     (8 + (uECC_BYTES * 2))
#define FELINK_RECOMMENDED_USER_TX_BUF_SIZE (8 + (uECC_BYTES * 2))

typedef enum
{
    RES_OK = 0,
    RES_DATA_VALID,
    RES_ERR,
    RES_ERR_ECC_UNSUPPORT,
    RES_ERR_NOMEM,
    RES_ERR_TRANSMIT,
    RES_ERR_CHKSUM,
    RES_ERR_CMD_INVALID,
} FLRESULT;

typedef enum
{
    UNPAIRED,
    HANDSHAKED,
    PAIRED,
    CONNECTED,
} FLPHASE;

struct flsav
{
    const char *name;
    FLU8 *ecdh_pri_key;
    FLU8 *ecdh_pub_key;
    FLU8 *tea_key;
};

struct fldev
{
    FLU32 id;
    FLU16 type;
    FLPHASE phase;
    FLU8 buf[FELINK_BUF_SIZE] FELINK_ATTR_ALIGN;
    FLU32 eigenval;
    FLU16 valid_data_len;
    struct flsav sav;
};

FLRESULT fl_receive_handler(
    struct fldev *dev,
    const FLU8 *bytes,
    FLUINT count);
FLRESULT fl_init(
    struct fldev *dev);

#endif // !_FELINK_DEV_FELINK_
