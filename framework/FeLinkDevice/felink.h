#ifndef _FELINK_DEV_FELINK_
#define FELINK_DEV_VERSION 0x0002
#define _FELINK_DEV_FELINK_ FELINK_DEV_VERSION

#include "types.h"
#include "userconf.h"
#include "uECC.h"

#define FELINK_MINIMUM_BUF_SIZE     (9 + (uECC_BYTES * 2))
#define FELINK_RECOMMENDED_BUF_SIZE (8 + 256)
#if (FELINK_BUF_SIZE < FELINK_MINIMUM_BUF_SIZE)
  #error FeLink ERROR: buf SIZE is smaller than minimum SIZE, device cant pair properly
#endif

#define FELINK_MINIMUM_USER_RX_BUF_SIZE     (8 + (uECC_BYTES * 2))
#define FELINK_RECOMMENDED_USER_RX_BUF_SIZE (12 + FELINK_RECOMMENDED_BUF_SIZE)
#define FELINK_MINIMUM_USER_TX_BUF_SIZE     (8 + (uECC_BYTES * 2))
#define FELINK_RECOMMENDED_USER_TX_BUF_SIZE (8 + (uECC_BYTES * 2))

typedef enum
{
    RES_OK = 0,
    RES_DATA_AVAILABLE = 1,
    RES_HANDSHAKED = 2,
    RES_PAIRED = 3,
    RES_CONNECTED = 4,
    RES_ERR = -1,
    RES_ERR_ECC_UNSUPPORT = -2,
    RES_ERR_NOMEM = -3,
    RES_ERR_TRANSMIT = -4,
    RES_ERR_CHKSUM = -5,
    RES_ERR_CRYPT = -6,
    RES_ERR_PERHAPS_ATTACK = -7,
    RES_ERR_CMD_INVALID = -8,
} flresult;

typedef enum
{
    TX_TYPE_PCMD,
    TX_TYPE_ACK,
} fltxtype;

typedef enum
{
    STATE_UNPAIRED,
    STATE_HANDSHAKED,
    STATE_PAIRED,
    STATE_CONNECTED,
} flstate;

struct fldev
{
    flu32 id;
    flu32 type;
    flstate state;
    flu8 buf[FELINK_BUF_SIZE] FELINK_ATTR_ALIGN;
    flu16 valid_data_len;

    flu32 connect_count;
    flu32 salt;

    const char *name;
    const flu8 *ecdh_pri_key;
    const flu8 *ecdh_pub_key;
    const flu8 *tea_key;
};

flresult fl_receive_handler(
    struct fldev *dev,
    const flu8 *bytes,
    fluint count);
flresult fl_create_key(
    struct fldev *dev);
flresult fl_init(
    struct fldev *dev);

#endif // !_FELINK_DEV_FELINK_
