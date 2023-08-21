#ifndef _FELINK_DEV_FELINK_
#define FELINK_DEV_VERSION 000001
#define _FELINK_DEV_FELINK_ FELINK_DEV_VERSION

#include "userconf.h"

#include <stdint.h>
#include <stdlib.h>
#include <errno.h>

typedef enum
{
    HANDSHAKED = 0,
    PAIRING = 1,
    PAIRED = 2,
    CONNECTED = 3,
} FLPHASE;

typedef int (*fl_tx_func_t)(uint8_t *buf, size_t count);
typedef void (*fl_devs_change_callback_t)(struct flbase_i *base);

struct fldev_i
{
    const uint32_t id;
    const uint16_t type;
    const char *name;
    const FLPHASE phase;
    uint16_t timeout;
    uint8_t max_retrans;
    const time_t tx_packet_delay;
    const size_t tx_packet_count;
    const size_t tx_packet_loss;
};

struct flbase_i
{
    const struct fldev_i **devs;
    const int ndevs;
};

int fl_receive_handler(
    struct flbase_i *base,
    const uint8_t *buf,
    size_t count);
int fl_scan(
    struct flbase_i *base);
int fl_pair(
    struct flbase_i *base,
    const struct fldev_i *dev);
int fl_connect(
    struct flbase_i *base,
    const struct fldev_i *dev);
int fl_send(
    struct flbase_i *base,
    const struct fldev_i *dev,
    const uint8_t *buf,
    size_t count);
int fl_send_plaintext(
    struct flbase_i *base,
    const struct fldev_i *dev,
    const uint8_t *buf,
    size_t count);
struct flbase_i *fl_init(
    fl_tx_func_t tx_func);
void fl_delete(
    struct flbase_i *base);
void fl_set_devs_change_callback(
    struct flbase_i *base,
    fl_devs_change_callback_t callback);
struct flbase_i *fl_reload(
    fl_tx_func_t tx_func,
    const uint8_t *sav,
    size_t count);
size_t fl_save(
    struct flbase_i *base,
    uint8_t **sav);

#endif // !_FELINK_DEV_FELINK_
