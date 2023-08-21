#include "felink.h"
#include "micro-ecc/uECC.h"
#include "tea.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>

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

struct fl_msg_t
{
    struct flbase *base;
    uint8_t *buf;
    uint32_t count;
    int result;
};

struct fldev
{
    uint32_t id;
    uint16_t type;
    char *name;
    FLPHASE phase;
    uint16_t timeout;
    uint8_t max_retrans;
    time_t tx_packet_delay;
    size_t tx_packet_count;
    size_t tx_packet_loss;

    uint32_t eigenval;
    uint8_t *tea_key;

    struct fl_msg_t *tx_msg;
    pthread_mutex_t tx_mutex;
    pthread_cond_t tx_cond;

    uint8_t ack_chksum8;
    pthread_cond_t ack_cond;
    pthread_mutex_t ack_mutex;

    pthread_t tx_thread;
};

struct flbase
{
    struct fldev **devs;
    size_t ndevs;

    fl_tx_func_t tx_func;
    fl_devs_change_callback_t devs_change_callback;
    uint8_t *pri_key;
    uint8_t *pub_key;
};

static uint16_t fl_rd16(const uint8_t *p)
{
    uint16_t rv;
    rv = p[1];
    rv = rv << 8 | p[0];
    return rv;
}

static uint32_t fl_rd32(const uint8_t *p)
{
    uint32_t rv;
    rv = p[3];
    rv = rv << 8 | p[2];
    rv = rv << 8 | p[1];
    rv = rv << 8 | p[0];
    return rv;
}

static void fl_wr16(uint8_t *p, uint16_t val)
{
    *p++ = (uint8_t)val;
    val >>= 8;
    *p++ = (uint8_t)val;
}

static void fl_wr32(uint8_t *p, uint32_t val)
{
    *p++ = (uint8_t)val;
    val >>= 8;
    *p++ = (uint8_t)val;
    val >>= 8;
    *p++ = (uint8_t)val;
    val >>= 8;
    *p++ = (uint8_t)val;
}

static uint8_t fl_chksum8(const uint8_t *bytes, size_t len)
{
    uint8_t chksum8 = 0;
    while (len)
        chksum8 += bytes[--len];
    return chksum8;
}

static int fl_random(uint8_t *dest, size_t size)
{
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd == -1)
    {
        fd = open("/dev/random", O_RDONLY);
        if (fd == -1)
            perror("no random generator");
    }

    char *ptr = (char *)dest;
    size_t left = size;
    while (left > 0)
    {
        ssize_t bytes_read = read(fd, ptr, left);
        if (bytes_read <= 0)
        {
            close(fd);
            return EIO;
        }
        left -= bytes_read;
        ptr += bytes_read;
    }

    close(fd);
    return 0;
}

static void fl_timespec_add_ns(struct timespec *t, uint64_t ns)
{
    uint64_t temp = t->tv_nsec + ns;
    t->tv_nsec = temp % 1000000000;
    t->tv_sec += temp / 1000000000;
}

static time_t fl_timeval_interval_us(struct timeval start, struct timeval end)
{
    return (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_usec - start.tv_usec);
}

static void fl_call_devs_change(struct flbase *b)
{
    if (b->devs_change_callback != NULL)
        b->devs_change_callback(b);
}

static void *fl_tx_thread(void *args)
{
    struct fldev *d = (struct fldev *)args;

    pthread_mutex_lock(&d->tx_mutex);
    while (1)
    {
        pthread_cond_wait(&d->tx_cond, &d->tx_mutex);
        pthread_testcancel();

        struct flbase *b = d->tx_msg->base;
        struct fl_msg_t *m = d->tx_msg;
        uint8_t chksum8 = fl_chksum8(m->buf, m->count);

        pthread_mutex_lock(&d->ack_mutex);
        size_t tries;
        for (tries = 0; tries < d->max_retrans; tries++)
        {
            int res = b->tx_func(m->buf, m->count);
            if (res)
            {
                m->result = res;
                break;
            }
            d->tx_packet_count++;

            struct timespec t;
            timespec_get(&t, TIME_UTC);
            fl_timespec_add_ns(&t, d->timeout * 1000000);
            int is_timeout;
            do
            {
                is_timeout = pthread_cond_timedwait(&d->ack_cond, &d->ack_mutex, &t);
            } while (!is_timeout && d->ack_chksum8 != chksum8);

            if (!is_timeout)
            {
                m->result = 0;
                break;
            }
            else
                d->tx_packet_loss++;
        }
        pthread_mutex_unlock(&d->ack_mutex);
        pthread_cond_signal(&d->tx_cond);
        if (tries == d->max_retrans)
        {
            m->result = ETIMEDOUT;
            d->phase = PAIRED;
        }
    }
}

static struct fl_msg_t *fl_msg_create(
    struct flbase *b,
    size_t count)
{
    struct fl_msg_t *msg = malloc(sizeof(struct fl_msg_t));
    if (msg == NULL)
        return NULL;
    msg->base = b;
    msg->buf = malloc(count);
    if (msg->buf == NULL)
    {
        free(msg);
        return NULL;
    }
    msg->count = count;
    msg->result = 0;
    return msg;
}

static void fl_msg_delete(
    struct fl_msg_t *msg)
{
    free(msg->buf);
    free(msg);
}

static struct fldev *fl_dev_create(
    uint32_t id,
    uint16_t type,
    const char *name)
{
    struct fldev *d = malloc(sizeof(struct fldev));

    d->id = id;
    d->type = type;
    d->name = malloc(strlen(name) + 1);
    strcpy(d->name, name);
    d->phase = HANDSHAKED;
    d->timeout = FELINK_DEFAULT_TIMEOUT;
    d->max_retrans = FELINK_DEFAULT_MAXRET;
    d->tx_packet_delay = -1;
    d->tx_packet_count = 0;
    d->tx_packet_loss = 0;
    d->tea_key = malloc(FELINK_uECC_CURVE_SIZE);
    d->ack_chksum8 = 0;
    pthread_cond_init(&d->tx_cond, NULL);
    pthread_mutex_init(&d->tx_mutex, NULL);
    pthread_cond_init(&d->ack_cond, NULL);
    pthread_mutex_init(&d->ack_mutex, NULL);
    pthread_create(&d->tx_thread, NULL, &fl_tx_thread, d);

    return d;
}

static void fl_dev_delete(
    struct flbase *b,
    size_t index)
{
    if (index >= b->ndevs)
        return;
    struct fldev *d = b->devs[index];
    pthread_cancel(d->tx_thread);
    pthread_join(d->tx_thread, NULL);
    pthread_cond_destroy(&d->tx_cond);
    pthread_mutex_destroy(&d->tx_mutex);
    pthread_cond_destroy(&d->ack_cond);
    pthread_mutex_destroy(&d->ack_mutex);
    free(d->name);
    free(d->tea_key);
    free(d->tx_msg);
    free(d);
    for (int i = index; i < b->ndevs - 1; i++)
        b->devs[i] = b->devs[i + 1];
    b->ndevs--;
    b->devs[b->ndevs] = NULL;

    fl_call_devs_change(b);
}

static void fl_base_add_dev(
    struct flbase *b,
    struct fldev *d)
{
    b->ndevs += 1;
    b->devs = realloc(b->devs, b->ndevs * sizeof(struct fldev *));
    b->devs[b->ndevs - 1] = d;
    
    fl_call_devs_change(b);
}

static struct fldev *fl_base_get_dev_by_id(
    struct flbase *b,
    uint32_t id)
{
    for (int i = 0; i < b->ndevs; i++)
        if (b->devs[i]->id == id)
            return b->devs[i];
    return NULL;
}

static int fl_base_is_dev_handshaked(
    struct flbase *b,
    struct fldev *d)
{
    if (d == NULL || b->ndevs == 0)
        return 0;
    for (int i = 0; i < b->ndevs; i++)
        if (b->devs[i] == d)
            return 1;
    return 0;
}

static void fl_get_key(
    struct fldev *d,
    uint32_t *key)
{
    uint8_t *keys = d->tea_key;
    uint32_t ev = d->eigenval;
    size_t cs_s4 = FELINK_uECC_CURVE_SIZE - 4;

    key[0] = fl_rd32(&keys[(uint8_t)(ev >> 0) % cs_s4]);
    key[1] = fl_rd32(&keys[(uint8_t)(ev >> 8) % cs_s4]);
    key[2] = fl_rd32(&keys[(uint8_t)(ev >> 16) % cs_s4]);
    key[3] = fl_rd32(&keys[(uint8_t)(ev >> 24) % cs_s4]);
}

static int fl_transmit_no_ack(
    struct fl_msg_t *msg)
{
    int res;
    res = msg->base->tx_func(msg->buf, msg->count);
    fl_msg_delete(msg);
    return res;
}

static int fl_transmit_with_ack(
    struct fl_msg_t *msg,
    struct fldev *d)
{
    pthread_mutex_lock(&d->tx_mutex);
    d->tx_msg = msg;
    pthread_mutex_unlock(&d->tx_mutex);

    struct timeval send_time;
    gettimeofday(&send_time, NULL);
    pthread_cond_signal(&d->tx_cond);

    pthread_cond_wait(&d->tx_cond, &d->tx_mutex);
    int res = msg->result;
    fl_msg_delete(msg);
    d->tx_msg = NULL;
    pthread_mutex_unlock(&d->tx_mutex);

    struct timeval ack_time;
    gettimeofday(&ack_time, NULL);
    if (res)
        d->tx_packet_delay = -res;
    else
        d->tx_packet_delay = fl_timeval_interval_us(send_time, ack_time) / 1000;

    return res;
}

static int fl_pcmd_base_search(
    struct flbase *b)
{
    struct fl_msg_t *msg = fl_msg_create(b, 2);

    msg->buf[0] = FELINK_PCMD;
    msg->buf[1] = FELINK_PCMD_BASE_SEARCH;

    return fl_transmit_no_ack(msg);
}

static int fl_pcmd_base_id_invalid(
    struct flbase *b,
    uint32_t id)
{
    struct fl_msg_t *msg = fl_msg_create(b, 10);

    msg->buf[0] = FELINK_PCMD;
    msg->buf[1] = FELINK_PCMD_BASE_ID_INVALID;
    fl_wr32(&msg->buf[2], id);
    int ret = fl_random(&msg->buf[6], 4);
    if (ret)
    {
        fl_msg_delete(msg);
        return ret;
    }

    return fl_transmit_no_ack(msg);
}

static int fl_pcmd_base_pair(
    struct flbase *b,
    struct fldev *d)
{
    size_t pub_key_size = FELINK_uECC_PUB_KEY_SIZE;
    struct fl_msg_t *msg = fl_msg_create(b, 8 + pub_key_size);

    msg->buf[0] = FELINK_PCMD;
    msg->buf[1] = FELINK_PCMD_BASE_PAIR;
    fl_wr32(&msg->buf[2], d->id);
    msg->buf[6] = pub_key_size;
    msg->buf[7] = fl_chksum8(b->pub_key, pub_key_size);
    memcpy(&msg->buf[8], b->pub_key, pub_key_size);

    int ret = fl_transmit_no_ack(msg);
    if (ret == 0)
        d->phase = PAIRING;

    return ret;
}

static int fl_ccmd_base_connect(
    struct flbase *b,
    struct fldev *d)
{
    struct fl_msg_t *msg = fl_msg_create(b, 14);

    msg->buf[0] = FELINK_CCMD;
    msg->buf[1] = FELINK_CCMD_BASE_CONNECT;
    fl_wr32(&msg->buf[2], d->id);
    int ret = fl_random(&msg->buf[7], 3);
    if (ret)
    {
        fl_msg_delete(msg);
        return ret;
    }
    fl_wr32(&msg->buf[10], 0x00000000);
    msg->buf[6] = fl_chksum8(&msg->buf[7], 7);
    uint32_t ev = fl_rd32(&msg->buf[6]);
    uint32_t key[4];
    d->eigenval = 0x00000000;
    fl_get_key(d, key);
    d->eigenval = ev;
    ret = fl_xxtea_byte_array_encrypt(&msg->buf[6], 8, key);
    if (ret)
    {
        fl_msg_delete(msg);
        return ret;
    }

    ret = fl_transmit_with_ack(msg, d);
    if (ret == 0)
    {
        d->phase = CONNECTED;
        fl_call_devs_change(b);
    }

    return ret;
}

static int fl_dcmd_data(
    struct flbase *b,
    struct fldev *d,
    const uint8_t *data,
    size_t count,
    char is_plaintext_transmit)
{
    if (count == 0)
        return ENODATA;
    if (count > 0x100)
        return EMSGSIZE;

    int16_t l = 4 + ((count + 3) / 4) * 4;
    struct fl_msg_t *msg = fl_msg_create(b, 8 + l);

    msg->buf[0] = FELINK_DCMD;
    msg->buf[1] = FELINK_DCMD_DATA;
    fl_wr32(&msg->buf[2], d->id);
    fl_wr16(&msg->buf[6], (uint16_t)(is_plaintext_transmit ? -l : l));
    msg->buf[8] = count;
    int ret = fl_random(&msg->buf[10], 2);
    if (ret)
    {
        fl_msg_delete(msg);
        return ret;
    }
    memcpy(&msg->buf[12], data, count);
    msg->buf[9] = fl_chksum8(&msg->buf[10], l - 2);
    uint32_t ev = fl_rd32(&msg->buf[8]);
    if (!is_plaintext_transmit)
    {
        uint32_t key[4];
        fl_get_key(d, key);
        ret = fl_xxtea_byte_array_encrypt(&msg->buf[8], l, key);
        if (ret)
        {
            fl_msg_delete(msg);
            return ret;
        }
    }

    ret = fl_transmit_with_ack(msg, d);
    if (ret)
        fl_call_devs_change(b);
    else
        d->eigenval = ev;

    return ret;
}

static int fl_pcmd_dev_handshake_handler(
    struct flbase *b,
    const uint8_t *data,
    size_t count)
{
    uint32_t id = fl_rd32(&data[2]);

    struct fldev *d = fl_base_get_dev_by_id(b, id);
    if (d == NULL)
    {
        uint16_t type = fl_rd16(&data[6]);
        d = fl_dev_create(id, type, &data[8]);
        fl_base_add_dev(b, d);

        return 0;
    }
    else
        return fl_pcmd_base_id_invalid(b, id);
}

static int fl_pcmd_dev_pair_handler(
    struct flbase *b,
    const uint8_t *data,
    size_t count)
{
    uint32_t id = fl_rd32(&data[2]);

    struct fldev *d = fl_base_get_dev_by_id(b, id);
    if (d != NULL && d->phase == PAIRING)
    {
        uint8_t n = data[6];
        if (n != FELINK_uECC_PUB_KEY_SIZE)
            return EPROTONOSUPPORT;
        uint8_t chksum8 = data[7];
        if (chksum8 != fl_chksum8(&data[8], n))
            return EBADMSG;

        uECC_shared_secret(&data[8], b->pri_key, d->tea_key, FELINK_uECC_CURVE);
        d->phase = PAIRED;
        fl_call_devs_change(b);
    }

    return 0;
}

static int fl_pcmd_dev_id_change_handler(
    struct flbase *b,
    const uint8_t *data,
    size_t count)
{
    uint32_t nid = fl_rd32(&data[2]);
    uint32_t oid = fl_rd32(&data[6]);

    struct fldev *d = fl_base_get_dev_by_id(b, nid);
    if (d != NULL)
        return fl_pcmd_base_id_invalid(b, nid);

    d = fl_base_get_dev_by_id(b, oid);
    if (d == NULL)
    {
        uint16_t type = fl_rd16(&data[10]);
        d = fl_dev_create(nid, type, &data[12]);
        fl_base_add_dev(b, d);
    }
    else
        d->id = nid;

    return 0;
}

static int fl_pcmd_handler(
    struct flbase *b,
    const uint8_t *data,
    size_t count)
{
    uint8_t minor_cmd = data[1];
    if (minor_cmd != FELINK_PCMD_BASE_SEARCH)
        if (count < 6)
            return EBADMSG;
    switch (minor_cmd)
    {
    case FELINK_PCMD_DEV_HANDSHAKE:
        return fl_pcmd_dev_handshake_handler(b, data, count);
    case FELINK_PCMD_DEV_PAIR:
        return fl_pcmd_dev_pair_handler(b, data, count);
    case FELINK_PCMD_DEV_ID_CHANGE:
        return fl_pcmd_dev_id_change_handler(b, data, count);
    case FELINK_PCMD_BASE_SEARCH:
    case FELINK_PCMD_BASE_PAIR:
    case FELINK_PCMD_BASE_ID_INVALID:
        return 0;
    default:
        return EBADMSG;
    }
}

static int fl_ccmd_dev_ack_handler(
    struct flbase *b,
    const uint8_t *data,
    size_t count)
{
    uint32_t id = fl_rd32(&data[2]);

    struct fldev *d = fl_base_get_dev_by_id(b, id);
    if (d != NULL)
    {
        pthread_mutex_lock(&d->ack_mutex);
        d->ack_chksum8 = data[6];
        pthread_mutex_unlock(&d->ack_mutex);
        pthread_cond_signal(&d->ack_cond);
    }

    return 0;
}

static int fl_ccmd_handler(
    struct flbase *b,
    const uint8_t *data,
    size_t count)
{
    if (count < 6)
        return EBADMSG;

    uint8_t minor_cmd = data[1];
    switch (minor_cmd)
    {
    case FELINK_CCMD_DEV_ACK:
        return fl_ccmd_dev_ack_handler(b, data, count);
    case FELINK_CCMD_BASE_CONNECT:
        return 0;
    default:
        return EBADMSG;
    }
}

int fl_receive_handler(
    struct flbase_i *base,
    const uint8_t *buf,
    size_t count)
{
    struct flbase *b = (struct flbase *)base;

    int res;
    uint8_t major_cmd = buf[0];
    switch (major_cmd)
    {
    case FELINK_PCMD:
        res = fl_pcmd_handler(b, buf, count);
        break;
    case FELINK_CCMD:
        res = fl_ccmd_handler(b, buf, count);
        break;
    case FELINK_DCMD:
        res = 0;
        break;
    default:
        res = EBADMSG;
        break;
    }

    return res;
}

int fl_scan(
    struct flbase_i *base)
{
    struct flbase *b = (struct flbase *)base;

    for (int i = b->ndevs - 1; i >= 0; i--)
        if (b->devs[i]->phase == HANDSHAKED)
            fl_dev_delete(b, i);
    fl_call_devs_change(b);
    return fl_pcmd_base_search(b);
}

int fl_pair(
    struct flbase_i *base,
    const struct fldev_i *dev)
{
    struct flbase *b = (struct flbase *)base;
    struct fldev *d = (struct fldev *)dev;

    if (!fl_base_is_dev_handshaked(b, d))
        return ENOTCONN;
    // if (d->phase == PAIRING)
    //     return EALREADY;
    if (d->phase == PAIRED || d->phase == CONNECTED)
        return EISCONN;

    return fl_pcmd_base_pair(b, d);
}

int fl_connect(
    struct flbase_i *base,
    const struct fldev_i *dev)
{
    struct flbase *b = (struct flbase *)base;
    struct fldev *d = (struct fldev *)dev;

    if (!fl_base_is_dev_handshaked(b, d) || d->phase == HANDSHAKED || d->phase == PAIRING)
        return ENOTCONN;

    d->tx_packet_count = 0;
    d->tx_packet_loss = 0;

    return fl_ccmd_base_connect(b, d);
}

int fl_send(
    struct flbase_i *base,
    const struct fldev_i *dev,
    const uint8_t *buf,
    size_t count)
{
    struct flbase *b = (struct flbase *)base;
    struct fldev *d = (struct fldev *)dev;

    if (!fl_base_is_dev_handshaked(b, d) || d->phase != CONNECTED)
        return ENOTCONN;

    int ret = fl_dcmd_data(b, d, buf, count, 0);

    return ret;
}

int fl_send_plaintext(
    struct flbase_i *base,
    const struct fldev_i *dev,
    const uint8_t *buf,
    size_t count)
{
    struct flbase *b = (struct flbase *)base;
    struct fldev *d = (struct fldev *)dev;

    if (!fl_base_is_dev_handshaked(b, d) || d->phase != CONNECTED)
        return ENOTCONN;

    int ret = fl_dcmd_data(b, d, buf, count, 1);

    return ret;
}

struct flbase_i *fl_init(
    fl_tx_func_t tx_func)
{
    struct flbase *b = malloc(sizeof(struct flbase));

    b->devs = malloc(1 * sizeof(struct fldev *));
    b->ndevs = 0;
    b->tx_func = tx_func;
    b->devs_change_callback = NULL;
    b->pri_key = malloc(FELINK_uECC_PRI_KEY_SIZE);
    b->pub_key = malloc(FELINK_uECC_PUB_KEY_SIZE);
    int ret = uECC_make_key(b->pub_key, b->pri_key, FELINK_uECC_CURVE);
    if (ret == 0)
    {
        free(b);
        return NULL;
    }

    return (struct flbase_i *)b;
}

void fl_delete(
    struct flbase_i *base)
{
    struct flbase *b = (struct flbase *)base;

    for (int i = b->ndevs - 1; i >= 0; i--)
        fl_dev_delete(b, i);
    free(b->devs);
    free(b->pri_key);
    free(b->pub_key);
    free(b);
}

void fl_set_devs_change_callback(
    struct flbase_i *base,
    fl_devs_change_callback_t callback)
{
    struct flbase *b = (struct flbase *)base;

    b->devs_change_callback = callback;
}

struct flbase_i *fl_reload(
    fl_tx_func_t tx_func,
    const uint8_t *sav,
    size_t count)
{
    size_t ecc_curve_len = FELINK_uECC_CURVE_SIZE, pri_key_len = FELINK_uECC_PRI_KEY_SIZE, pub_key_len = FELINK_uECC_PUB_KEY_SIZE;

    const uint8_t *ptr = sav;

    if (strncmp(ptr, "FELK", 4))
        return NULL;
    ptr += 4;

    uint32_t len = fl_rd32(ptr);
    if (len > count)
        return NULL;
    ptr += 4;

    if (*ptr++ != fl_chksum8(ptr, len - 9))
        return NULL;

    if (*ptr++ != ecc_curve_len)
        return NULL;

    struct flbase *b = malloc(sizeof(struct flbase));
    b->tx_func = tx_func;
    b->devs_change_callback = NULL;
    b->pri_key = malloc(pri_key_len);
    memcpy(b->pri_key, ptr, pri_key_len);
    ptr += pri_key_len;
    b->pub_key = malloc(pub_key_len);
    memcpy(b->pub_key, ptr, pub_key_len);
    ptr += pub_key_len;

    uint32_t n_paired_devs = fl_rd32(ptr);
    ptr += 4;
    b->devs = malloc(n_paired_devs * sizeof(struct fldev *));
    for (int i = 0; i < n_paired_devs; i++)
    {
        uint32_t id = fl_rd32(ptr);
        ptr += 4;
        uint16_t type = fl_rd16(ptr);
        ptr += 2;
        if (ecc_curve_len != *ptr)
        {
            ptr += 1 + *ptr;
            ptr += strlen((char *)ptr) + 1;
            continue;
        }
        
        const uint8_t *tea_key = (uint8_t *)(ptr + 1);
        ptr += 1 + *ptr;
        const char *name = (const char *)ptr;
        ptr += strlen((char *)ptr) + 1;

        struct fldev *d = fl_dev_create(id, type, name);
        memcpy(d->tea_key, tea_key, ecc_curve_len);
        d->phase = PAIRED;
        b->devs[b->ndevs++] = d;
    }

    return (struct flbase_i *)b;
}

size_t fl_save(
    struct flbase_i *base,
    uint8_t **sav)
{
    struct flbase *b = (struct flbase *)base;

    size_t ecc_curve_len = FELINK_uECC_CURVE_SIZE, pri_key_len = FELINK_uECC_PRI_KEY_SIZE, pub_key_len = FELINK_uECC_PUB_KEY_SIZE;
    uint32_t len = 14 + pri_key_len + pub_key_len;

    uint32_t n_paired_devs = 0;
    struct fldev *paired_devs[b->ndevs];
    for (int i = 0; i < b->ndevs; i++)
    {
        struct fldev *d = b->devs[i];
        if (d->phase == PAIRED || d->phase == CONNECTED)
        {
            paired_devs[n_paired_devs++] = d;
            len += 7 + ecc_curve_len + strlen(d->name) + 1;
        }
    }

    *sav = malloc(len);
    uint8_t *ptr = *sav;

    strncpy((char *)ptr, "FELK", 4);
    ptr += 4;
    fl_wr32(ptr, len);
    ptr += 4;
    ptr += 1;
    *ptr++ = (uint8_t)ecc_curve_len;
    memcpy(ptr, b->pri_key, pri_key_len);
    ptr += pri_key_len;
    memcpy(ptr, b->pub_key, pub_key_len);
    ptr += pub_key_len;
    fl_wr32(ptr, n_paired_devs);
    ptr += 4;
    for (int i = 0; i < n_paired_devs; i++)
    {
        struct fldev *d = paired_devs[i];
        fl_wr32(ptr, d->id);
        ptr += 4;
        fl_wr16(ptr, d->type);
        ptr += 2;
        *ptr++ = (uint8_t)ecc_curve_len;
        memcpy(ptr, d->tea_key, ecc_curve_len);
        ptr += ecc_curve_len;
        strcpy((char *)ptr, d->name);
        ptr += strlen(d->name) + 1;
    }
    (*sav)[8] = fl_chksum8(&(*sav)[9], len - 9);

    return len;
}
