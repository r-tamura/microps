#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>

#include "platform.h"

#include "util.h"
#include "net.h"
#include "ip.h"
#include "icmp.h"
#include "arp.h"
#include "udp.h"

struct net_protocol
{
    struct net_protocol *next;
    uint16_t type;
    struct queue_head queue; /* input queue */
    void (*handler)(const uint8_t *data, size_t len, struct net_device *dev);
};

struct net_protocol_queue_entry
{
    struct net_device *dev;
    size_t len;
    uint8_t data[];
};

struct net_timer
{
    struct net_timer *next;
    struct timeval interval;
    struct timeval last;
    void (*handler)(void);
};

struct net_event
{
    struct net_event *next;
    void (*handler)(void *arg);
    void *arg;
};

static struct net_device *devices;
static struct net_protocol *protocols;
static struct net_timer *timers;
static struct net_event *events;

struct net_device *
net_device_alloc(void)
{
    struct net_device *dev;

    /*
     * memory_alloc()で確保したメモリ領域は0で初期化されている
     */
    dev = memory_alloc(sizeof(*dev));
    if (!dev)
    {
        errorf("memory_alloc() failed");
        return NULL;
    }
    return dev;
}

/*
 * デバイスを登録します
 * デバイス名ルール net0, net1, ...　
 */
int net_device_register(struct net_device *dev)
{
    static unsigned int index = 0;
    dev->index = index++;
    snprintf(dev->name, sizeof(dev->name), "net%d", dev->index);
    dev->next = devices;
    devices = dev;
    infof("registered, dev=%s, type=0x%04x", dev->name, dev->type);
    return 0;
}

static int
net_device_open(struct net_device *dev)
{
    if (NET_DEVICE_IS_UP(dev))
    {
        errorf("already opened, dev=%s", dev->name);
        return -1;
    }
    if (dev->ops->open)
    {
        if (dev->ops->open(dev) == -1)
        {
            errorf("failure, dev=%s", dev->name);
            return -1;
        }
    }
    dev->flags |= NET_DEVICE_FLAG_UP;
    infof("dev=%s, state=%s", dev->name, NET_DEVICE_STATE(dev));
    return 0;
}

static int
net_device_close(struct net_device *dev)
{
    if (!NET_DEVICE_IS_UP(dev))
    {
        errorf("already closed, dev=%s", dev->name);
        return -1;
    }
    if (dev->ops->close)
    {
        if (dev->ops->close(dev) == -1)
        {
            errorf("failure, dev=%s", dev->name);
            return -1;
        }
    }
    dev->flags &= ~NET_DEVICE_FLAG_UP;
    infof("dev=%s, state=%s", dev->name, NET_DEVICE_STATE(dev));
    return 0;
}

int net_device_add_iface(struct net_device *dev, struct net_iface *iface)
{
    struct net_iface *entry;

    for (entry = dev->ifaces; entry; entry = entry->next)
    {
        if (entry->family == iface->family)
        {
            errorf("already exists, dev=%s, family=%d", dev->name, iface->family);
            return -1;
        }
    }
    iface->dev = dev;
    /* Day2 P22 Exercise 7-1: デバイスのインタフェースリストの先頭にifaceを挿入 */
    iface->next = dev->ifaces;
    dev->ifaces = iface;
    /* Exercise 7-1 end */
    return 0;
}

struct net_iface *
net_device_get_iface(struct net_device *dev, int family)
{
    /* Day2 P22 Exercise 7-2: デバイスに紐づくインタフェースを検索 */
    struct net_iface *entry;

    for (entry = dev->ifaces; entry; entry = entry->next)
    {
        if (entry->family == family)
        {
            return entry;
        }
    }
    return NULL;
    /* Exercise 7-2 end*/
}

int net_device_output(struct net_device *dev, uint16_t type, const uint8_t *data, size_t len, const void *dst)
{
    if (!NET_DEVICE_IS_UP(dev))
    {
        errorf("not opened, dev=%s", dev->name);
        return -1;
    }
    // MTUを超えるサイズのデータは送信不可
    if (len > dev->mtu)
    {
        errorf("too large, dev=%s, len=%zu, mtu=%zu", dev->name, len, dev->mtu);
        return -1;
    }
    debugf("dev=%s, type=0x%04x, len=%zu", dev->name, type, len);
    debugdump(data, len);
    if (dev->ops->transmit(dev, type, data, len, dst) == -1)
    {
        errorf("device transmit failure, dev=%s, len=%zu", dev->name, len);
        return -1;
    }
    return 0;
}

int net_protocol_register(uint16_t type, void (*handler)(const uint8_t *data, size_t len, struct net_device *dev))
{
    struct net_protocol *proto;

    for (proto = protocols; proto; proto = proto->next)
    {
        if (type == proto->type)
        {
            errorf("already registered, type=0x%04x", type);
            return -1;
        }
    }
    proto = memory_alloc(sizeof(*proto));
    if (!proto)
    {
        errorf("memory_alloc() failed");
        return -1;
    }
    proto->type = type;
    proto->handler = handler;
    proto->next = protocols;
    protocols = proto;
    infof("registered, type=0x%04x", type);
    return 0;
}

int net_timer_register(struct timeval interval, void (*handler)(void))
{
    struct net_timer *timer;

    /* Exercise 16-1: タイマーの登録 */
    timer = memory_alloc(sizeof(*timer));
    if (!timer)
    {
        errorf("memory_alloc() failed");
        return -1;
    }
    timer->interval = interval;
    gettimeofday(&timer->last, NULL);
    timer->handler = handler;
    timer->next = timers;
    timers = timer;
    /* Exercise 16-1 end */
    infof("registered, interval={%d, %d}", interval.tv_sec, interval.tv_usec);
    return 0;
}

int net_timer_handler(void)
{
    struct net_timer *timer;
    struct timeval now, diff;

    for (timer = timers; timer; timer = timer->next)
    {
        gettimeofday(&now, NULL);
        timersub(&now, &timer->last, &diff);
        // [timercmp(3): timeval operations - Linux man page](https://linux.die.net/man/3/timercmp)
        // > returns true (nonzero) or false (0) depending on the result of the comparison.
        if (timercmp(&timer->interval, &diff, <) != 0)
        {
            timer->handler();
            timer->last = now;
        }
    }
    return 0;
}

int net_input_handler(uint16_t type, const uint8_t *data, size_t len, struct net_device *dev)
{
    struct net_protocol *proto;
    struct net_protocol_queue_entry *entry;

    for (proto = protocols; proto; proto = proto->next)
    {
        if (proto->type == type)
        {
            /* Day1 P72 Exercise 4-1: プロトコルの受信キューにエントリを挿入 */
            entry = memory_alloc(sizeof(*entry) + len);
            if (!entry)
            {
                errorf("memory_alloc() failed");
                return -1;
            }
            entry->dev = dev;
            entry->len = len;
            memcpy(entry->data, data, len);

            void *result;
            result = queue_push(&proto->queue, entry);
            if (!result)
            {
                errorf("queue_push() failed");
                return -1;
            }

            /* Exercise 4-1: end */
            debugf("queue pushed (num:%u), dev=%s, type=0x%04x, len=%zu",
                   proto->queue.num, dev->name, type, len);
            debugdump(data, len);
            intr_raise_irq(INTR_IRQ_SOFTIRQ);
            return 0;
        }
    }

    /* unsupported protocol */
    return 0;
}

/* ソフトウェア割り込みハンドラ　*/
int net_softirq_handler(void)
{
    struct net_protocol *proto;
    struct net_protocol_queue_entry *entry;
    for (proto = protocols; proto; proto = proto->next)
    {
        while (1)
        {
            entry = queue_pop(&proto->queue);
            if (!entry)
            {
                break;
            }
            debugf("queue popped (num:%u), dev=%s, type=0x%04x, len=%zu",
                   proto->queue.num, entry->dev->name, proto->type, entry->len);
            debugdump(entry->data, entry->len);
            proto->handler(entry->data, entry->len, entry->dev);
            memory_free(entry);
        }
    }
    return 0;
}

/**
 * イベントの購読します
 */
int net_event_subscribe(void (*handler)(void *arg), void *arg)
{
    struct net_event *event;

    event = memory_alloc(sizeof(*event));
    if (!event)
    {
        errorf("memory_alloc() failed");
        return -1;
    }
    event->handler = handler;
    event->arg = arg;
    event->next = events;
    events = event;
    return 0;
}

/*
 * 購読しているハンドラをすべて実行します
 */
int net_event_handler(void)
{
    struct net_event *event;
    for (event = events; event; event = event->next)
    {
        event->handler(event->arg);
    }
    return 0;
}

void net_raise_event()
{
    intr_raise_irq(INTR_IRQ_EVENT);
}

/*
 * 登録済みのデバイスをすべてオープンします
 */
int net_run(void)
{
    struct net_device *dev;

    if (intr_run() == -1)
    {
        errorf("intr_run() failure");
        return -1;
    }

    debugf("open all devices...");
    for (dev = devices; dev; dev = dev->next)
    {
        net_device_open(dev);
    }
    debugf("running");
    return 0;
}

/*
 * 登録済みのデバイスをすべてくろーずします
 */
void net_shutdown(void)
{
    struct net_device *dev;

    debugf("close all devices...");
    for (dev = devices; dev; dev = dev->next)
    {
        net_device_close(dev);
    }
    intr_shutdown();
    debugf("shutting down");
}

int net_init(void)
{
    if (intr_init() == -1)
    {
        errorf("intr_init() failure");
        return -1;
    }
    /* Exercise 13-5: ARPの初期化関数を呼び出す */
    if (arp_init() == -1)
    {
        errorf("arp_init() failure");
        return -1;
    }
    /* Exercise 13-5 end */

    if (ip_init() == -1)
    {
        errorf("ip_init() failure");
        return -1;
    }
    if (icmp_init() == -1)
    {
        errorf("icmp_init() failure");
        return -1;
    }
    /* Exercise 18-4: UDPの初期化関数を呼び出す */
    if (udp_init() == -1)
    {
        errorf("udp_init() failure");
        return -1;
    }
    /* Exercise 18-4 end */
    infof("initialized");
    return 0;
}