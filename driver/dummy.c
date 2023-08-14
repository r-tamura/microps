/*
 * ダミーデバイスの実装
 */
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>

#include "platform.h"

#include "util.h"
#include "net.h"

#define DUMMY_MTU UINT16_MAX /* maximum size of IP datagram */

#define DUMMY_IRQ INTR_IRQ_BASE

static int
dummy_transmit(struct net_device *dev, uint16_t type, const uint8_t *data, size_t len, const void *dst)
{
  debugf("dev=%p, type=%04x, len=%zu", dev, type, len);
  debugdump(data, len);
  /* drop data */
  intr_raise_irq(DUMMY_IRQ); // テスト用の割り込み発生
  return 0;
}

static struct net_device_ops dummy_ops = {
    .transmit = dummy_transmit,
};

static int
dummy_isr(unsigned int irq, void *id)
{
  debugf("irq=%u, dev=%s", irq, ((struct net_device *)id)->name);
  return 0;
}

struct net_device *
dummy_init(void)
{
  struct net_device *dev;

  dev = net_device_alloc();
  if (!dev)
  {
    errorf("net_device_alloc() failure");
    return NULL;
  }
  dev->type = NET_DEVICE_TYPE_DUMMY;
  dev->mtu = DUMMY_MTU;
  dev->hlen = 0;
  dev->alen = 0;
  dev->ops = &dummy_ops;
  if (net_device_register(dev) == -1)
  {
    errorf("net_device_register() failure");
    return NULL;
  }
  intr_request_irq(DUMMY_IRQ, dummy_isr, INTR_IRQ_SHARED, dev->name, dev);
  debugf("initialized dummy device: %s", dev->name);
  return dev;
}