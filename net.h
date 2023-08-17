#ifndef NET_H
#define NET_H

#include <stddef.h>
#include <stdint.h>

#ifndef IFNAMSIZ
#define IFNAMSIZ 16
#endif

#define NET_DEVICE_TYPE_DUMMY 0x0000
#define NET_DEVICE_TYPE_LOOPBACK 0x0001
#define NET_DEVICE_TYPE_ETHERNET 0x0002

#define NET_DEVICE_FLAG_UP 0x0001
#define NET_DEVICE_FLAG_LOOPBACK 0x0010
#define NET_DEVICE_FLAG_BROADCAST 0x0020
#define NET_DEVICE_FLAG_P2P 0x0040
#define NET_DEVICE_FLAG_NOARP 0x0100

#define NET_DEVICE_ADDR_LEN 16

#define NET_DEVICE_IS_UP(x) ((x)->flags & NET_DEVICE_FLAG_UP)
#define NET_DEVICE_STATE(x) (NET_DEVICE_IS_UP(x) ? "up" : "down")

/* struct net_protocolのtype */
#define NET_PROTOCOL_TYPE_IP 0x0800
#define NET_PROTOCOL_TYPE_ARP 0x0806
#define NET_PROTOCOL_TYPE_IPV6 0x86dd
#define NET_DEVICE_FLAG_P2P 0x0040
#define NET_DEVICE_FLAG_NEED_ARP 0x0100

/*
 * プロトコルファミリ（アドレスファミリ）
 * [プロトコルファミリとは｜「分かりそう」で「分からない」でも「分かった」気になれるIT用語辞典](https://wa3.i-3-i.info/word13166.html)
 *
 * Linuxではsocket()の第一引数で指定するdomainがプロトコルファミリに相当する。ファミリとなっているが通常は1つのプロトコルのケースになることが多い
 * > Normally only a single protocol exists to support a particular socket type within a given protocol family
 * [socket(2) - Linux manual page](https://man7.org/linux/man-pages/man2/socket.2.html)
 */
#define NET_IFACE_FAMIRY_IP 1
#define NET_IFACE_FAMILY_IPV6 2

/*
 * iface->iface.familyをNET_IFACE(iface)->familyで書けるようにするマクロ
 * ip_iface型の最初の要素がnet_iface型であるのでip_iface型のポインタをnet_iface型のポインタにキャストすることができる
 */
#define NET_IFACE(x) ((struct net_iface *)(x))

struct net_device
{
  struct net_device *next;  // 次のデバイスへのポインタ
  struct net_iface *ifaces; // デバイスとインタフェースは1対多の関係
  unsigned int index;
  char name[IFNAMSIZ];
  // [What does the second 't' stand for in 'uint8_t'? - Quora](https://www.quora.com/What-does-the-second-t-stand-for-in-uint8_t)
  uint16_t type; // デバイスの種別
  /* デバイスの種別によって変わる値 */
  uint16_t mtu;
  uint16_t flags;
  uint16_t hlen; /* header length */
  uint16_t alen; /* address length */

  /*
    デバイスのハードウェアアドレスなど
  */
  uint8_t addr[NET_DEVICE_ADDR_LEN];
  union
  {
    uint8_t peer[NET_DEVICE_ADDR_LEN];
    uint8_t broadcast[NET_DEVICE_ADDR_LEN];
  };
  struct net_device_ops *ops; // デバイスドライバに実装された関数へのポインタ
  void *priv;
};

/*
 * デバイスのインタフェース
 * open（optional）
 * close（optional）
 * transmit（required）: デバイスへメッセージを送信する
 */
struct net_device_ops
{
  int (*open)(struct net_device *dev);
  int (*close)(struct net_device *dev);
  int (*transmit)(struct net_device *dev, uint16_t type, const uint8_t *data, size_t len, const void *dst);
};

/* 抽象的なインタフェース */
struct net_iface
{
  struct net_iface *next;
  struct net_device *dev; // インタフェースを持つデバイス側へのポインタ
  int family;
};

extern struct net_device *
net_device_alloc(void);
extern int
net_device_register(struct net_device *dev);
extern int
net_device_add_iface(struct net_device *dev, struct net_iface *iface);
extern struct net_iface *
net_device_get_iface(struct net_device *dev, int family);
extern int
net_device_output(struct net_device *dev, uint16_t type, const uint8_t *data, size_t len, const void *dst);

extern int
net_protocol_register(uint16_t type, void (*handler)(const uint8_t *data, size_t len, struct net_device *dev));

extern int net_input_handler(uint16_t type, const uint8_t *data, size_t len, struct net_device *dev);
extern int
net_softirq_handler(void);

extern int
net_run(void);
extern void
net_shutdown(void);
extern int
net_init(void);
#endif