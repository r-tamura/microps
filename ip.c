#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>

#include "platform.h"

#include "util.h"
#include "net.h"
#include "ip.h"

struct ip_hdr
{
    uint8_t vhl;     // バージョン4bit + IPヘッダ長4bit
    uint8_t tos;     // サービスタイプ
    uint16_t total;  // データグラム(ヘッダとペイロード)全長
    uint16_t id;     // フラグメンテーションで利用される識別子
    uint16_t offset; // フラグメント前のデータの中でどの位置にあるか
    uint8_t ttl;
    uint8_t protocol;
    uint16_t sum; // チェックサム ルータ経由時にTTLが変わるのでその度に計算
    ip_addr_t src;
    ip_addr_t dst;
    uint8_t options[];
};

const ip_addr_t IP_ADDR_ANY = 0x00000000;
const ip_addr_t IP_ADDR_BROADCAST = 0xffffffff;

static struct ip_iface *ifaces;

/*
 * Network binary TO Printable text
 * IPアドレスを文字列からネットワークバイトオーダーのバイナリ値（ip_addr_t）に変換
 */
int ip_addr_pton(const char *p, ip_addr_t *n)
{
    char *sp, *ep;
    int idx;
    long ret;

    sp = (char *)p;
    for (idx = 0; idx < 4; idx++)
    {
        ret = strtol(sp, &ep, 10);
        if (ret < 0 || ret > 255)
        {
            return -1;
        }
        if (ep == sp)
        {
            return -1;
        }
        if ((idx == 3 && *ep != '\0') || (idx != 3 && *ep != '.'))
        {
            return -1;
        }
        ((uint8_t *)n)[idx] = ret;
        sp = ep + 1;
    }
    return 0;
}

/*
 * Printable text TO Network binary
 * IPアドレスをネットワークバイトオーダーのバイナリ値（ip_addr_t）から文字列に変換
 */
char *
ip_addr_ntop(ip_addr_t n, char *p, size_t size)
{
    uint8_t *u8;
    u8 = (uint8_t *)&n;
    snprintf(p, size, "%d.%d.%d.%d", u8[0], u8[1], u8[2], u8[3]);
    return p;
}

static void
ip_dump(const uint8_t *data, size_t len)
{
    struct ip_hdr *hdr;
    uint8_t v, hl, hlen;
    uint16_t total, offset;
    char addr[IP_ADDR_STR_LEN];

    flockfile(stderr);
    hdr = (struct ip_hdr *)data;
    v = (hdr->vhl & 0xf0) >> 4;
    hl = hdr->vhl & 0x0f;
    hlen = hl << 2;
    fprintf(stderr, "        vhl: 0x%02x [v: %u, hl: %u (%u)]\n", hdr->vhl, v, hl, hlen);
    fprintf(stderr, "        tos: 0x%02x\n", hdr->tos);
    total = ntoh16(hdr->total); // リトルエンディアンの場合、多バイト長の数値をビッグエンディアンに変換
    fprintf(stderr, "      total: %u (payload: %u)\n", total, total - hlen);
    fprintf(stderr, "         id: %u\n", ntoh16(hdr->id));
    offset = ntoh16(hdr->offset);
    fprintf(stderr, "     offset: 0x%04x [flags=%x, offset=%u]\n", offset, (offset & 0xe000) >> 13, offset & 0x1fff);
    fprintf(stderr, "        ttl: %u\n", hdr->ttl);
    fprintf(stderr, "   protocol: %u\n", hdr->protocol);
    fprintf(stderr, "        sum: 0x%04x\n", ntoh16(hdr->sum));
    fprintf(stderr, "        src: %s\n", ip_addr_ntop(hdr->src, addr, sizeof(addr)));
    fprintf(stderr, "        dst: %s\n", ip_addr_ntop(hdr->dst, addr, sizeof(addr)));

#ifdef HEXDUMP
    hexdump(stderr, data, len);
#endif
    funlockfile(stderr);
}

struct ip_iface *
ip_iface_alloc(const char *unicast, const char *network)
{
    struct ip_iface *iface;
    ip_addr_t network_addr;

    iface = memory_alloc(sizeof(*iface));
    if (!iface)
    {
        errorf("memory_alloc() failed");
        return NULL;
    }
    NET_IFACE(iface)->family = NET_IFACE_FAMIRY_IP;

    /* Day2 P23 Exercise 7-3: IPインタフェースにアドレス情報を設定 */
    // (1) iface->unicast : 引数 unicast を文字列からバイナリ値へ変換して設定する)
    if (ip_addr_pton(unicast, &iface->unicast) == -1)
    {
        errorf("ip_addr_pton() failed: unicast=%s", unicast);
        memory_free(iface);
        return NULL;
    }
    // (2) iface->netmask : 引数 netmask を文字列からバイナリ値へ変換して設定する
    if (ip_addr_pton(network, &iface->netmask) == -1)
    {
        errorf("ip_addr_pton() failed: network=%s", network);
        memory_free(iface);
        return NULL;
    }
    // (3) iface->broadcast : iface->unicast と iface->netmask の値から算出して設定する
    network_addr = iface->unicast & iface->netmask;
    iface->broadcast = network_addr | ~iface->netmask;
    /* Exercise 7-3 end */

    return iface;
}

int ip_iface_register(struct net_device *dev, struct ip_iface *iface)
{
    char addr1[IP_ADDR_STR_LEN];
    char addr2[IP_ADDR_STR_LEN];
    char addr3[IP_ADDR_STR_LEN];

    /* Day2 P24 Exercise 7-4: IPインタフェースの登録 */
    if (net_device_add_iface(dev, NET_IFACE(iface)) == -1)
    {
        errorf("net_device_add_iface() failed");
        return -1;
    }

    iface->next = ifaces;
    ifaces = iface;

    /* Exercise 7-4 end */

    infof("registered: dev=%s, unicast=%s, netmask=%s, broadcast=%s", dev->name,
          ip_addr_ntop(iface->unicast, addr1, sizeof(addr1)),
          ip_addr_ntop(iface->netmask, addr2, sizeof(addr2)),
          ip_addr_ntop(iface->broadcast, addr3, sizeof(addr3)));
    return 0;
}

struct ip_iface *
ip_iface_select(ip_addr_t addr)
{
    /* Day2 Exercise 7-5: IPインタフェースの検索 */
    struct ip_iface *entry;
    for (entry = ifaces; entry; entry = entry->next)
    {
        if (addr == entry->unicast)
        {
            return entry;
        }
    }
    return NULL;
    /* Exercise 7-5 end */
}

static void
ip_input(const uint8_t *data, size_t len, struct net_device *dev)
{
    struct ip_hdr *hdr;
    uint8_t v;
    uint16_t hlen, total, offset, sum;
    struct ip_iface *iface;
    char addr[IP_ADDR_STR_LEN];

    if (len < IP_HDR_SIZE_MIN)
    {
        errorf("too short");
        return;
    }
    hdr = (struct ip_hdr *)data;

    /* Day2 P14 Exercise 6-1: IPデータグラムの検証 */
    v = hdr->vhl >> 4;
    if (v != IP_VERSION_IPV4)
    {
        errorf("not IPv4");
        return;
    }
    hlen = hdr->vhl & 0x0f;
    if (len < hlen)
    {
        errorf("should not be short than header");
        return;
    }
    total = ntoh16(hdr->total);
    if (len < total)
    {
        errorf("should not be short than total");
        return;
    }
    /* チェックサムの検証
     * ヘッダ長の値(IHL)は4オクテット単位
     * [RFC 791 - Internet Protocol](https://datatracker.ietf.org/doc/html/rfc791#section-3.1)
     *
     * 送信側でチェックサムを計算するときはヘッダのチェックサム値は0としているので、
     * 受信側でチェックサムを計算すると0になることを確認する
     */
    sum = cksum16((uint16_t *)hdr, hlen << 2, 0);
    if (sum != 0)
    {
        errorf("invalid checksum");
        return;
    }

    /* Exercise 6-1 end */

    offset = ntoh16(hdr->offset);
    // フラグメントかどうかの判断 … MF（More Flagments）ビットが立っている or フラグメントオフセットに値がある
    if (offset & 0x2000 || offset & 0x1fff)
    {
        errorf("fragments does not support");
        return;
    }

    /* Day2 Exercise 7-6: IPデータグラムのフィルタリング */
    // デバイスに紐づくIPインタフェースを取得
    iface = ip_iface_select(hdr->dst);
    if (!iface || NET_IFACE(iface)->dev != dev)
    {
        errorf("no interface");
        return;
    }

    // 宛先IPアドレスの検証
    if (hdr->dst != iface->unicast && hdr->dst != IP_ADDR_BROADCAST && hdr->dst != iface->broadcast)
    {
        return;
    }
    /* Exercise 7-6 end */

    debugf("dev=%s, iface=%s, protocol=%u, total=%u", dev->name, ip_addr_ntop(iface->unicast, addr, sizeof(addr)), hdr->protocol, total);
    ip_dump(data, total);
}

/*
 * data: ヘッダを含むIPパケット
 */
static int
ip_output_device(struct ip_iface *iface, const uint8_t *data, size_t len, ip_addr_t dst)
{
    uint8_t hwaddr[NET_DEVICE_ADDR_LEN] = {};

    if (NET_IFACE(iface)->dev->flags & NET_DEVICE_FLAG_NEED_ARP)
    {
        if (dst == iface->broadcast || dst == IP_ADDR_BROADCAST)
        {
            memcpy(hwaddr, NET_IFACE(iface)->dev->broadcast, NET_DEVICE_ADDR_LEN);
        }
        else
        {
            errorf("arp not implemented");
            return -1;
        }
    }

    /* Day2 Exercise 8-4: デバイスから送信 */
    return net_device_output(NET_IFACE(iface)->dev, NET_PROTOCOL_TYPE_IP, data, len, hwaddr);
    /* Exercise 8-4 end */
}

static ssize_t
ip_output_core(struct ip_iface *iface, uint8_t protocol, const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst, uint16_t id, uint16_t offset)
{
    uint8_t buf[IP_TOTAL_SIZE_MAX];
    struct ip_hdr *hdr;
    uint16_t hlen, total;
    char addr[IP_ADDR_STR_LEN];

    hdr = (struct ip_hdr *)buf;
    /* Day2 Exercise 8-3: IPデータグラムの生成 */
    hlen = IP_HDR_SIZE_MIN >> 2;
    hdr->vhl = (IP_VERSION_IPV4 << 4) | hlen;
    hdr->tos = 0;
    total = hton16(len + IP_HDR_SIZE_MIN);
    hdr->total = total;
    hdr->id = hton16(id);
    // フラグメンテーションは未実装なのでflagは0
    hdr->offset = hton16(offset);
    hdr->ttl = 255;
    hdr->protocol = protocol;
    hdr->src = src;
    hdr->dst = dst;
    // チェックサムはIPアドレスも含むので最後に計算する
    hdr->sum = 0;
    hdr->sum = cksum16((uint16_t *)hdr, IP_HDR_SIZE_MIN, 0);
    memcpy(hdr + 1, data, len);

    /* Exercise 8-3 end */
    debugf("dev=%s, dst=%s, protocol=%u, len=%u", NET_IFACE(iface)->dev->name, ip_addr_ntop(dst, addr, sizeof(addr)), protocol, len);
    ip_dump(buf, total);
    return ip_output_device(iface, buf, total, dst);
}

static uint16_t
ip_generate_id(void)
{
    static mutex_t mutex = MUTEX_INITIALIZER;
    static uint16_t id = 128;
    uint16_t ret;

    mutex_lock(&mutex);
    ret = id++;
    mutex_unlock(&mutex);
    return ret;
}

// Note: size_tとssize_tの違い
// [【2022年最新版】size_tとssize_tを使い分けてSegmentation Faultを予防する](https://www.servernote.net/article.cgi?id=use-size-t-and-ssize-t-on-c)
ssize_t
ip_output(uint8_t protocol, const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst)
{
    struct ip_iface *iface;
    char addr[IP_ADDR_STR_LEN];
    char addr2[IP_ADDR_STR_LEN];
    char addr3[IP_ADDR_STR_LEN];
    uint16_t id;

    if (src == IP_ADDR_ANY)
    {
        errorf("invalid src");
        return -1;
    }
    else
    {
        /* Day2 Exercise 8-1: IPインタフェースの検索 */
        iface = ip_iface_select(src);
        if (!iface)
        {
            errorf("no interface");
            return -1;
        }
        /* Exercise 8-1 end*/

        /* Day2 Exercise 8-2: 宛先へ到達可能か確認 */
        if ((dst < (iface->unicast & iface->netmask) || dst > iface->broadcast) && dst != IP_ADDR_BROADCAST)
        {
            errorf("no route, netaddr=%s, brdcst=%s, dst=%s",
                   ip_addr_ntop(iface->unicast & iface->netmask, addr, sizeof(addr)),
                   ip_addr_ntop(iface->broadcast, addr2, sizeof(addr2)),
                   ip_addr_ntop(dst, addr3, sizeof(addr3)));
            return -1;
        }
        /* Exercise 8-2 end */
    }

    // フラグメンテーションは未実装
    if (NET_IFACE(iface)->dev->mtu < IP_HDR_SIZE_MIN + len)
    {
        errorf("too large, dev=%s, mtu=%u < %zu", NET_IFACE(iface)->dev->name, NET_IFACE(iface)->dev->mtu, IP_HDR_SIZE_MIN + len);
        return -1;
    }
    id = ip_generate_id();
    if (ip_output_core(iface, protocol, data, len, iface->unicast, dst, id, 0) == -1)
    {
        errorf("ip_output_core() failed");
        return -1;
    }
    return len;
}

int ip_init(void)
{
    if (net_protocol_register(NET_PROTOCOL_TYPE_IP, ip_input) == -1)
    {
        errorf("net_protocol_register() failure");
        return -1;
    }
    return 0;
}