#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

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

static void
ip_input(const uint8_t *data, size_t len, struct net_device *dev)
{
    struct ip_hdr *hdr;
    uint8_t v;
    uint16_t hlen, total, offset, sum;

    if (len < IP_HDR_SIZE_MIN)
    {
        errorf("too short");
        return;
    }
    hdr = (struct ip_hdr *)data;

    /* DAY2 P14 Exercise 6-1: IPデータグラムの検証 */
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
    if (cksum16((uint16_t *)hdr, hlen << 2, 0) != 0)
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
    debugf("dev=%s, protocol=%u, total=%u", dev->name, hdr->protocol, total);
    ip_dump(data, total);
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