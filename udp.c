#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "util.h"
#include "ip.h"
#include "udp.h"

struct pseudo_hdr
{
    uint32_t src;
    uint32_t dst;
    uint8_t zero;
    uint8_t proto;
    uint16_t len;
};

struct udp_hdr
{
    uint16_t src;
    uint16_t dst;
    uint16_t len;
    uint16_t sum;
};

static void
udp_dump(const uint8_t *data, size_t len)
{
    struct udp_hdr *hdr;

    flockfile(stderr);
    hdr = (struct udp_hdr *)data;
    fprintf(stderr, "        src: %u\n", ntoh16(hdr->src));
    fprintf(stderr, "        dst: %u\n", ntoh16(hdr->dst));
    fprintf(stderr, "        len: %u\n", ntoh16(hdr->len));
    fprintf(stderr, "        sum: 0x%04x\n", ntoh16(hdr->sum));
#ifdef HEXDUMP
    haxdump(strerr, data, len);
#endif
    funlockfile(stderr);
}

static void
udp_input(const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst, struct ip_iface *iface)
{
    struct pseudo_hdr pseudo;
    uint16_t psum = 0;
    struct udp_hdr *hdr;
    char addr1[IP_ADDR_STR_LEN];
    char addr2[IP_ADDR_STR_LEN];

    if (len < sizeof(*hdr))
    {
        debugf("too short");
        return;
    }
    hdr = (struct udp_hdr *)data;
    if (len != ntoh16(hdr->len))
    {
        errorf("length error: len=%zu, hdr->len=%u", len, ntoh16(hdr->len));
        return;
    }
    // UDPのチェックサム計算は疑似ヘッダを含めて行う（送信元と宛先を含めて整合性を検証するため）
    pseudo.src = src;
    pseudo.dst = dst;
    pseudo.zero = 0;
    pseudo.proto = IP_PROTOCOL_UDP;
    pseudo.len = hton16(len);
    // cksum16は最後にビット反転を行うが、疑似ヘッダはチェックサムは全体の途中なのでビットを戻す
    psum = ~cksum16((uint16_t *)&pseudo, sizeof(pseudo), 0);
    if (cksum16((uint16_t *)hdr, len, psum) != 0)
    {
        errorf("checksum error: sum=0x%04x, verify=x04x",
               ntoh16(hdr->sum),
               ntoh16(cksum16((uint16_t *)hdr, len, ~hdr->sum + psum)));
        return;
    }
    debugf("%s:%d => %s:%d, len=%zu, payload=%zu",
           ip_addr_ntop(src, addr1, sizeof(addr1)), ntoh16(hdr->src),
           ip_addr_ntop(dst, addr2, sizeof(addr2)), ntoh16(hdr->dst),
           len, len - sizeof(*hdr));
    udp_dump(data, len);
}

ssize_t
udp_output(struct ip_endpoint *src, struct ip_endpoint *dst, const uint8_t *data, size_t len)
{
    uint8_t buf[IP_PAYLOAD_SIZE_MAX];
    struct udp_hdr *hdr;
    struct pseudo_hdr pseudo;
    uint16_t total, psum = 0;
    char ep1[IP_ENDPOINT_STR_LEN];
    char ep2[IP_ENDPOINT_STR_LEN];

    if (len > IP_PAYLOAD_SIZE_MAX - sizeof(*hdr))
    {
        errorf("too large payload: len=%zu", len);
        return -1;
    }
    hdr = (struct udp_hdr *)buf;

    /* Exercise 18-1: UDPデータグラムの生成 */
    pseudo.src = src->addr;
    pseudo.dst = dst->addr;
    pseudo.zero = 0;
    pseudo.proto = IP_PROTOCOL_UDP;
    total = len + sizeof(*hdr);
    pseudo.len = ntoh16(total);

    hdr->src = ntoh16(src->port);
    hdr->dst = ntoh16(dst->port);
    hdr->len = ntoh16(total);
    hdr->sum = 0;
    memcpy(hdr + 1, data, len);

    psum = ~cksum16((uint16_t *)&pseudo, sizeof(pseudo), 0);
    hdr->sum = cksum16((uint16_t *)buf, total, psum);

    /* Exercise 18-1 end */
    debugf("%s => %s, len=%zu, payload=%zu",
           ip_endpoint_ntop(src, ep1, sizeof(ep1)),
           ip_endpoint_ntop(dst, ep2, sizeof(ep2)),
           total, len);
    udp_dump((uint8_t *)hdr, sizeof(*hdr));

    /* Exercise 18-2: IPの送信関数を呼び出す */
    if (ip_output(IP_PROTOCOL_UDP, buf, total, src->addr, dst->addr) == -1)
    {
        errorf("ip_output() failure");
        return -1;
    };
    /* Exercise 18-2 end */
    return len;
}

int udp_init(void)
{
    /* Exercise 18-3: IPの上位プロトコルとしてUDPを登録する */
    if (ip_protocol_register(IP_PROTOCOL_UDP, udp_input) == -1)
    {
        errorf("ip_protocol_register() failure");
        return -1;
    }
    /* Exercise 18-3 end */
    return 0;
}