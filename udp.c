#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "platform.h"

#include "util.h"
#include "ip.h"
#include "udp.h"

#define UDP_PCB_SIZE 16

#define UDP_PCB_STATE_FREE 0
#define UDP_PCB_STATE_OPEN 1
#define UDP_PCB_STATE_CLOSING 2

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

struct udp_pcb
{
    int state;
    struct ip_endpoint local;
    struct queue_head queue; /* receive queue */
};

/* PCBの受信キューエントリ*/
struct udp_queue_entry
{
    struct ip_endpoint foreign; // 送信元のアドレス&ポート番号
    uint16_t len;
    uint8_t data[];
};

static mutex_t mutex = MUTEX_INITIALIZER;
static struct udp_pcb pcbs[UDP_PCB_SIZE];

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

/*
 * UDP Protocol Control Block (PCB)
 */

static struct udp_pcb *
udp_pcb_alloc(void)
{
    struct udp_pcb *pcb;

    for (pcb = pcbs; pcb < tailof(pcbs); pcb++)
    {
        if (pcb->state == UDP_PCB_STATE_FREE)
        {
            pcb->state = UDP_PCB_STATE_OPEN;
            return pcb;
        }
    }
    return NULL;
}

static void
udp_pcb_release(struct udp_pcb *pcb)
{
    struct queue_entry *entry;

    pcb->state = UDP_PCB_STATE_FREE;
    pcb->local.addr = IP_ADDR_ANY;
    pcb->local.port = 0;
    while (1)
    {
        entry = queue_pop(&pcb->queue);
        if (!entry)
        {
            break;
        }
        memory_free(entry);
    }
}

static struct udp_pcb *
udp_pcb_select(ip_addr_t addr, uint16_t port)
{
    struct udp_pcb *pcb;
    for (pcb = pcbs; pcb < tailof(pcbs); pcb++)
    {
        if (pcb->state == UDP_PCB_STATE_OPEN)
        {
            if ((pcb->local.addr == IP_ADDR_ANY || addr == IP_ADDR_ANY || pcb->local.addr == addr) && pcb->local.port == port)
            {
                return pcb;
            }
        }
    }
    return NULL;
}

/*
 * PCBリストのインデックスでPCBを取得する
 */
static struct udp_pcb *
udp_pcb_get(int id)
{
    struct udp_pcb *pcb;

    if (id < 0 || id >= (int)countof(pcbs))
    {
        /* out of range */
        return NULL;
    }
    pcb = &pcbs[id];
    if (pcb->state != UDP_PCB_STATE_OPEN)
    {
        /* not open */
        return NULL;
    }
    return pcb;
}

/*
 * マッチするPCBのインデックスを取得する
 */
static int udp_pcb_id(struct udp_pcb *pcb)
{
    return indexof(pcbs, pcb);
}

static void
udp_input(const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst, struct ip_iface *iface)
{
    struct pseudo_hdr pseudo;
    uint16_t psum = 0;
    struct udp_hdr *hdr;
    char addr1[IP_ADDR_STR_LEN];
    char addr2[IP_ADDR_STR_LEN];
    struct udp_pcb *pcb;
    struct udp_queue_entry *entry;

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
    mutex_lock(&mutex);
    pcb = udp_pcb_select(dst, ntoh16(hdr->dst));
    if (!pcb)
    {
        mutex_unlock(&mutex);
        return;
    }
    /* Exercise 19-1: 受信キューへデータを格納 */
    // 受信キューエントリの大きさは受信キューメタデータ長さ + UDPペイロードの長さ
    // つまり、受信キューエントリの長さ(data[]は0?) + (UDP（ヘッダ+ペイロード）の長さ - UDPヘッダの長さ)
    entry = memory_alloc(sizeof(*entry) + len - sizeof(*hdr));
    entry->foreign.addr = src;
    entry->foreign.port = hton16(hdr->src);
    entry->len = len - sizeof(*hdr);
    memcpy(entry->data, hdr + 1, entry->len);
    queue_push(&pcb->queue, entry);
    /* Exercise 19-1 end */
    debugf("queue pushed: id=%d, num%d", udp_pcb_id(pcb), pcb->queue.num);
    mutex_unlock(&mutex);
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

/*
 * UDP User Commands
 */
int udp_open(void)
{
    /* Exercise 19-2: UDPソケットのオープン */
    struct udp_pcb *pcb;
    pcb = udp_pcb_alloc();
    if (!pcb)
    {
        errorf("udp_pcb_alloc() failure");
        return -1;
    }
    return udp_pcb_id(pcb);
    /* Exercise 19-2 end */
}

int udp_close(int id)
{
    /* Exercise 19-3: UDPソケットのクローズ */
    struct udp_pcb *pcb;
    pcb = udp_pcb_get(id);
    if (!pcb)
    {
        errorf("udp_pcb_get() failure");
        return -1;
    }
    udp_pcb_release(pcb);
    return 0;
    /* Exercise 19-3 end */
}

int udp_bind(int id, struct ip_endpoint *local)
{
    struct udp_pcb *pcb, *exist;
    char ep1[IP_ENDPOINT_STR_LEN];
    char ep2[IP_ENDPOINT_STR_LEN];

    mutex_lock(&mutex);
    /* Exercise 19-4: UDPソケットへアドレスとポート番号を紐づけ */
    pcb = udp_pcb_get(id);
    if (!pcb)
    {
        errorf("udp_pcb_get() failure");
        mutex_unlock(&mutex);
        return -1;
    }
    exist = udp_pcb_select(local->addr, local->port);
    if (exist)
    {
        errorf("already bound, id=%d, local=%s", udp_pcb_id(exist), ip_endpoint_ntop(&exist->local, ep2, sizeof(ep2)));
        mutex_unlock(&mutex);
        return -1;
    }
    pcb->local = *local;
    /* Exercise 19-4 end */
    debugf("bound, id=%d, local=%s", id, ip_endpoint_ntop(local, ep1, sizeof(ep1)));
    mutex_unlock(&mutex);
    return 0;
}