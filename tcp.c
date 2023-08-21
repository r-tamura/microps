#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "platform.h"

#include "util.h"
#include "ip.h"
#include "tcp.h"

#define TCP_FLG_FIN 0x01
#define TCP_FLG_SYN 0x02
#define TCP_FLG_RST 0x04
#define TCP_FLG_PSH 0x08
#define TCP_FLG_ACK 0x10
#define TCP_FLG_URG 0x20

#define TCP_FLG_BIT_MASK 0x3f // 6bit

#define TCP_FLG_IS(x, y) ((x & TCP_FLG_BIT_MASK) == (y))
#define TCP_FLG_ISSET(x, y) ((x & TCP_FLG_BIT_MASK) & (y) ? 1 : 0)

#define TCP_PCB_SIZE 16

#define TCP_PCB_STATE_FREE 0
#define TCP_PCB_STATE_CLOSED 1
#define TCP_PCB_STATE_LISTEN 2
#define TCP_PCB_STATE_SYN_SENT 3
#define TCP_PCB_STATE_SYN_RECEIVED 4
#define TCP_PCB_STATE_ESTABLISHED 5
#define TCP_PCB_STATE_FIN_WAIT1 6
#define TCP_PCB_STATE_FIN_WAIT2 7
#define TCP_PCB_STATE_CLOSING 8
#define TCP_PCB_STATE_TIME_WAIT 9
#define TCP_PCB_STATE_CLOSE_WAIT 10
#define TCP_PCB_STATE_LAST_ACK 11

struct pseudo_hdr
{
    uint32_t src;
    uint32_t dst;
    uint8_t zero;
    uint8_t proto;
    uint16_t len;
};

// TCPヘッダ
// TCPヘッダはオプションの数によって長さが変わるが、オプションなしとする
// [TCPヘッダとは](https://www.infraexpert.com/study/tcpip8.html)
struct tcp_hdr
{
    uint16_t src;
    uint16_t dst;
    uint32_t seq;
    uint32_t ack;
    // TCPヘッダ
    // 0         4          10       16
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // | Offset  |  Reserved.| Flags |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // 構造体上のヘッダ
    // 0        4        8        12       16
    // +--------+--------+--------+--------+
    // |       off       |       flg       |
    // +--------+--------+--------+--------+
    uint8_t off; // TCPヘッダの長さ 32bit単位
    uint8_t flg;
    uint16_t wnd;
    uint16_t sum;
    uint16_t up;
};

struct tcp_segment_info
{
    uint32_t seq;
    uint32_t ack;
    uint16_t len;
    uint16_t wnd;
    uint16_t up;
};

struct tcp_pcb
{
    int state; // コネクション状態
    struct ip_endpoint local;
    struct ip_endpoint foreign;
    // 送信時に使う情報
    struct
    {
        uint32_t nxt;
        uint32_t una;
        uint32_t wnd;
        uint16_t up;
        uint32_t wl1;
        uint32_t wl2;
    } snd;
    uint32_t iss; // 初期シーケンス番号
    // 受信時に使う情報
    struct
    {
        uint32_t nxt;
        uint16_t wnd;
        uint16_t up;
    } rcv;
    uint32_t irs;
    uint16_t mtu;
    uint16_t mss;
    uint8_t buf[65535]; // receive buffer
    struct sched_ctx ctx;
};

static mutex_t mutex = MUTEX_INITIALIZER;
static struct tcp_pcb pcbs[TCP_PCB_SIZE];

static char *
tcp_flg_ntoa(uint8_t flg)
{
    static char str[9];
    snprintf(str, sizeof(str), "--%c%c%c%c%c%c",
             TCP_FLG_ISSET(flg, TCP_FLG_URG) ? 'U' : '-',
             TCP_FLG_ISSET(flg, TCP_FLG_ACK) ? 'A' : '-',
             TCP_FLG_ISSET(flg, TCP_FLG_PSH) ? 'P' : '-',
             TCP_FLG_ISSET(flg, TCP_FLG_RST) ? 'R' : '-',
             TCP_FLG_ISSET(flg, TCP_FLG_SYN) ? 'S' : '-',
             TCP_FLG_ISSET(flg, TCP_FLG_FIN) ? 'F' : '-');
    return str;
}

static void
tcp_dump(const uint8_t *data, size_t len)
{
    struct tcp_hdr *hdr;

    flockfile(stderr);
    hdr = (struct tcp_hdr *)data;
    fprintf(stderr, "        src: %u\n", ntoh16(hdr->src));
    fprintf(stderr, "        dst: %u\n", ntoh16(hdr->dst));
    fprintf(stderr, "        seq: %u\n", ntoh32(hdr->seq));
    fprintf(stderr, "        ack: %u\n", ntoh32(hdr->ack));
    fprintf(stderr, "        off: 0x%02x (%d)\n", hdr->off, (hdr->off >> 4) << 2);
    fprintf(stderr, "        flg: 0x%02x (%s)\n", hdr->flg, tcp_flg_ntoa(hdr->flg));
    fprintf(stderr, "        wnd: %u\n", ntoh16(hdr->wnd));
    fprintf(stderr, "        sum: 0x%04x\n", ntoh16(hdr->sum));
    fprintf(stderr, "         up: %u\n", ntoh16(hdr->up));
#ifdef HEXDUMP
    hexdump(stderr, data, len);
#endif
    funlockfile(stderr);
}

/*
 * TCP Protocol Control Block (PCB)
 */

static struct tcp_pcb *
tcp_pcb_alloc(void)
{
    struct tcp_pcb *pcb;

    for (pcb = pcbs; pcb < tailof(pcbs); pcb++)
    {
        if (pcb->state == TCP_PCB_STATE_FREE)
        {
            pcb->state = TCP_PCB_STATE_CLOSED;
            sched_ctx_init(&pcb->ctx);
            return pcb;
        }
    }
    return NULL;
}

static void
tcp_pcb_release(struct tcp_pcb *pcb)
{
    char ep1[IP_ENDPOINT_STR_LEN];
    char ep2[IP_ENDPOINT_STR_LEN];

    // PCP利用中のタスクが存在する場合は、すぐに解放できない
    // 他のタスクの待ちを解除して、解放をまかせる
    if (sched_ctx_destroy(&pcb->ctx) == -1)
    {
        sched_wakeup(&pcb->ctx);
        return;
    }
    debugf("released, local=%s, foreign=%s",
           ip_endpoint_ntop(&pcb->local, ep1, sizeof(ep1)),
           ip_endpoint_ntop(&pcb->foreign, ep2, sizeof(ep2)));
    memset(pcb, 0, sizeof(*pcb));
}

/*
 * 送信元と送信先のペアからPCBを検索する
 */
static struct tcp_pcb *
tcp_pcb_select(struct ip_endpoint *local, struct ip_endpoint *foreign)
{
    struct tcp_pcb *pcb, *listen_pcb = NULL;
    for (pcb = pcbs; pcb < tailof(pcbs); pcb++)
    {
        if ((pcb->local.addr == IP_ADDR_ANY || pcb->local.addr == local->addr) && pcb->local.port == local->port)
        {
            // ローカルアドレスにbind可能かを調べるとき
            if (!foreign)
            {
                return pcb;
            }
            if (pcb->foreign.addr == foreign->addr && pcb->foreign.addr == foreign->addr)
            {
                return pcb;
            }
            // PCBがLISTENしているときは、foreignが指定なし(0.0.0.0:0)
            if (pcb->state == TCP_PCB_STATE_LISTEN)
            {
                if (pcb->foreign.addr == IP_ADDR_ANY && pcb->foreign.port == 0)
                {
                    listen_pcb = pcb;
                }
            }
        }
    }
    return listen_pcb;
}

/*
 * PCB IDでPCBを検索する
 */
static struct tcp_pcb *
tcp_pcb_get(int id)
{
    struct tcp_pcb *pcb;

    if (id < 0 || id >= TCP_PCB_SIZE)
    {
        return NULL;
    }
    pcb = &pcbs[id];
    if (pcb->state == TCP_PCB_STATE_FREE)
    {
        return NULL;
    }
    return pcb;
}

/*
 * 指定されたPCBのIDを取得する
 */
static int
tcp_pcb_id(struct tcp_pcb *pcb)
{
    return indexof(pcbs, pcb);
}

/*
 * TCPセグメントの組み立てと送信
 *
 * data: TCPペイロードデータ
 * len: TCPペイロードデータの長さ
 */
static ssize_t
tcp_output_segment(uint32_t seq, uint32_t ack, uint8_t flg, uint16_t wnd, uint8_t *data, size_t len,
                   struct ip_endpoint *local, struct ip_endpoint *foreign)
{
    uint8_t buf[IP_PAYLOAD_SIZE_MAX] = {};
    struct tcp_hdr *hdr;
    struct pseudo_hdr pseudo;
    uint16_t psum;
    uint16_t total;
    char ep1[IP_ENDPOINT_STR_LEN];
    char ep2[IP_ENDPOINT_STR_LEN];

    hdr = (struct tcp_hdr *)buf;
    /* Exercise 23-1: TCPセグメントの生成 */
    pseudo.src = local->addr;
    pseudo.dst = foreign->addr;
    pseudo.zero = 0;
    pseudo.proto = IP_PROTOCOL_TCP;
    pseudo.len = hton16(sizeof(*hdr) + len);

    hdr->src = local->port;
    hdr->dst = foreign->port;
    hdr->seq = hton32(seq);
    hdr->ack = hton32(ack);
    hdr->off = (sizeof(*hdr) >> 2) << 4; // オプションなしとするので固定長
    hdr->flg = flg & TCP_FLG_BIT_MASK;
    hdr->wnd = hton16(wnd);
    hdr->sum = 0;
    hdr->up = 0;
    memcpy(hdr + 1, data, len);
    total = sizeof(*hdr) + len;
    psum = ~cksum16((uint16_t *)&pseudo, sizeof(pseudo), 0);
    hdr->sum = cksum16((uint16_t *)buf, total, psum);
    /* Exercise 23-1 end */
    debugf("%s => %s, len=%zu (payload=%zu)",
           ip_endpoint_ntop(local, ep1, sizeof(ep1)),
           ip_endpoint_ntop(foreign, ep2, sizeof(ep2)),
           total,
           len);
    tcp_dump(buf, total);
    /* Exercise 23-2: IPの送信関数を呼び出す */
    ip_output(IP_PROTOCOL_TCP, buf, total, local->addr, foreign->addr);
    /* Exercise 23-2 end */
    return len;
}

static ssize_t
tcp_output(struct tcp_pcb *pcb, uint8_t flg, uint8_t *data, size_t len)
{
    uint32_t seq;

    seq = pcb->snd.nxt;
    // 初回送信時は初期シーケンス番号を利用
    if (TCP_FLG_ISSET(flg, TCP_FLG_SYN))
    {
        seq = pcb->iss;
    }
    if (TCP_FLG_ISSET(flg, TCP_FLG_SYN | TCP_FLG_FIN) || len)
    {
        /* TODO: retransmission queue */
    }
    return tcp_output_segment(seq, pcb->rcv.nxt, flg, pcb->rcv.wnd, data, len,
                              &pcb->local, &pcb->foreign);
}

/* rfc793 - section 3.9 [Event Processing > SEGMENT ARRIVES] */
static void
tcp_segment_arrives(struct tcp_segment_info *seg, uint8_t flags, uint8_t *data, size_t len,
                    struct ip_endpoint *local, struct ip_endpoint *foreign)
{
    struct tcp_pcb *pcb;

    pcb = tcp_pcb_select(local, foreign);
    // 使用していないポートでデータを受信したらRSTを返す
    if (!pcb || pcb->state == TCP_PCB_STATE_CLOSED)
    {
        if (TCP_FLG_ISSET(flags, TCP_FLG_RST))
        {
            return;
        }
        if (!TCP_FLG_ISSET(flags, TCP_FLG_ACK))
        {
            tcp_output_segment(0, seg->seq + seg->len, TCP_FLG_RST | TCP_FLG_ACK,
                               0, NULL, 0, local, foreign);
        }
        else
        {
            tcp_output_segment(seg->ack, 0, TCP_FLG_RST, 0, NULL, 0, local, foreign);
        }
        return;
    }
}

/*
 * IP受信処理から呼ばれるTCP受信処理
 * 引数にIP層で解釈された情報は受け取れる
 *
 * data: TCPヘッダ + TCPペイロード
 */
static void
tcp_input(const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst, struct ip_iface *iface)
{
    struct tcp_hdr *hdr;
    struct pseudo_hdr pseudo;
    uint16_t psum;
    struct ip_endpoint local, foreign;
    uint16_t hlen;
    struct tcp_segment_info seg;
    char addr1[IP_ADDR_STR_LEN];
    char addr2[IP_ADDR_STR_LEN];

    if (len < sizeof(*hdr))
    {
        errorf("too short");
        return;
    }
    hdr = (struct tcp_hdr *)data;
    /* Exercise 22-3: チェックサムの検証 */
    pseudo.src = src;
    pseudo.dst = dst;
    pseudo.zero = 0;
    pseudo.proto = IP_PROTOCOL_TCP;
    pseudo.len = hton16(len);
    psum = ~cksum16((uint16_t *)&pseudo, sizeof(pseudo), 0);
    if (cksum16((uint16_t *)data, len, psum) != 0)
    {
        errorf("checksum error");
        return;
    }
    /* Exercise 22-3 end */
    /* Exercise 22-4: アドレスのチェック */
    if ((src == IP_ADDR_BROADCAST || src == iface->broadcast) && (dst == IP_ADDR_BROADCAST || dst == iface->broadcast))
    {
        errorf("invalid address");
        return;
    }
    /* Exercise 22-4 end */
    debugf("%s:%d => %s:%d, len=%zu (payload=%zu)",
           ip_addr_ntop(src, addr1, sizeof(addr1)),
           ntoh16(hdr->src),
           ip_addr_ntop(dst, addr2, sizeof(addr2)),
           ntoh16(hdr->dst),
           len,
           len - sizeof(*hdr));
    tcp_dump(data, len);
    // Note: 元実装ではip_endpointのaddrが
    local.addr = dst;
    local.port = hdr->dst;
    foreign.addr = src;
    foreign.port = hdr->src;
    hlen = (hdr->off >> 4) << 2;
    /* tcp_segment_arrives()で利用する情報 */
    seg.seq = ntoh32(hdr->seq);
    seg.ack = ntoh32(hdr->ack);
    seg.len = len - hlen;
    if (TCP_FLG_ISSET(hdr->flg, TCP_FLG_SYN))
    {
        // SYN flag consumes one sequence number
        seg.len++;
    }
    if (TCP_FLG_ISSET(hdr->flg, TCP_FLG_FIN))
    {
        // FIN flag consumes one sequence number
        seg.len++;
    }
    seg.wnd = ntoh16(hdr->wnd);
    seg.up = ntoh16(hdr->up);
    mutex_lock(&mutex);
    tcp_segment_arrives(&seg, hdr->flg, (uint8_t *)hdr + hlen, len - hlen, &local, &foreign);
    mutex_unlock(&mutex);
    return;
}

int tcp_init(void)
{
    /* Exercise 22-1: IPの上位プロトコルとしてTCPを登録する */
    if (ip_protocol_register(IP_PROTOCOL_TCP, tcp_input) == -1)
    {
        errorf("ip_protocol_register() failure");
        return -1;
    }
    /* Exercise 22-1 end */
    return 0;
}