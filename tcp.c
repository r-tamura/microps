#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <errno.h>

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

#define TCP_DEFAULT_RTO_MICROSEC 200000
#define TCP_RETRANSMISSION_DEATLINES_SEC 12

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
    uint16_t len; // TCPペイロード長
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
        uint32_t nxt; // 次回送信時のシーケンス番号
        uint32_t una; // 未確認のシーケンス番号 unacknowledged
        uint32_t wnd; // 送信ウィンドウサイズ(相手から送られてきたセグメントに指定された値)
        uint16_t up;
        uint32_t wl1; // 前回のウィンドウサイズ変更時のシーケンス番号
        uint32_t wl2; // 前回のウィンドウサイズ変更時のACK番号
    } snd;
    uint32_t iss; // 初期シーケンス番号 initial send sequence number
    // 受信時に使う情報
    struct
    {
        uint32_t nxt;
        uint16_t wnd;
        uint16_t up;
    } rcv;
    uint32_t irs; // initial receive sequence number
    uint16_t mtu;
    uint16_t mss;
    uint8_t buf[65535]; // receive buffer
    struct sched_ctx ctx;
    struct queue_head queue; // retransmission queue
};

struct tcp_queue_entry
{
    struct timeval first; // 初回送信時刻
    struct timeval last;  // 最終（前回）の送信時刻
    unsigned int rto;     // micro seconds (retransmission timeout)

    uint32_t seq; // セグメントのシーケンス番号
    uint8_t flg;  // セグメントの制御フラグ
    // その他情報は再送時にPCBから取得する

    size_t len;
    uint8_t data[];
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
    char ep1[IP_ENDPOINT_STR_LEN];
    char ep2[IP_ENDPOINT_STR_LEN];
    debugf("finding PCB, local=%s, foreign=%s",
           ip_endpoint_ntop(local, ep1, sizeof(ep1)),
           ip_endpoint_ntop(foreign, ep2, sizeof(ep2)));
    for (pcb = pcbs; pcb < tailof(pcbs); pcb++)
    {
        if ((pcb->local.addr == IP_ADDR_ANY || pcb->local.addr == local->addr) && pcb->local.port == local->port)
        {
            debugf("found");
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
                    debugf("updated listen pcb");
                    listen_pcb = pcb;
                }
            }
        }
    }
    debugf("listen pcb");
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

/*
 * TCP Retransmission
 * NOTE: TCP Retransmission funcsions must be called after mutex locked
 */

static int
tcp_retransmit_queue_add(struct tcp_pcb *pcb, uint32_t seq, uint8_t flg, uint8_t *data, size_t len)
{
    struct tcp_queue_entry *entry;

    entry = memory_alloc(sizeof(*entry) + len);
    if (!entry)
    {
        errorf("memory_alloc() failure");
        return -1;
    }
    entry->rto = TCP_DEFAULT_RTO_MICROSEC;
    entry->seq = seq;
    entry->flg = flg;
    entry->len = len;
    memcpy(entry->data, data, entry->len);
    gettimeofday(&entry->first, NULL);
    entry->last = entry->first;
    if (!queue_push(&pcb->queue, entry))
    {
        errorf("queue_push() failure");
        memory_free(entry);
        return -1;
    }
    return 0;
}

static void
tcp_retransmit_queue_cleanup(struct tcp_pcb *pcb)
{
    struct tcp_queue_entry *entry;

    while (1)
    {
        entry = queue_peek(&pcb->queue);
        if (!entry)
        {
            break;
        }
        // ACKの応答が得られていなかった削除しない
        if (entry->seq >= pcb->snd.una)
        {
            break;
        }
        entry = queue_pop(&pcb->queue);
        debugf("remove, seq=%u, flags=%s, len=%u", entry->seq, tcp_flg_ntoa(entry->flg), entry->len);
        memory_free(entry);
    }
    return;
}

static void
tcp_retransmit_queue_emit(void *arg, void *data)
{
    struct tcp_pcb *pcb;
    struct tcp_queue_entry *entry;
    struct timeval now, diff, timeout;

    pcb = (struct tcp_pcb *)arg;
    entry = (struct tcp_queue_entry *)data;
    gettimeofday(&now, NULL);
    timersub(&now, &entry->first, &diff); // 初回送信時からの経過時間
    // タイムアウトを超えていたらコネクションを破棄
    if (diff.tv_sec >= TCP_RETRANSMISSION_DEATLINES_SEC)
    {
        pcb->state = TCP_PCB_STATE_CLOSED;
        sched_wakeup(&pcb->ctx);
        return;
    }
    timeout = entry->last;
    timeval_add_usec(&timeout, entry->rto); // 再送時刻の計算
    // 再送時刻を超えていたら再送
    if (timercmp(&now, &timeout, >))
    {
        tcp_output_segment(entry->seq, pcb->rcv.nxt, entry->flg, pcb->rcv.wnd, entry->data, entry->len,
                           &pcb->local, &pcb->foreign);
        entry->last = now;
        entry->rto *= 2; // exponential backoff
    }
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
    // シーケンス番号が増加するセグメントのみ再送キューへ格納（単純なACKやRSTセグメントは除外）
    if (TCP_FLG_ISSET(flg, TCP_FLG_SYN | TCP_FLG_FIN) || len)
    {
        tcp_retransmit_queue_add(pcb, seq, flg, data, len);
    }
    return tcp_output_segment(seq, pcb->rcv.nxt, flg, pcb->rcv.wnd, data, len,
                              &pcb->local, &pcb->foreign);
}

/*
 * TCPデータを受信したときに現在の状態と受信データから次の状態を決定し、必要なアクションを実行する
 */
/* rfc793 - section 3.9 [Event Processing > SEGMENT ARRIVES] */
static void
tcp_segment_arrives(struct tcp_segment_info *seg, uint8_t flags, uint8_t *data, size_t len,
                    struct ip_endpoint *local, struct ip_endpoint *foreign)
{
    struct tcp_pcb *pcb;
    int acceptable = 0;

    pcb = tcp_pcb_select(local, foreign);
    // 使用していないポートでデータを受信したらRSTを返す
    debugf("state=%d", pcb->state);
    if (!pcb || pcb->state == TCP_PCB_STATE_CLOSED)
    {
        warnf("unexpected segment");
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

    // [RFC 793 - Transmission Control Protocol](https://datatracker.ietf.org/doc/html/rfc793#section-3.9)
    // P65-67
    switch (pcb->state)
    {
    case TCP_PCB_STATE_LISTEN:
        /*
         * 1st check for an RST
         */
        if (TCP_FLG_ISSET(flags, TCP_FLG_RST))
        {
            return;
        }
        /*
         * 2nd check for an ACK
         * LISTEN状態でACKを受け取るのは間違いなので、RSTを返す
         */
        if (TCP_FLG_ISSET(flags, TCP_FLG_ACK))
        {
            warnf("unexpected ACK");
            tcp_output_segment(seg->ack, 0, TCP_FLG_RST, 0, NULL, 0, local, foreign);
        }

        /*
         * 3rd check for a SYN
         * SYN+ACKを返す
         */
        if (TCP_FLG_ISSET(flags, TCP_FLG_SYN))
        {
            // ignore: security/compartment check
            // ignore: precedence check
            pcb->local = *local;
            pcb->foreign = *foreign;
            pcb->rcv.wnd = sizeof(pcb->buf);
            pcb->rcv.nxt = seg->seq + 1;                         // 次に受信を期待するシーケンス番号(ACKで使われる)
            pcb->irs = seg->seq;                                 // 初期受信シーケンス番号の保存
            pcb->iss = random();                                 // 初期受信シーケンス番号の裁判
            tcp_output(pcb, TCP_FLG_SYN | TCP_FLG_ACK, NULL, 0); // SYN+ACK送信
            pcb->snd.nxt = pcb->iss + 1;                         // 次に送信するシーケンス番号
            pcb->snd.una = pcb->iss;                             // 未確認の送信シーケンス番号
            pcb->state = TCP_PCB_STATE_SYN_RECEIVED;
            // ignore: Note that any other incoming control or data
            // (combined with SYN) will be processed in the SYN-RECEIVED state,
            // but processing of SYN and ACK should not be repeated.
            return;
        }
        /*
         * 4th other text or control
         */
        /* drop segment */
        return;
    case TCP_PCB_STATE_SYN_SENT:
        /*
         * 1st check the ACK bit
         */
        if (TCP_FLG_ISSET(flags, TCP_FLG_ACK))
        {
            if (seg->ack <= pcb->iss || seg->ack > pcb->snd.nxt)
            {
                tcp_output_segment(seg->ack, 0, TCP_FLG_RST, 0, NULL, 0, local, foreign);
                return;
            }
            // o -----snd.una-----(seg->ack)----snd.nxt------> // 相手に受信されたことが未確認なデータに対するACKはacceptable
            // x -----(seg->ack)----snd.una----snd.nxt-------> // ACK済みのデータに対するACKはnot acceptable
            // x -----snd.una----->snd.nxt-----(seg->ack)----> // 送ってもないデータに対するACKはnot acceptable
            if (pcb->snd.una <= seg->ack && seg->ack <= pcb->snd.nxt)
            {
                acceptable = 1;
            }
        }
        /*
         * 2nd check the RST bit
         */
        /*
         * 3rd check sucurity and precedence (ignore)
         */
        /*
         * 4th check the SYN bit
         * SYN or SYN+ACKを受信した場合
         */
        if (TCP_FLG_ISSET(flags, TCP_FLG_SYN))
        {
            pcb->rcv.nxt = seg->seq + 1;
            pcb->irs = seg->seq;
            if (acceptable)
            {
                // ACK番号は送信者が次に要求しているシーケンス番号なので、ACK番号のセグメントは確認が取れていない
                pcb->snd.una = seg->ack;
                tcp_retransmit_queue_cleanup(pcb);
            }
            if (pcb->snd.una > pcb->iss)
            {
                // こちらのSYNに対するSYN+ACK受信したとき
                pcb->state = TCP_PCB_STATE_ESTABLISHED;
                tcp_output(pcb, TCP_FLG_ACK, NULL, 0); // 相手のSYNに対するACK
                // NOTE: not sepecified in the RFC793, but send window initialization requried
                pcb->snd.wnd = seg->wnd;
                pcb->snd.wl1 = seg->seq;
                pcb->snd.wl2 = seg->ack;
                sched_wakeup(&pcb->ctx);
                // ignore: continue processing at the sixth step below where the URG bit is checked
                return;
            }
            else
            {
                // すれちがいで相手もSYNを送信したとき
                // こちらがゆずって最初のSYNを取り消すような対応
                pcb->state = TCP_PCB_STATE_SYN_RECEIVED;
                tcp_output(pcb, TCP_FLG_SYN | TCP_FLG_ACK, NULL, 0);
                /* ignore: If there are other controls or text in the segment, queue them for processing after the ESTABLISHED state has been reached */
                return;
            }
        }
        /*
         * 5th if neither of the SYN or RST bits is set then drop the segment and return
         */
        /* drop segment */
        return;
    }

    /*
     * Otherwise
     */

    /*
     * 1st check sequence number
     * RFC793 P69
     */
    switch (pcb->state)
    {
    case TCP_PCB_STATE_SYN_RECEIVED:
    case TCP_PCB_STATE_ESTABLISHED:
        // 受信したセグメントが処理継続可能かどうかの判断をし、処理継続可能でない場合はACKを返す(受信したセグメントがRSTを含む場合は除く)
        // ペイロードのありなしで分岐
        if (!seg->len)
        {
            if (!pcb->rcv.wnd)
            {
                if (seg->seq == pcb->rcv.nxt)
                {
                    acceptable = 1;
                }
            }
            else
            {
                if (pcb->rcv.nxt <= seg->seq && seg->seq < pcb->rcv.nxt + pcb->rcv.wnd)
                {
                    acceptable = 1;
                }
            }
        }
        else
        {
            if (!pcb->rcv.wnd)
            {
                // not acceptable
            }
            else
            {
                if ((pcb->rcv.nxt <= seg->seq && seg->seq < pcb->rcv.nxt + pcb->rcv.wnd) ||
                    (pcb->rcv.nxt <= seg->seq + seg->len - 1 && seg->seq + seg->len - 1 < pcb->rcv.nxt + pcb->rcv.wnd))
                {
                    acceptable = 1;
                }
            }
        }
        if (!acceptable)
        {
            if (!TCP_FLG_ISSET(flags, TCP_FLG_RST))
            {
                tcp_output(pcb, TCP_FLG_ACK, NULL, 0);
            }
            return;
        }
    }

    /*
     * 2nd check the RST bit
     */

    /*
     * 3rd check security and precedence (ignore)
     */

    /*
     * 4th check the SYN bit
     */

    /*
     * 5th check the ACK field
     */
    if (!TCP_FLG_ISSET(flags, TCP_FLG_ACK))
    {
        /* drop segment */
        return;
    }
    switch (pcb->state)
    {
    case TCP_PCB_STATE_SYN_RECEIVED:
        // まだACKを受け取っていない送信データに対するACKかどうかの判断
        // seg->ack <= pcb->snd.nxt: 次に送ろうとしている（まだ送ってない）番号のACKが来るのはおかしい
        if (pcb->snd.una <= seg->ack && seg->ack <= pcb->snd.nxt)
        {
            pcb->state = TCP_PCB_STATE_ESTABLISHED;
            sched_wakeup(&pcb->ctx);
        }
        else
        {
            warnf("invalid ACK");
            tcp_output_segment(seg->ack, 0, TCP_FLG_RST, 0, NULL, 0, local, foreign);
            return;
        }
        // fall through
    case TCP_PCB_STATE_ESTABLISHED:
        // まだACKを受け取っていない送信データに対するACKかどうかの判断
        if (pcb->snd.una < seg->ack && seg->ack <= pcb->snd.nxt)
        {
            pcb->snd.una = seg->ack;
            tcp_retransmit_queue_cleanup(pcb); // 受信の確認が取れたら再送キューから削除
            /* ignore: Users should receive positive acknowledgments for buffers
            　　which have been SENT and fully acknowledged (i.e., SEND buffer should be returned with "ok" response) */
            if (pcb->snd.wl1 < seg->seq || (pcb->snd.wl1 == seg->seq && pcb->snd.wl2 <= seg->ack))
            {
                // ウィンドウサイズ更新
                pcb->snd.wnd = seg->wnd;
                pcb->snd.wl1 = seg->seq;
                pcb->snd.wl2 = seg->ack;
            }
        }
        else if (seg->ack < pcb->snd.una)
        {
            // 確認済みのACK
        }
        else if (seg->ack > pcb->snd.nxt)
        {
            // 範囲外のACK
            tcp_output(pcb, TCP_FLG_ACK, NULL, 0);
            return;
        }
        break;
    }

    /*
     * 6th, check the URG bit (ignore)
     */

    /*
     * 7th, process the segment text
     */
    switch (pcb->state)
    {
    case TCP_PCB_STATE_ESTABLISHED:
        // 受信データをバッファにコピーしてACKを返す
        // seg.len = len
        if (len)
        {
            memcpy(pcb->buf + (sizeof(pcb->buf) - pcb->rcv.wnd), data, len);
            pcb->rcv.nxt = seg->seq + seg->len;
            // バッファにたまっているデータが処理されるまではその分だけウィンドウサイズを減らす
            pcb->rcv.wnd -= len;
            tcp_output(pcb, TCP_FLG_ACK, NULL, 0);
            sched_wakeup(&pcb->ctx);
        }
        break;
    }

    /*
     * 8th, check the FIN bit
     */

    return;
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

static void
event_handler(void *arg)
{
    struct tcp_pcb *pcb;

    mutex_lock(&mutex);
    for (pcb = pcbs; pcb <= tailof(pcbs); pcb++)
    {
        if (pcb->state != TCP_PCB_STATE_FREE)
        {
            sched_interrupt(&pcb->ctx);
        }
    }
    mutex_unlock(&mutex);
}

/*
 * 受信キューのすべてのエントリに対して再送処理を行う
 */
static void
tcp_timer(void)
{
    struct tcp_pcb *pcb;
    mutex_lock(&mutex);
    for (pcb = pcbs; pcb < tailof(pcbs); pcb++)
    {
        if (pcb->state == TCP_PCB_STATE_FREE)
        {
            continue;
        }
        queue_foreach(&pcb->queue, tcp_retransmit_queue_emit, pcb);
    }
    mutex_unlock(&mutex);
}

int tcp_init(void)
{
    struct timeval interval = {0, 100000};
    /* Exercise 22-1: IPの上位プロトコルとしてTCPを登録する */
    if (ip_protocol_register(IP_PROTOCOL_TCP, tcp_input) == -1)
    {
        errorf("ip_protocol_register() failure");
        return -1;
    }
    /* Exercise 22-1 end */
    net_event_subscribe(event_handler, NULL);
    if (net_timer_register(interval, tcp_timer) == -1)
    {
        errorf("net_timer_register() failure");
        return -1;
    }
    return 0;
}

int tcp_open_rfc793(struct ip_endpoint *local, struct ip_endpoint *foreign, int active)
{
    struct tcp_pcb *pcb;
    char ep1[IP_ENDPOINT_STR_LEN];
    char ep2[IP_ENDPOINT_STR_LEN];
    int state, id;
    mutex_lock(&mutex);
    pcb = tcp_pcb_alloc();
    if (!pcb)
    {
        errorf("tcp_pcb_alloc() failure");
        mutex_unlock(&mutex);
        return -1;
    }
    if (active)
    {
        debugf("active open: local=%s, foreign=%s, connecting...",
               ip_endpoint_ntop(local, ep1, sizeof(ep1)),
               ip_endpoint_ntop(foreign, ep2, sizeof(ep2)));
        pcb->local = *local;
        pcb->foreign = *foreign;
        pcb->rcv.wnd = sizeof(pcb->buf); // 初期受信ウィンドうサイズは受信バッファの最大サイズ
        pcb->iss = random();
        if (tcp_output(pcb, TCP_FLG_SYN, NULL, 0) == -1)
        {
            errorf("tcp_output() failure");
            pcb->state = TCP_PCB_STATE_CLOSED;
            tcp_pcb_release(pcb);
            mutex_unlock(&mutex);
            return -1;
        }
        pcb->snd.nxt = pcb->iss;
        pcb->snd.nxt = pcb->iss + 1;
        pcb->state = TCP_PCB_STATE_SYN_SENT;
    }
    else
    {
        debugf("passive open: local=%s waiting for connection...", ip_endpoint_ntop(local, ep1, sizeof(ep1)));
        pcb->local = *local;
        if (foreign)
        {
            pcb->foreign = *foreign;
        }
        pcb->state = TCP_PCB_STATE_LISTEN;
    }

AGAIN:
    state = pcb->state;
    // stateが変わるのを待つ
    while (pcb->state == state)
    {
        if (sched_sleep(&pcb->ctx, &mutex, NULL) == -1)
        {
            debugf("interrupted");
            pcb->state = TCP_PCB_STATE_CLOSED;
            tcp_pcb_release(pcb);
            mutex_unlock(&mutex);
            errno = EINTR;
            return -1;
        }
    }
    if (pcb->state != TCP_PCB_STATE_ESTABLISHED)
    {
        // ハンドシェイク中
        if (pcb->state == TCP_PCB_STATE_SYN_RECEIVED)
        {
            goto AGAIN;
        }
        errorf("open error: %d", pcb->state);
        pcb->state = TCP_PCB_STATE_CLOSED;
        tcp_pcb_release(pcb);
        mutex_unlock(&mutex);
        return -1;
    }
    id = tcp_pcb_id(pcb);
    debugf("connection established: local=%s, foreign=%s", ip_endpoint_ntop(&pcb->local, ep1, sizeof(ep1)), ip_endpoint_ntop(&pcb->foreign, ep2, sizeof(ep2)));
    mutex_unlock(&mutex);
    return id;
}

int tcp_close(int id)
{
    struct tcp_pcb *pcb;

    mutex_lock(&mutex);
    pcb = tcp_pcb_get(id);
    if (!pcb)
    {
        errorf("pcb not found");
        mutex_unlock(&mutex);
        return -1;
    }
    tcp_output(pcb, TCP_FLG_RST, NULL, 0); // 暫定措置
    tcp_pcb_release(pcb);
    mutex_unlock(&mutex);
    return 0;
}

ssize_t
tcp_send(int id, uint8_t *data, size_t len)
{
    struct tcp_pcb *pcb;
    ssize_t sent = 0;
    struct ip_iface *iface;
    size_t mss, cap, slen;

    mutex_lock(&mutex);
    pcb = tcp_pcb_get(id);
    if (!pcb)
    {
        errorf("pcb not found");
        mutex_unlock(&mutex);
        return -1;
    }

RETRY:
    switch (pcb->state)
    {
    case TCP_PCB_STATE_ESTABLISHED:
        iface = ip_route_get_iface(pcb->foreign.addr);
        if (!iface)
        {
            errorf("ip_route_get_iface() failure");
            mutex_unlock(&mutex);
            return -1;
        }
        // Ethernetフレーム長 - IPヘッダ長 - TCPヘッダ長
        // ヘッダ長はオプションを使わない実装なので固定
        mss = NET_IFACE(iface)->dev->mtu - (IP_HDR_SIZE_MIN + sizeof(struct tcp_hdr));
        while (sent < (ssize_t)len)
        {
            // - 送信ウィンドウサイズは相手から送られてきたセグメントに指定されたウィンドウサイズ
            // - シーケンス番号の方がACK番号より常に先行する
            cap = pcb->snd.wnd - (pcb->snd.nxt - pcb->snd.una);
            if (!cap)
            {
                // 相手の受信バッファがあくまで待機
                if (sched_sleep(&pcb->ctx, &mutex, NULL) == -1)
                {
                    debugf("interrupted");
                    if (!sent)
                    {
                        mutex_unlock(&mutex);
                        errno = EINTR;
                        return -1;
                    }
                    break;
                }
                goto RETRY;
            }
            // 送信データ長はMSSと相手の受信バッファを考慮して決まる
            slen = MIN(MIN(mss, len - sent), cap);
            if (tcp_output(pcb, TCP_FLG_ACK, data + sent, slen) == -1)
            {
                errorf("tcp_output() failure");
                pcb->state = TCP_PCB_STATE_CLOSED;
                tcp_pcb_release(pcb);
                mutex_unlock(&mutex);
                return -1;
            }
            // 送信した分だけシーケンス番号を進める
            pcb->snd.nxt += slen;
            sent += slen;
        }
        break;
    default:
        errorf("unknown state '%u'", pcb->state);
        mutex_unlock(&mutex);
        return -1;
    }
    mutex_unlock(&mutex);
    return sent;
}

ssize_t
tcp_receive(int id, uint8_t *buf, size_t size)
{
    struct tcp_pcb *pcb;
    size_t remain, len;

    mutex_lock(&mutex);
    pcb = tcp_pcb_get(id);
    if (!pcb)
    {
        errorf("pcb not found");
        mutex_unlock(&mutex);
        return -1;
    }

RETRY:
    switch (pcb->state)
    {
    case TCP_PCB_STATE_ESTABLISHED:
        remain = sizeof(pcb->buf) - pcb->rcv.wnd; // バッファに格納されている未読み込みの受信データ長
        // 受信バッファにデータが格納されるまで待機
        if (!remain)
        {
            if (sched_sleep(&pcb->ctx, &mutex, NULL) == -1)
            {
                debugf("interrupted");
                mutex_unlock(&mutex);
                errno = EINTR;
                return -1;
            }
            goto RETRY;
        }
        break;
    default:
        errorf("unknown state '%u'", pcb->state);
        mutex_unlock(&mutex);
        return -1;
    }

    len = MIN(size, remain);
    memcpy(buf, pcb->buf, len);
    memmove(pcb->buf, pcb->buf + len, remain - len); // コピーした分だけバッファをずらす
    pcb->rcv.wnd += len;                             // 受信バッファから読み取りが完了したので、受信ウィンドウサイズをその分増やす
    mutex_unlock(&mutex);
    return len;
}