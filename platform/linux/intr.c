#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <pthread.h>
#include <time.h>
#include <errno.h>

#include "platform.h"

#include "util.h"
#include "net.h"

/*
 * 割り込み要求
 * IRQ: Interrupt Request
 */
struct irq_entry
{
    struct irq_entry *next;
    unsigned int irq;
    // Note: void型ポインタ
    // [汎用ポインタ](http://wisdom.sakura.ne.jp/programming/c/c47.html)
    int (*handler)(unsigned int irq, void *dev);
    /**
     * INTR_IRQ_SHARED: IRQ番号の共有が可能
     */
    int flags;
    // デバッグ出力で識別するための名前
    char name[16];
    // 割り込み発生元となるデバイスのポインタ
    void *dev;
};

// IRQリスト
static struct irq_entry *irqs;

// シグナル集合
// [c - vscode report undefined symbol which has been actually included - Stack Overflow](https://stackoverflow.com/questions/71043304/vscode-report-undefined-symbol-which-has-been-actually-included)
static sigset_t sigmask;

static pthread_t tid;
static pthread_barrier_t barrier;

int intr_request_irq(unsigned int irq, int (*handler)(unsigned int irq, void *dev), int flags, const char *name, void *dev)
{
    struct irq_entry *entry;

    debugf("irq=%u, flags=%d, name=%s", irq, flags, name);
    for (entry = irqs; entry; entry = entry->next)
    {
        if (entry->irq == irq)
        {
            if (entry->flags ^ INTR_IRQ_SHARED || flags ^ INTR_IRQ_SHARED)
            {
                errorf("conflicts with already registered IRQs");
                return -1;
            }
        }
    }
    // IRQリストへ新しいエントリを追加
    entry = memory_alloc(sizeof(*entry));
    if (!entry)
    {
        errorf("memory_alloc() failure");
        return -1;
    }
    entry->irq = irq;
    entry->handler = handler;
    entry->flags = flags;
    strncpy(entry->name, name, sizeof(entry->name) - 1);
    entry->dev = dev;
    // 現在のポインタを次のポインタとしてセットして、自信をリストの先頭にセット
    entry->next = irqs;
    irqs = entry;

    sigaddset(&sigmask, irq);
    debugf("registered: irq=%u, name=%s", irq, name);

    return 0;
}

int intr_raise_irq(unsigned int irq)
{
    return pthread_kill(tid, (int)irq);
}

static int
intr_timer_setup(struct itimerspec *interval)
{
    timer_t id;
    // タイマーの作成とインターバルの設定
    // timer_createの第二引数がNULLの場合はSIGALRMシグナルが発生する
    // [timer_create(2) - Linux manual page](https://man7.org/linux/man-pages/man2/timer_create.2.html)
    // > Specifying sevp as NULL is equivalent to specifying a pointer to
    // > a sigevent structure in which sigev_notify is SIGEV_SIGNAL,
    // > sigev_signo is SIGALRM, and sigev_value.sival_int is the timer ID.
    if (timer_create(CLOCK_REALTIME, NULL, &id) == -1)
    {
        errorf("timer_create: %s", strerror(errno));
        return -1;
    }
    if (timer_settime(id, 0, interval, NULL) == -1)
    {
        errorf("timer_settime: %s", strerror(errno));
        return -1;
    }
    return 0;
}

static void *
intr_thread(void *arg)
{
    const struct timespec ts = {0, 1000000}; // 1ms
    struct itimerspec interval = {ts, ts};
    int terminate = 0, sig, err;
    struct irq_entry *entry;

    debugf("start...");
    pthread_barrier_wait(&barrier);
    if (intr_timer_setup(&interval) == -1)
    {
        errorf("intr_timer_setup() failure");
        return NULL;
    }
    while (!terminate)
    {
        // シグナルが発生するまで待つ
        // [sigwait(3) - Linux manual page](https://man7.org/linux/man-pages/man3/sigwait.3.html)
        err = sigwait(&sigmask, &sig);
        if (err)
        {
            errorf("sigwait() failure: %s", strerror(err));
            break;
        }
        // SIGHUP以外のシグナルのときは、登録されている割り込みハンドラを呼び出す
        switch (sig)
        {
        case SIGHUP:
            terminate = -1;
            break;
        case SIGALRM:
            net_timer_handler();
            break;
        case SIGUSR1:
            net_softirq_handler();
            break;
        case SIGUSR2:
            net_event_handler();
            break;
        default:
            for (entry = irqs; entry; entry = entry->next)
            {
                if (entry->irq == (unsigned int)sig)
                {
                    debugf("irq=%d, name=%s", entry->irq, entry->name);
                    entry->handler(entry->irq, entry->dev);
                }
            }
            break;
        }
    }
    debugf("terminated");
    return NULL;
}

int intr_run(void)
{
    int err;

    err = pthread_sigmask(SIG_BLOCK, &sigmask, NULL);
    if (err)
    {
        errorf("pthread_sigmask() %s", strerror(err));
        return -1;
    }
    err = pthread_create(&tid, NULL, intr_thread, NULL);
    if (err)
    {
        errorf("pthread_create() %s", strerror(err));
        return -1;
    }
    pthread_barrier_wait(&barrier);
    return 0;
}

void intr_shutdown(void)
{
    if (pthread_equal(tid, pthread_self()) != 0)
    {
        /* Thread not created. */
        return;
    }
    pthread_kill(tid, SIGHUP);
    pthread_join(tid, NULL);
}

int intr_init(void)
{
    // スレッドID初期値にメインスレッドのIDを設定する
    tid = pthread_self();
    // 2スレッド分のバリアを初期化する
    pthread_barrier_init(&barrier, NULL, 2);
    sigemptyset(&sigmask);
    sigaddset(&sigmask, SIGHUP);
    sigaddset(&sigmask, SIGALRM); // timer用シグナル
    sigaddset(&sigmask, SIGUSR1);
    sigaddset(&sigmask, SIGUSR2);
    return 0;
}
