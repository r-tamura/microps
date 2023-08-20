#include <pthread.h>
#include <time.h>
#include <errno.h>

#include "platform.h"

int sched_ctx_init(struct sched_ctx *ctx)
{
    // 条件変数について
    // https://linuxjm.osdn.jp/html/glibc-linuxthreads/man3/pthread_cond_wait.3.html
    pthread_cond_init(&ctx->cond, NULL);
    ctx->interrupted = 0;
    ctx->wc = 0;
    return 0;
}

int sched_ctx_destroy(struct sched_ctx *ctx)
{
    return pthread_cond_destroy(&ctx->cond); // 条件変数の破棄（待機中のスレッドが存在する場合にのみエラーが返る）
}

int sched_sleep(struct sched_ctx *ctx, mutex_t *mutex, const struct timespec *abstime)
{
    int ret;

    if (ctx->interrupted)
    {
        // EINTRはシグナルに割り込まれたことを示すエラー
        // https://www.gnu.org/software/libc/manual/html_node/Interrupted-Primitives.html
        errno = EINTR;
        return -1;
    }
    ctx->wc++;
    // 書籍「並行プログラミング入門」では信号機に例えられている。
    // pthread_cond_waitは赤信号で待つ様子に相当する。
    // pthread_cond_broadcastが青信号への変更に相当する。
    if (abstime)
    {
        ret = pthread_cond_timedwait(&ctx->cond, mutex, abstime);
    }
    else
    {
        ret = pthread_cond_wait(&ctx->cond, mutex);
    }
    ctx->wc--;
    if (ctx->interrupted)
    {
        // 休止中だったスレッドすべてが希少したらinterruptedフラグを下げる
        if (!ctx->wc)
        {
            ctx->interrupted = 0;
        }
        errno = EINTR;
        return -1;
    }
    return ret;
}

int sched_wakeup(struct sched_ctx *ctx)
{
    return pthread_cond_broadcast(&ctx->cond);
}

int sched_interrupt(struct sched_ctx *ctx)
{
    ctx->interrupted = 1;
    return pthread_cond_broadcast(&ctx->cond);
}