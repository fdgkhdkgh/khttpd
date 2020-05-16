#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kthread.h>
#include <linux/sched/signal.h>
#include <linux/tcp.h>
#include <net/sock.h>

#include "http_server.h"

#define DEFAULT_PORT 8081
#define DEFAULT_BACKLOG 100

static ushort port = DEFAULT_PORT;
// 在 insmod 時，可以給予的參數
module_param(port, ushort, S_IRUGO);

static ushort backlog = DEFAULT_BACKLOG;
module_param(backlog, ushort, S_IRUGO);

static struct socket *listen_socket;
static struct http_server_param param;
static struct task_struct *http_server;

struct workqueue_struct *khttpd_wq;

static inline int setsockopt(struct socket *sock,
                             int level,
                             int optname,
                             int optval)
{
    int opt = optval;
    return kernel_setsockopt(sock, level, optname, (char *) &opt, sizeof(opt));
}

static int open_listen_socket(ushort port, ushort backlog, struct socket **res)
{
    struct socket *sock;
    struct sockaddr_in s;

    // 或許可以看看 struct sock 有哪些欄位 ??
    // 也可以學習 kernel driver 怎麼使用工具來 debug ？？ kernel pwn
    // 的基礎可以來學習一下了 ??

    // Guess : 創建 socket
    //
    // PF_INET : 使用 IPv4
    // SOCK_STREAM : 提供一個“序列化”以及可靠的 “byte stream”
    // IPPROTO_TCP : 指定使用 TCP 協定
    //
    // Q: 什麼是序列化？
    int err = sock_create(PF_INET, SOCK_STREAM, IPPROTO_TCP, &sock);
    if (err < 0) {
        pr_err("sock_create() failure, err=%d\n", err);
        return err;
    }

    // Guess : 對已經建好的 socket 進行設定
    err = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, 1);
    if (err < 0)
        goto bail_setsockopt;

    // SOL_TCP : 使用 TCP 協定的 API
    // TCP_NODELAY : 關係 TCP 資料處理的 Nagle's Algorithm
    err = setsockopt(sock, SOL_TCP, TCP_NODELAY, 1);
    if (err < 0)
        goto bail_setsockopt;

    err = setsockopt(sock, SOL_TCP, TCP_CORK, 0);
    if (err < 0)
        goto bail_setsockopt;

    err = setsockopt(sock, SOL_SOCKET, SO_RCVBUF, 1024 * 1024);
    if (err < 0)
        goto bail_setsockopt;

    err = setsockopt(sock, SOL_SOCKET, SO_SNDBUF, 1024 * 1024);
    if (err < 0)
        goto bail_setsockopt;

    memset(&s, 0, sizeof(s));
    s.sin_family = AF_INET;
    s.sin_addr.s_addr = htonl(INADDR_ANY);
    s.sin_port = htons(port);
    // 綁定一個網路位址
    // Guess : 將建立出來的 socket 進行一些初始化後 (sock_create) ，開啟某些設定
    // (kernel_setsockopt) ， sockaddr_in （變數 s）就是網路位址
    err = kernel_bind(sock, (struct sockaddr *) &s, sizeof(s));
    if (err < 0) {
        pr_err("kernel_bind() failure, err=%d\n", err);
        goto bail_sock;
    }

    // DEFAULT_BACKLOG : 紀錄 pending connection 資訊(因為 client 端有可能在
    // server 呼叫 accept() 之前就呼叫 connect()) Q: 看不懂上面那一段的意思
    //
    // Q: backlog??
    // A: https://elixir.bootlin.com/linux/latest/source/net/socket.c#L3619 ,
    // pending connections queue size
    //
    // Q: server 端的 connect v.s. client 端的 accept
    err = kernel_listen(sock, backlog);
    if (err < 0) {
        pr_err("kernel_listen() failure, err=%d\n", err);
        goto bail_sock;
    }
    *res = sock;
    return 0;

bail_setsockopt:
    pr_err("kernel_setsockopt() failure, err=%d\n", err);
bail_sock:
    sock_release(sock);
    return err;
}

static void close_listen_socket(struct socket *socket)
{
    // kernel_sock_shutdown :
    // https://elixir.bootlin.com/linux/latest/source/net/socket.c#L3830
    // kernel_sock_shutdown(struct socket *sock, enum sock_shutdown_cmd how);
    //
    // sock_shutdown_cmd :
    // https://elixir.bootlin.com/linux/latest/source/include/linux/net.h#L88
    kernel_sock_shutdown(socket, SHUT_RDWR);

    // 釋放 socket object
    sock_release(socket);
}

static int __init khttpd_init(void)
{

    pr_info("module init\n");
    // 初始化 socket
    // 設定 socket
    // 將 socket 綁定在某個 port 上
    // 開始聆聽這個 port
    int err = open_listen_socket(port, backlog, &listen_socket);
    if (err < 0) {
        pr_err("can't open listen socket\n");
        return err;
    }

    // http_server_param
    param.listen_socket = listen_socket;

    khttpd_wq = alloc_workqueue("khttpd_wq", WQ_UNBOUND, 0);

    //printk("khttpd_wq : 0x%x\n", khttpd_wq);
    // 建立一個 kernel thread 並執行它
    // static struct task_struct *http_server;
    //
    // 原本我還在傻傻地想，為什麼不直接在 init 裡面跑一個無窮迴圈
    //   但是後來想想，卡死在這邊的話，能夠緊接著 __exit 嗎？
    http_server = kthread_run(http_server_daemon, &param, KBUILD_MODNAME);

    if (IS_ERR(http_server)) {
        pr_err("can't start http server daemon\n");
        close_listen_socket(listen_socket);
        return PTR_ERR(http_server);
    }
    return 0;
}

static void __exit khttpd_exit(void)
{
    send_sig(SIGTERM, http_server, 1);

    // 停止 kthread 的運行
    kthread_stop(http_server);

    close_listen_socket(listen_socket);

    destroy_workqueue(khttpd_wq);

    pr_info("module unloaded\n");
}

module_init(khttpd_init);
module_exit(khttpd_exit);

MODULE_LICENSE("Dual MIT/GPL");
MODULE_AUTHOR("National Cheng Kung University, Taiwan");
MODULE_DESCRIPTION("in-kernel HTTP daemon");
MODULE_VERSION("0.1");
