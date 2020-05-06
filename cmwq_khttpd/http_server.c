#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kthread.h>
#include <linux/sched/signal.h>
#include <linux/tcp.h>
#include <linux/workqueue.h>
#include <linux/module.h>

#include "http_parser.h"
#include "http_server.h"
#include "bn.h"
#include "apm.h"

#define CRLF "\r\n"

#define HTTP_RESPONSE_200_DUMMY                               \
    ""                                                        \
    "HTTP/1.1 200 OK" CRLF "Server: " KBUILD_MODNAME CRLF     \
    "Content-Type: text/plain" CRLF "Content-Length: 12" CRLF \
    "Connection: Close" CRLF CRLF "Hello World!" CRLF
#define HTTP_RESPONSE_200_KEEPALIVE_DUMMY                     \
    ""                                                        \
    "HTTP/1.1 200 OK" CRLF "Server: " KBUILD_MODNAME CRLF     \
    "Content-Type: text/plain" CRLF "Content-Length: 12" CRLF \
    "Connection: Keep-Alive" CRLF CRLF "Hello World!" CRLF
#define HTTP_RESPONSE_501                                              \
    ""                                                                 \
    "HTTP/1.1 501 Not Implemented" CRLF "Server: " KBUILD_MODNAME CRLF \
    "Content-Type: text/plain" CRLF "Content-Length: 21" CRLF          \
    "Connection: Close" CRLF CRLF "501 Not Implemented1" CRLF
#define HTTP_RESPONSE_501_KEEPALIVE                                    \
    ""                                                                 \
    "HTTP/1.1 501 Not Implemented" CRLF "Server: " KBUILD_MODNAME CRLF \
    "Content-Type: text/plain" CRLF "Content-Length: 21" CRLF          \
    "Connection: KeepAlive" CRLF CRLF "501 Not Implemented2" CRLF

#define RECV_BUFFER_SIZE 4096

struct http_request {
    struct socket *socket;
    enum http_method method;
    char request_url[128];
    int complete;
};

extern struct workqueue_struct *khttpd_wq;
struct khttpd_service daemon = {.is_stopped = false};

// TODO : 這裡應該可以想辦法不用多複製一份
// ~ fib[1000000]
//static char response[210500];
//static char content[210000];

// fast doubling
static void fast_doubling(bn_t fib, long long k)
{
    // unlikely is for branch predictor
    if (unlikely(k <= 2)) {
        if (k == 0) {
            bn_init_u32(fib, 0);
        } else {
            bn_init_u32(fib, 1);
        }
        return;
    }

    unsigned long long leftbit = (unsigned long long) 1
                                 << ((sizeof(leftbit) * 8) - 1);

    while (!(leftbit & k)) {
        leftbit = leftbit >> 1;
    }

    bn* a = fib;
    bn_t b;

    bn_t tmp1;
    bn_t tmp2;

    bn_init_u32(a, 0);
    bn_init_u32(b, 1);
    bn_init(tmp1);
    bn_init(tmp2);

    while (leftbit > 0) {
        bn_lshift(b, 1, tmp1);
        a->sign = 1;
        bn_add(tmp1, a, tmp1);
        a->sign = 0;
        bn_mul(tmp1, a, tmp1);

        bn_sqr(a, a);
        bn_sqr(b, b);
        bn_add(a, b, tmp2);

        bn_swap(a, tmp1);
        bn_swap(b, tmp2);

        if (leftbit & k) {
            bn_swap(a, b);
            bn_add(a, b, b);
        }

        leftbit = leftbit >> 1;
    }

    bn_free(tmp1);
    bn_free(tmp2);
    bn_free(b);
}



static int http_server_recv(struct socket *sock, char *buf, size_t size)
{
    struct kvec iov = {.iov_base = (void *) buf, .iov_len = size};
    struct msghdr msg = {.msg_name = 0,
                         .msg_namelen = 0,
                         .msg_control = NULL,
                         .msg_controllen = 0,
                         .msg_flags = 0};
    return kernel_recvmsg(sock, &msg, &iov, 1, size, msg.msg_flags);
}


static int http_server_send(struct socket *sock, const char *buf, size_t size)
{
    // Q: msghdr ??
    // Q: struct kvec ??
    struct msghdr msg = {.msg_name = NULL,
                         .msg_namelen = 0,
                         .msg_control = NULL,
                         .msg_controllen = 0,
                         .msg_flags = 0};
    int done = 0;
    while (done < size) {
        struct kvec iov = {
            .iov_base = (void *) ((char *) buf + done),
            .iov_len = size - done,
        };
        int length = kernel_sendmsg(sock, &msg, &iov, 1, iov.iov_len);
        if (length < 0) {
            pr_err("write error: %d\n", length);
            break;
        }
        done += length;
    }
    return done;
}

// 組成 response 訊息後，再用 http_server_send 送出
static int http_server_response(struct http_request *request, int keep_alive)
{
    char *tmp_request_url;
    char *token;
    char *const delim = "/";
    int num_of_token = 0;
    long long fibo_k = 0;

    size_t response_len;

    char *response;
    char *content;
	
    // for test
    //char response[1000];
    //response = (char *)MALLOC(sizeof(char) * 1000);
    //char content[500];
    //response_len = 1000;    
    // test end

    // pr_info : 輸出訊息到 kernel 的 log 裡，可用 dmesg 查看
    // request->request_url 可以讀取 url 裡的訊息 --> 解析 fib 相關的參數
    //pr_info("requested_url = %s\n", request->request_url);

    //Q: keep alive 是什麼～？
    tmp_request_url = (char *)kmalloc(strlen(request->request_url) + 1, GFP_USER);
    strncpy(tmp_request_url, request->request_url, strlen(request->request_url) + 1);

    token = strsep(&tmp_request_url, delim);
    while (token = strsep(&tmp_request_url, delim)) {
        if (num_of_token == 0 && !strncmp(token, "fib", strlen(token))) {
            num_of_token = 1;
	} else if (num_of_token == 1) {
            fibo_k = simple_strtol(token, NULL, 10);	
	} else {
            num_of_token = -1;
	}
    }

    bn_t fib;
    
    if (fibo_k <= 3000000) {
        fast_doubling(fib, fibo_k);

	// set content
        size_t st_size = apm_string_size(fib->size, 10);
        content = (char *)MALLOC(sizeof(char) * st_size + 10);

	// set response
	response_len = st_size+500;
        response = (char *)MALLOC(response_len);

	bn_to_string(fib, content, sizeof(char) * st_size + 10, 10);
    } else {

        char *tempstr = "We only can handle f[k], k <= 3000000\nSorry about that, we are just not good enough.\n";
	size_t tempstr_len = strlen(tempstr);
        size_t content_len;

	// set content
        content = (char *)MALLOC(tempstr_len + 10);
	memset(content, 0, tempstr_len + 10);
        strncpy(content, tempstr, tempstr_len); 
        content_len = strlen(content);
	
        // set response
        response_len = content_len + 500;	
	response = (char *)MALLOC(response_len);
    }

    snprintf(response, response_len, 
            ""
	    "HTTP/1.1 200 OK" CRLF "Server: " KBUILD_MODNAME CRLF
	    "Content-Type: text/plain" CRLF "Content-Length: %lu" CRLF
	    "Connection: Close" CRLF CRLF "%s" CRLF, strlen(content), content);

    /*if (request->method != HTTP_GET) {
        //response = keep_alive ? HTTP_RESPONSE_501_KEEPALIVE : HTTP_RESPONSE_501;
        if (keep_alive) {
            strncpy(response, HTTP_RESPONSE_501_KEEPALIVE, strlen(HTTP_RESPONSE_501_KEEPALIVE));
	} else {
            strncpy(response, HTTP_RESPONSE_501, strlen(HTTP_RESPONSE_501));
	}
    } else {
        //response = keep_alive ? HTTP_RESPONSE_200_KEEPALIVE_DUMMY
        //                      : HTTP_RESPONSE_200_DUMMY;
        if (keep_alive) {
            strncpy(response, HTTP_RESPONSE_200_KEEPALIVE_DUMMY, strlen(HTTP_RESPONSE_200_KEEPALIVE_DUMMY));
	} else {
            strncpy(response, HTTP_RESPONSE_200_DUMMY, strlen(HTTP_RESPONSE_200_DUMMY));
	}
    }*/

    http_server_send(request->socket, response, strlen(response));

    kfree(content);
    kfree(response);
    kfree(tmp_request_url);
    return 0;
}

static int http_parser_callback_message_begin(http_parser *parser)
{
    struct http_request *request = parser->data;
    struct socket *socket = request->socket;
    memset(request, 0x00, sizeof(struct http_request));
    request->socket = socket;
    return 0;
}

static int http_parser_callback_request_url(http_parser *parser,
                                            const char *p,
                                            size_t len)
{
    struct http_request *request = parser->data;
    strncat(request->request_url, p, len);
    return 0;
}

static int http_parser_callback_header_field(http_parser *parser,
                                             const char *p,
                                             size_t len)
{
    return 0;
}

static int http_parser_callback_header_value(http_parser *parser,
                                             const char *p,
                                             size_t len)
{
    return 0;
}

static int http_parser_callback_headers_complete(http_parser *parser)
{
    struct http_request *request = parser->data;
    request->method = parser->method;
    return 0;
}

static int http_parser_callback_body(http_parser *parser,
                                     const char *p,
                                     size_t len)
{
    return 0;
}

static int http_parser_callback_message_complete(http_parser *parser)
{
    struct http_request *request = parser->data;
    http_server_response(request, http_should_keep_alive(parser));
    request->complete = 1;
    return 0;
}

//for kthread
/*
static int http_server_worker(void *arg)
{
    char *buf;
    struct http_parser parser;
    struct http_parser_settings setting = {
        .on_message_begin = http_parser_callback_message_begin,
        .on_url = http_parser_callback_request_url,
        .on_header_field = http_parser_callback_header_field,
        .on_header_value = http_parser_callback_header_value,
        .on_headers_complete = http_parser_callback_headers_complete,
        .on_body = http_parser_callback_body,
        .on_message_complete = http_parser_callback_message_complete};
    struct http_request request;
    struct socket *socket = (struct socket *) arg;

    allow_signal(SIGKILL);
    allow_signal(SIGTERM);

    buf = kmalloc(RECV_BUFFER_SIZE, GFP_KERNEL);
    if (!buf) {
        pr_err("can't allocate memory!\n");
        return -1;
    }

    request.socket = socket;
    http_parser_init(&parser, HTTP_REQUEST);
    parser.data = &request;
    while (!kthread_should_stop()) {
        int ret = http_server_recv(socket, buf, RECV_BUFFER_SIZE - 1);
        if (ret <= 0) {
            if (ret)
                pr_err("recv error: %d\n", ret);
            break;
        }
        http_parser_execute(&parser, &setting, buf, ret);
        if (request.complete && !http_should_keep_alive(&parser))
            break;
    }
    kernel_sock_shutdown(socket, SHUT_RDWR);
    sock_release(socket);
    kfree(buf);
    return 0;
}
*/

static void http_server_worker(struct work_struct *work)
{
    struct khttpd_worker *worker = container_of(work, struct khttpd_worker, worker);

    char *buf;
    struct http_parser parser;
    struct http_parser_settings setting = {
        .on_message_begin = http_parser_callback_message_begin,
        .on_url = http_parser_callback_request_url,
        .on_header_field = http_parser_callback_header_field,
        .on_header_value = http_parser_callback_header_value,
        .on_headers_complete = http_parser_callback_headers_complete,
        .on_body = http_parser_callback_body,
        .on_message_complete = http_parser_callback_message_complete};
    struct http_request request;

    printk("worker->sock : 0x%x\n", worker->sock);

    struct socket *socket = (struct socket *) worker->sock;

    allow_signal(SIGKILL);
    allow_signal(SIGTERM);

    buf = kmalloc(RECV_BUFFER_SIZE, GFP_KERNEL);
    if (!buf) {
        pr_err("can't allocate memory!\n");
        return -1;
    }

    request.socket = socket;
    http_parser_init(&parser, HTTP_REQUEST);
    parser.data = &request;

    //while (!daemon.is_stopped) {
    while (!kthread_should_stop()) {
        int ret = http_server_recv(socket, buf, RECV_BUFFER_SIZE - 1);
        if (ret <= 0) {
            if (ret)
                pr_err("recv error: %d\n", ret);
            break;
        }
        http_parser_execute(&parser, &setting, buf, ret);
        if (request.complete && !http_should_keep_alive(&parser))
            break;
    }
    kernel_sock_shutdown(socket, SHUT_RDWR);
    sock_release(socket);
    kfree(buf);
    
}


// for workqueue
// 參考（抄） kecho 的寫法
static struct work_struct *create_work(struct socket *sk) {

    printk("in create_work\n");

    struct khttpd_worker *khttpd_work;

    if (!(khttpd_work = kmalloc(sizeof(struct khttpd_worker), GFP_KERNEL))) {
        return NULL;
    }

    khttpd_work->sock = sk;

    INIT_WORK(&khttpd_work->worker, http_server_worker);

    list_add(&khttpd_work->list, &daemon.workers);

    return &khttpd_work->worker;
}

// for workqueue
static void free_work(void) {

    struct khttpd_worker *l, *tar;

    // 我猜 list 是在 khttp_worker 裡的 list 變數
    list_for_each_entry_safe (tar, l, &daemon.workers, list) {
        kernel_sock_shutdown(tar->sock, SHUT_RDWR);
        flush_work(&tar->worker);
        sock_release(tar->sock);
        kfree(tar);
    }
}


int http_server_daemon(void *arg)
{
    struct socket *socket;

    // for kthread
    //struct task_struct *worker;

    // for workqueue 
    struct work_struct *worker;
    //struct work_struct worker;

    struct http_server_param *param = (struct http_server_param *) arg;
    
    allow_signal(SIGKILL);
    allow_signal(SIGTERM);

    INIT_LIST_HEAD(&daemon.workers);
 
    while (!kthread_should_stop()) {

        printk("hi 1!\n");

        int err = kernel_accept(param->listen_socket, &socket, 0);
        if (err < 0) {
            if (signal_pending(current))
                break;
            pr_err("kernel_accept() error: %d\n", err);
            continue;
        }

	printk("hi 2!\n");

	// kthread worker start
        //worker = kthread_run(http_server_worker, socket, KBUILD_MODNAME);
        //if (IS_ERR(worker)) {
        //    pr_err("can't create more worker process\n");
        //    continue;
        //}
        //
	// kthread worker end
	
        printk("socket : 0x%x\n", socket);

	// cmwq worker start
        if (unlikely(!(worker = create_work(socket)))) {
            pr_err("can't create more worker\n");
	    continue;
	}

	queue_work(khttpd_wq, worker);
	// cmwq worker end
    }

    daemon.is_stopped = true;
    free_work();
    return 0;
}
