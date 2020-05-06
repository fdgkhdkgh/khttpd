#ifndef KHTTPD_HTTP_SERVER_H
#define KHTTPD_HTTP_SERVER_H

#include <net/sock.h>

struct http_server_param {
    struct socket *listen_socket;
};

struct khttpd_service {
    bool is_stopped;
    struct list_head workers;
};

struct khttpd_worker {
    struct socket *sock;
    struct list_head list;
    struct work_struct worker;
};

extern int http_server_daemon(void *arg);

#endif
