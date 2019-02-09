
#include <stdio.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "mongoose.h"
#include "httpd.h"

static struct httpd_ops _ops;
static struct mg_mgr _mgr;
static SemaphoreHandle_t _httpd_mutex;

static void _httpd_task(void* arg) {
    while (1) {
        xSemaphoreTake(_httpd_mutex, 0);
        mg_mgr_poll(&_mgr, 1000);
        xSemaphoreGive(_httpd_mutex);
    }
}

static void mg_ev_handler(struct mg_connection* nc, int ev, void *p, void* user_data) {
    switch (ev)     {
        case MG_EV_ACCEPT: {
            if (_ops.accept) {
                _ops.accept(user_data, nc);
            }

            char addr[32];
            mg_sock_addr_to_str(&nc->sa, addr, sizeof(addr),
                                MG_SOCK_STRINGIFY_IP | MG_SOCK_STRINGIFY_PORT);
            printf("[HTTPD] Connection %p from %s\n", nc, addr);
            break;
        }
        case MG_EV_RECV: {
            printf("[HTTPD] MG_EV_RECV\n");
            if (_ops.recv) {
                _ops.recv(user_data, nc, nc->recv_mbuf.buf, nc->recv_mbuf.len);
            }
            break;
        }
        case MG_EV_POLL: {
            break;
        }
        case MG_EV_CLOSE: {
            printf("[HTTPD] MG_EV_CLOSE");
            printf("Connection %p closed\n", nc);
            if (_ops.close) {
                _ops.close(user_data, nc);
            }
            break;
        }
        case MG_EV_SEND: {
            printf("[HTTPD] MG_EV_SEND. %d\n", *((int*)user_data));
            break;
        }
        default: {
            printf("[HTTPD] DEFAULT:%d\n", ev);
            break;
        }
    }
}

void* httpd_bind(int port, void* user_data) {
    if (port <= 0)
        return NULL;

    struct mg_connection* nc = NULL;
    char port_string[8] = {0,};
    #if MG_ENABLE_IPV6
        sprintf(port_string, "[::]:%d", port);
    #else
        sprintf(port_string, "%d", port);
    #endif

    xSemaphoreTake(_httpd_mutex, 0);
    nc = mg_bind(&_mgr, port_string, mg_ev_handler, user_data);
    if (nc == NULL) {
        printf("[ERR] mg_bind failed]n");
        goto err_mg_bind;
    }

    mg_set_protocol_http_websocket(nc);

err_mg_bind:
    xSemaphoreGive(_httpd_mutex);
    return nc;
}

void httpd_init(struct httpd_ops* ops) {
#define HTTPD_STACK (1024*8)
    mg_mgr_init(&_mgr, NULL);
    _httpd_mutex = xSemaphoreCreateMutex();
    _ops = *ops;
    xTaskCreate(_httpd_task, "httpd_task", HTTPD_STACK, NULL, 5, NULL);
}
