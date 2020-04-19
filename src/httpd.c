
#include <stdio.h>
#include <esp_log.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "mongoose.h"
#include "httpd.h"

#define TAG "httpd"
#define HTTPD_STACK (1024 * 8)

static struct httpd_ops _ops;
static struct mg_mgr _mgr;
static SemaphoreHandle_t _httpd_mutex;
static bool s_go = true;

static void _httpd_task(void* arg) {
    LWIP_UNUSED_ARG(arg);

    while (s_go) {
        if (xSemaphoreTake(_httpd_mutex, 1000 / portMAX_DELAY) == pdTRUE) {
            mg_mgr_poll(&_mgr, 500);
            xSemaphoreGive(_httpd_mutex);
        }
        vTaskDelay(100); // yield to allow semaphore to be taken
    }
}

static void mg_ev_handler(struct mg_connection* nc, int ev, void *p, void* user_data) {
    LWIP_UNUSED_ARG(p);

    switch (ev)     {
        case MG_EV_ACCEPT: {
            if (_ops.accept) {
                _ops.accept(user_data, nc);
            }

            char addr[32];
            mg_sock_addr_to_str(&nc->sa, addr, sizeof(addr),
                                (unsigned)MG_SOCK_STRINGIFY_IP | (unsigned)MG_SOCK_STRINGIFY_PORT);
            ESP_LOGI(TAG, "Connection %p from %s", nc, addr);
            break;
        }
        case MG_EV_RECV: {
            ESP_LOGD(TAG, "MG_EV_RECV");
            if (_ops.recv) {
                _ops.recv(user_data, nc, nc->recv_mbuf.buf, nc->recv_mbuf.len);
            }
            break;
        }
        case MG_EV_POLL: {
            break;
        }
        case MG_EV_CLOSE: {
            ESP_LOGI(TAG, "Connection closed - MG_EV_CLOSE");
            if (_ops.close) {
                _ops.close(user_data, nc);
            }
            break;
        }
        case MG_EV_SEND: {
            ESP_LOGD(TAG, "MG_EV_SEND. %d", *((int*)user_data));
            break;
        }
        default: {
            ESP_LOGD(TAG, "DEFAULT:%d", ev);
            break;
        }
    }
}

void* httpd_bind(int port, void* user_data) {
    if (port <= 0)
        return NULL;

    ESP_LOGI(TAG, "Binding");

    struct mg_connection* nc = NULL;
    char port_string[11] = {0,};
    sprintf(port_string, "%d", port);

    bool taken = xSemaphoreTake(_httpd_mutex, portMAX_DELAY) == pdTRUE;
    ESP_LOGI(TAG, "Got semaphore");

    nc = mg_bind(&_mgr, port_string, mg_ev_handler, user_data);
    if (nc == NULL) {
        ESP_LOGE(TAG, "mg_bind failed]n");
        goto err_mg_bind;
    }

    mg_set_protocol_http_websocket(nc);

err_mg_bind:
    if (taken) {
        xSemaphoreGive(_httpd_mutex);
    }
    ESP_LOGI("httpd", "Done.");
    return nc;
}

void httpd_init(struct httpd_ops* ops) {
    mg_mgr_init(&_mgr, NULL);
    _httpd_mutex = xSemaphoreCreateMutex();
    _ops = *ops;
    xTaskCreate(_httpd_task, "httpd_task", HTTPD_STACK, NULL, 5, NULL);
}
