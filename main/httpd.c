#include <esp_log.h>
#include <esp_task_wdt.h>

#include "mongoose.h"

#include "httpd.h"
#include "pairing.h"
#include "tlv.h"
#include "hap.h"

#define TAG "HTTPD"

struct httpd_desc {
    int nr_restapi;
    struct httpd_restapi* restapi;
};
static struct httpd_desc _httpd = {
    .nr_restapi = 0
};

static void mg_ev_handler(struct mg_connection* nc, int ev, void *p) {
    switch (ev) {
        case MG_EV_ACCEPT: {
          char addr[32];
          mg_sock_addr_to_str(&nc->sa, addr, sizeof(addr),
                              MG_SOCK_STRINGIFY_IP | MG_SOCK_STRINGIFY_PORT);
          printf("Connection %p from %s\n", nc, addr);
          break;
        }
        case MG_EV_HTTP_REQUEST: {
          char addr[32];
          struct http_message *hm = (struct http_message *) p;
          mg_sock_addr_to_str(&nc->sa, addr, sizeof(addr),
                              MG_SOCK_STRINGIFY_IP | MG_SOCK_STRINGIFY_PORT);

          printf("HTTP request from %s: %.*s %.*s\n", addr, (int) hm->method.len,
                 hm->method.p, (int) hm->uri.len, hm->uri.p);
          //printf("%.*s\n", (int)hm->message.len, (char*)hm->message.p);

          for (int i=0; i<_httpd.nr_restapi; i++) {
              if (strncasecmp(_httpd.restapi[i].uri, hm->uri.p, hm->uri.len) == 0 &&
                  strncasecmp(_httpd.restapi[i].method, hm->method.p, hm->method.len) == 0) {

                  char* res_header = NULL;
                  char* res_body = NULL;
                  int res_header_len = 0;
                  int body_len = 0;
                  _httpd.restapi[i].ops((char*)hm->body.p, hm->body.len, &res_header, &res_header_len, &res_body, &body_len);

                  if (res_header) {
                      mg_send(nc, res_header, res_header_len);
                  }

                  if (res_body) {
                      mg_send(nc, res_body, body_len);
                  }

                  _httpd.restapi[i].post_response(res_header, res_body);
                  //nc->flags |= MG_F_ENABLE_BROADCAST;
                  break;
              }
          }
          break;
        }
        case MG_EV_RECV: {
          break;
        }

        case MG_EV_POLL: {
          break;
        }
        case MG_EV_CLOSE: {
          printf("Connection %p closed\n", nc);
          break;
        }
        default: {
          printf("[HTTPD] DEFAULT:%d\n", ev);
          break;
        }
    }
}

static void _httpd_task(void* arg) {
    struct mg_mgr mgr;
    mg_mgr_init(&mgr, NULL);

    char port_string[16] = {0,};
    sprintf(port_string, "%d", (int)arg);
    struct mg_connection* nc = mg_bind(&mgr, port_string, mg_ev_handler);
    if (nc == NULL) {
        ESP_LOGE(TAG, "mg_bind failed\n");
        return;
    }

    mg_set_protocol_http_websocket(nc);

    while (1) {
        mg_mgr_poll(&mgr, 1000);
        esp_task_wdt_feed();
    }
}

void httpd_start(int port, struct httpd_restapi* api, int nr_restapi) {
    _httpd.restapi = malloc(sizeof(struct httpd_restapi) * nr_restapi);
    if (_httpd.restapi == NULL) {
        ESP_LOGE(TAG, "malloc failed\n");
        return;
    }
    memcpy(_httpd.restapi, api, sizeof(struct httpd_restapi) * nr_restapi);
    _httpd.nr_restapi = nr_restapi;
    xTaskCreate(_httpd_task, "httpd_task", 1024*8, (void*)port, 5, NULL);
    ESP_LOGI(TAG, "STARTED\n");
}



