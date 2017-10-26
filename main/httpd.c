#include <esp_log.h>
#include <esp_task_wdt.h>

#include "tlv.h"
#include "mongoose.h"

#define TAG "HTTPD"

static void mg_ev_handler(struct mg_connection* nc, int ev, void *p) {
    static const char *reply_fmt =
        "HTTP/1.0 200 OK\r\n"
        "Connection: close\r\n"
        "Content-Type: text/plain\r\n"
        "\r\n"
        "Hello %s\n";

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

          if (strncmp("/pair-setup", hm->uri.p, hm->uri.len) == 0) {
              for (int i=0; i<hm->body.len; i++) {
                  printf("%x ", hm->body.p[i]);
              }

              printf("\n");

              //struct tlv* i1 = tlv_item_get(hm->body.p, hm->body.len, 0);
              //printf("%x\n", i1->value[0]);
              //struct tlv* i2 = tlv_item_get(hm->body.p, hm->body.len, 6);
              //printf("%x\n", i2->value[0]);

              //tlv_item_free(i1);
              //tlv_item_free(i2);
          }

          //mg_printf(nc, reply_fmt, addr);
          nc->flags |= MG_F_SEND_AND_CLOSE;


          break;
        }
        case MG_EV_CLOSE: {
          printf("Connection %p closed\n", nc);
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

void httpd_start(int port) {
    xTaskCreate(_httpd_task, "httpd_task", 1024*8, port, 5, NULL);
}
