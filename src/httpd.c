#include "httpd.h"

#include <esp_wifi.h>
#include <esp_event.h>
#include <esp_http_server.h>
#include <esp_log.h>
#include <esp_event_base.h>

#define TAG "httpd"

static httpd_config_t s_config = HTTPD_DEFAULT_CONFIG();
static httpd_handle_t s_server = NULL;

esp_err_t _connection_opened(httpd_handle_t hd, int sockfd) {
    ESP_LOGW(TAG, "Connection opened.");

    return ESP_OK;
}

esp_err_t _connection_closed(httpd_handle_t hd, int sockfd) {
    ESP_LOGW(TAG, "Connection closed.");

    return ESP_OK;
}

static esp_err_t _accessories_get(httpd_req_t *req) {
    ESP_LOGI(TAG, "[GET] accessories");
    return ESP_OK;
}

static esp_err_t _characteristics_get(httpd_req_t *req) {
    ESP_LOGI(TAG, "[GET] characteristics");
    return ESP_OK;
}

static esp_err_t _characteristics_put(httpd_req_t *req) {
    ESP_LOGI(TAG, "[PUT] characteristics");
    return ESP_OK;
}

static esp_err_t _pairings_get(httpd_req_t *req) {
    ESP_LOGI(TAG, "[GET] pairings");
    return ESP_OK;
}

static esp_err_t _pair_verify_post(httpd_req_t *req) {
    ESP_LOGI(TAG, "[POST] pair-verify");
    return ESP_OK;
}

static esp_err_t _pair_setup_post(httpd_req_t *req) {
    ESP_LOGI(TAG, "[POST] pair-setup");
    return ESP_OK;
}

static esp_err_t _start_server() {
    // Start the httpd server
    ESP_LOGI(TAG, "Starting server on port: '%d'", s_config.server_port);
    esp_err_t ret = httpd_start(&s_server, &s_config);
    if (ret == ESP_OK) {

        // Set URI handlers
        ESP_LOGI(TAG, "Registering URI handlers");

        httpd_register_uri_handler(s_server, &(httpd_uri_t) {
                .uri       = "/accessories",
                .method    = HTTP_GET,
                .handler   = _accessories_get,
                .user_ctx  = NULL
        });

        httpd_register_uri_handler(s_server, &(httpd_uri_t) {
                .uri       = "/characteristics",
                .method    = HTTP_GET,
                .handler   = _characteristics_get,
                .user_ctx  = NULL
        });

        httpd_register_uri_handler(s_server, &(httpd_uri_t) {
                .uri       = "/characteristics",
                .method    = HTTP_PUT,
                .handler   = _characteristics_put,
                .user_ctx  = NULL
        });

        httpd_register_uri_handler(s_server, &(httpd_uri_t) {
                .uri       = "/pairings",
                .method    = HTTP_GET,
                .handler   = _pairings_get,
                .user_ctx  = NULL
        });

        httpd_register_uri_handler(s_server, &(httpd_uri_t) {
                .uri       = "/pair-verify",
                .method    = HTTP_POST,
                .handler   = _pair_verify_post,
                .user_ctx  = NULL
        });

        httpd_register_uri_handler(s_server, &(httpd_uri_t) {
                .uri       = "/pair-setup",
                .method    = HTTP_POST,
                .handler   = _pair_setup_post,
                .user_ctx  = NULL
        });

    } else {
        ESP_LOGE(TAG, "Error starting server!");
    }

    return ret;
}

static void _stop_server() {
    ESP_LOGI(TAG, "Stopping server");
    httpd_stop(&s_server);
}

static void _disconnect_handler(void *arg, esp_event_base_t event_base,
                                int32_t event_id, void *event_data) {
    LWIP_UNUSED_ARG(arg);
    LWIP_UNUSED_ARG(event_base);
    LWIP_UNUSED_ARG(event_id);
    LWIP_UNUSED_ARG(event_data);

    _stop_server();
}

static void _connect_handler(void *arg, esp_event_base_t event_base,
                             int32_t event_id, void *event_data) {
    LWIP_UNUSED_ARG(arg);
    LWIP_UNUSED_ARG(event_base);
    LWIP_UNUSED_ARG(event_id);
    LWIP_UNUSED_ARG(event_data);

    _start_server();
}


esp_err_t httpd_init(int port) {
    if (s_server != NULL) {
        ESP_LOGE(TAG, "Already initialised.");
        return -1;
    }

    s_config.server_port = port;
    s_config.open_fn = _connection_opened;
    s_config.close_fn = _connection_closed;

    // Register listening on wifi start / stop to keep the server up
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &_connect_handler, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, WIFI_EVENT_STA_DISCONNECTED, &_disconnect_handler, NULL));

    return _start_server();
}

void httpd_terminate() {
    if (s_server == NULL) {
        ESP_LOGE(TAG, "Not initialised.");
        return;
    }

    // Register listening on wifi start / stop to keep the server up
    ESP_ERROR_CHECK(esp_event_handler_unregister(IP_EVENT, IP_EVENT_STA_GOT_IP, &_connect_handler));
    ESP_ERROR_CHECK(esp_event_handler_unregister(WIFI_EVENT, WIFI_EVENT_STA_DISCONNECTED, &_disconnect_handler));

    _stop_server();
}

