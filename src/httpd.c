#include "httpd.h"
#include "pair_verify.h"
#include "pair_setup.h"

#include <esp_wifi.h>
#include <esp_event.h>
#include <esp_http_server.h>
#include <esp_log.h>
#include <esp_event_base.h>
#include <sys/param.h>
#include <mbedtls/base64.h>

#define TAG "httpd"

#define MAX_BODY_LEN 1024

// HACK remove me
char tmp[2048];

static char* s_rx_buffer;

static httpd_config_t s_config = HTTPD_DEFAULT_CONFIG();
static httpd_handle_t s_server = NULL;

static struct hap_accessory* s_accessory = NULL;


struct hap_connection *_check_ctx(httpd_req_t *req);

/**
 * Streams the body's content
 * @return ESP_FAIL if badness, or the total number of bytes received if > 0
 */
int _recv_body(httpd_req_t *req, size_t len, char *buf, size_t max_len) {
    int count = 0;
    int ret;

    if (len > max_len) {
        ESP_LOGE(TAG, "Exceeded max rx buffer length %d > %d", len, max_len);
        return ESP_FAIL;
    }

    while (len > 0) {
        if ((ret = httpd_req_recv(req, buf + count, len)) <= 0) {
            if (ret == HTTPD_SOCK_ERR_TIMEOUT) {
                /* Retry receiving if timeout occurred */
                continue;
            }
            return ESP_FAIL;
        }

        len -= ret;
        count += ret;
    }

    size_t out_len;
    mbedtls_base64_encode((unsigned char*)tmp, 2048, &out_len, (unsigned char*)buf, count);
    ESP_LOGI(TAG, "<<<<<<<<< %.*s", out_len, tmp);

    return count;
}

/**
 * This is called when a connection is closed.
 * If any context data exists and therefore was allocated, we clean up as required.
 */
static void _free_ctx(void *instance) {
    struct hap_connection* ctx = instance;
    if (ctx != NULL) {
        ESP_LOGI(TAG, "Deleting context");

        if (ctx->pair_verify) {
            free(ctx->pair_verify);
        }

        if (ctx->pair_setup) {
            free(ctx->pair_setup);
        }

        free(ctx);
    }
}

struct hap_connection *_check_ctx(httpd_req_t *req) {
    struct hap_connection *ctx = req->sess_ctx;
    if (ctx == NULL) {
        // This is a new connection with no context, allocate a context and proceed with verification
        req->free_ctx = _free_ctx;

        ctx = calloc(1, sizeof(struct hap_connection));

        ctx->pair_verify = pair_verify_init(
                s_accessory->id, s_accessory->iosdevices,
                s_accessory->keys.public, s_accessory->keys.private);

        ctx->pair_setup = pair_setup_init(
                s_accessory->id, s_accessory->pincode,
                s_accessory->iosdevices, s_accessory->keys.public, s_accessory->keys.private);

    }

    return ctx;
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

    struct hap_connection *ctx = _check_ctx(req);
    int len =  _recv_body(req, req->content_len, s_rx_buffer, MAX_BODY_LEN);

    char* res_body = NULL;
    int body_len = 0;

    int verify_status = pair_verify_do(ctx->pair_verify, s_rx_buffer, len, &res_body, &body_len, ctx->session_key);

    if (verify_status > 0) {
        ESP_LOGI(TAG, "Connection verified.");
        ctx->pair_verified = true;

        hkdf_key_get(HKDF_KEY_TYPE_CONTROL_READ, (uint8_t*)ctx->session_key,
                CURVE25519_SECRET_LENGTH, ctx->encrypt_key);
        hkdf_key_get(HKDF_KEY_TYPE_CONTROL_WRITE, (uint8_t*)ctx->session_key,
                CURVE25519_SECRET_LENGTH, ctx->decrypt_key);

    } else if (verify_status < 0) {
        ESP_LOGE(TAG, "Verification failed.");
    }

    httpd_resp_set_type(req, "application/pairing+tlv8");
    httpd_resp_send(req, res_body, body_len);

    size_t out_len;
    mbedtls_base64_encode((unsigned char*)tmp, 2048, &out_len, (unsigned char*)res_body, body_len);
    ESP_LOGI(TAG, ">>>>> %.*s", out_len, tmp);

    free(res_body);
    return ESP_OK;
}



static esp_err_t _pair_setup_post(httpd_req_t *req) {
    ESP_LOGI(TAG, "[POST] pair-setup");

    struct hap_connection *ctx = _check_ctx(req);
    int len =  _recv_body(req, req->content_len, s_rx_buffer, MAX_BODY_LEN);

    char* res_body = NULL;
    int body_len = 0;

    pair_setup_do(ctx->pair_setup, s_rx_buffer, len, &res_body, &body_len);

    httpd_resp_set_type(req, "application/pairing+tlv8");
    httpd_resp_send(req, res_body, body_len);

    size_t out_len;
    mbedtls_base64_encode((unsigned char*)tmp, 2048, &out_len, (unsigned char*)res_body, body_len);
    ESP_LOGI(TAG, ">>>>> %.*s", out_len, tmp);

    free(res_body);
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


esp_err_t httpd_init(struct hap_accessory* accessory) {
    if (s_accessory != NULL) {
        ESP_LOGE(TAG, "Already initialised.");
        return -1;
    }

    s_accessory = accessory;

    s_config.server_port = s_accessory->port;
    s_config.stack_size = 1024 * 8;

    // Register listening on wifi start / stop to keep the server up
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &_connect_handler, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, WIFI_EVENT_STA_DISCONNECTED, &_disconnect_handler, NULL));

    // Allocate receive buffer
    s_rx_buffer = calloc(1, sizeof(char) * MAX_BODY_LEN);

    return _start_server();
}

void httpd_terminate() {
    if (s_accessory == NULL) {
        ESP_LOGE(TAG, "Not initialised.");
        return;
    }

    // Register listening on wifi start / stop to keep the server up
    ESP_ERROR_CHECK(esp_event_handler_unregister(IP_EVENT, IP_EVENT_STA_GOT_IP, &_connect_handler));
    ESP_ERROR_CHECK(esp_event_handler_unregister(WIFI_EVENT, WIFI_EVENT_STA_DISCONNECTED, &_disconnect_handler));

    _stop_server();
    free(s_rx_buffer);
    s_accessory = NULL;
}

