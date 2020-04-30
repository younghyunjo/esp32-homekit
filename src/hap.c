#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <cJSON.h>
#include <esp_log.h>
#include <esp_http_server.h>
#include <esp_event_base.h>
#include <esp_event.h>

#include "advertise.h"
#include "chacha20_poly1305.h"
#include "ed25519.h"
#include "hap.h"
#include "hap_internal.h"
#include "accessories.h"
#include "iosdevice.h"
#include "nvs.h"
#include "pair_setup.h"
#include "pair_verify.h"
#include "pairings.h"
#include "httpd_encrypted.h"


static bool s_registered = false;
static httpd_handle_t s_server = NULL;
static struct hap_accessory* s_accessory = NULL;


static esp_err_t _accessories_get(httpd_req_t *req) {
    ESP_LOGI(TAG, "[GET] accessories");

    char* res_body = NULL;
    int body_len = 0;
    hap_acc_accessories_do(s_accessory, &res_body, &body_len);

    httpd_resp_set_type(req, "application/hap+json");
    httpd_encrypted_send(req, res_body, body_len);

    free(res_body);
    return ESP_OK;
}

static esp_err_t _characteristics_get(httpd_req_t *req) {
    ESP_LOGI(TAG, "[GET] characteristics");

    int params_len = httpd_req_get_url_query_len(req) + 1;
    if (params_len > 0) {
        char* params = malloc(params_len);
        httpd_req_get_url_query_str(req, params, params_len);
        ESP_LOGD(TAG, "[GET] characteristics params: %.*s, len=%d", params_len, params, params_len-1);

        char* res_body = NULL;
        int body_len = 0;

        int ret = hap_acc_characteristic_get(s_accessory, params, params_len-1, &res_body, &body_len);
        if ( ret == ESP_OK) {
            httpd_resp_set_type(req, "application/hap+json");
            httpd_encrypted_send(req, res_body, body_len);
        }

        free(params);
        free(res_body);
        return ESP_OK;
    } else {
        ESP_LOGI(TAG, "Header did not contain 'id' tag");
        return httpd_encrypted_send_err(req, HTTPD_400_BAD_REQUEST, NULL);
    }
}

static esp_err_t _characteristics_put(httpd_req_t *req) {
    ESP_LOGI(TAG, "[PUT] characteristics");

    int ret = ESP_OK;
    char* res_body = NULL;
    char* buffer = NULL;
    int body_len = 0;

    if (req->content_len > MAX_RX_LENGTH) {
        ESP_LOGE(TAG, "Incoming body content length too long: %d", req->content_len);
        ret = httpd_encrypted_send_err(req, HTTPD_400_BAD_REQUEST, NULL);
        goto done;
    }

    buffer = calloc(1, req->content_len);
    if (!buffer) {
        ESP_LOGE(TAG, "No memory");
        ret = httpd_encrypted_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, NULL);
        goto done;
    }

    int len = httpd_encrypted_recv_body(req, req->content_len, buffer, req->content_len);
    if (len > 0) {
        hap_acc_characteristic_put(s_accessory, buffer, len, &res_body, &body_len);

        httpd_resp_set_status(req, "204");
        httpd_encrypted_send(req, res_body, body_len);
    } else {
        ESP_LOGE(TAG, "[PUT] characteristics: Received body length invalid len=%d", len);
        ret = httpd_encrypted_send_err(req, HTTPD_400_BAD_REQUEST, NULL);
    }

    done:
    free(buffer);
    free(res_body);
    return ret;
}

static esp_err_t _pairings_put(httpd_req_t *req) {
    ESP_LOGI(TAG, "[PUT] pairings");

    int ret = ESP_OK;
    char* res_body = NULL;
    char* buffer = NULL;
    int body_len = 0;

    buffer = calloc(1, req->content_len);
    if (!buffer) {
        ESP_LOGE(TAG, "No memory");
        ret = httpd_encrypted_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, NULL);
        goto done;
    }

    int len = httpd_encrypted_recv_body(req, req->content_len, buffer, req->content_len);
    if (len > 0) {
        pairings_do(s_accessory->iosdevices, buffer, len, &res_body, &body_len);

        httpd_resp_set_type(req, "application/pairing+tlv8");
        httpd_encrypted_send(req, res_body, body_len);
    } else {
        ESP_LOGE(TAG, "[PUT] characteristics: Received body length invalid len=%d", len);
        ret = httpd_encrypted_send_err(req, HTTPD_400_BAD_REQUEST, NULL);
    }

    done:
    free(buffer);
    free(res_body);
    return ret;
}


static esp_err_t _pair_verify_post(httpd_req_t *req) {
    ESP_LOGI(TAG, "[POST] pair-verify");

    // Get connection, die hard if if pointer is not valid, it would be a programming error.
    struct hap_connection *ctx = httpd_encrypted_get_connection(httpd_req_to_sockfd(req));

    int ret = ESP_OK;
    char* res_body = NULL;
    char* buffer = NULL;
    int body_len = 0;

    if (ctx->pair_verified) {
        ESP_LOGW(TAG, "Already verified");
        ret = httpd_encrypted_send_err(req, HTTPD_400_BAD_REQUEST, NULL);
        goto done;
    } else if (ctx->pair_verify == NULL) {
        ESP_LOGI(TAG, "Initiating verification");
        // Then we must have a valid verify instance
        ctx->pair_verify = pair_verify_init(
                s_accessory->id, s_accessory->iosdevices,
                s_accessory->keys.public, s_accessory->keys.private);
    }

    buffer = calloc(1, req->content_len);
    if (!buffer) {
        ESP_LOGE(TAG, "No memory");
        ret = httpd_encrypted_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, NULL);
        goto done;
    }

    int len = httpd_encrypted_recv_body(req, req->content_len, buffer, req->content_len);
    if (len <= 0) {
        ESP_LOGE(TAG, "Received bad length %d", len);
        ret = httpd_encrypted_send_err(req, HTTPD_400_BAD_REQUEST, NULL);
        goto done;
    }

    int verify_status = pair_verify_do(ctx->pair_verify, buffer, len, &res_body, &body_len, ctx->session_key);

    if (verify_status == 1) {
        ESP_LOGI(TAG, "Connection verified.");

        hkdf_key_get(HKDF_KEY_TYPE_CONTROL_READ, (uint8_t*)ctx->session_key,
                     CURVE25519_SECRET_LENGTH, ctx->encrypt_key);
        hkdf_key_get(HKDF_KEY_TYPE_CONTROL_WRITE, (uint8_t*)ctx->session_key,
                     CURVE25519_SECRET_LENGTH, ctx->decrypt_key);

        // Clean up, we are done.
        free(ctx->pair_verify);
        ctx->pair_verify = NULL;
    } else if (verify_status < 0) {
        ESP_LOGE(TAG, "Verification failed.");
    }

    httpd_resp_set_type(req, "application/pairing+tlv8");
    httpd_encrypted_send(req, res_body, body_len);

    // Set verified flag after reply is sent
    ctx->pair_verified = (verify_status == 1);

    done:
    free(buffer);
    free(res_body);
    return ret;
}

static esp_err_t _pair_setup_post(httpd_req_t *req) {
    ESP_LOGI(TAG, "[POST] pair-setup");

    int ret = ESP_OK;
    char* res_body = NULL;
    char* buffer = NULL;
    int body_len = 0;

    // Get connection, die hard if if pointer is not valid, it would be a programming error.
    struct hap_connection *ctx = httpd_encrypted_get_connection(httpd_req_to_sockfd(req));

    if (ctx->pair_setup == NULL) {
        ctx->pair_setup = pair_setup_init(
                s_accessory->id, s_accessory->pincode,
                s_accessory->iosdevices, s_accessory->keys.public, s_accessory->keys.private);
    }

    buffer = calloc(1, req->content_len);
    if (!buffer) {
        ESP_LOGE(TAG, "No memory");
        ret = httpd_encrypted_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, NULL);
        goto done;
    }

    int len = httpd_encrypted_recv_body(req, req->content_len, buffer, req->content_len);
    if (len <= 0) {
        ESP_LOGE(TAG, "Received bad length %d", len);
        ret = httpd_encrypted_send_err(req, HTTPD_400_BAD_REQUEST, NULL);
        goto done;
    }

    pair_setup_do(ctx->pair_setup, buffer, len, &res_body, &body_len);
    httpd_resp_set_type(req, "application/pairing+tlv8");
    httpd_encrypted_send(req, res_body, body_len);

    done:
    free(buffer);
    free(res_body);
    return ret;
}

static void _connect_handler(void *arg, esp_event_base_t event_base,
                             int32_t event_id, void *event_data) {
    UNUSED_ARG(arg);
    UNUSED_ARG(event_base);
    UNUSED_ARG(event_id);
    UNUSED_ARG(event_data);

    if (s_server != NULL) {
        ESP_LOGI(TAG, "HTTP server already initialised.");
        // not yet initialised.
        return;
    }

    esp_err_t ret = httpd_encrypted_start(&s_server);

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
                .method    = HTTP_POST,
                .handler   = _pairings_put,
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
}

static void _disconnect_handler(void *arg, esp_event_base_t event_base,
                                int32_t event_id, void *event_data) {
    UNUSED_ARG(arg);
    UNUSED_ARG(event_base);
    UNUSED_ARG(event_id);
    UNUSED_ARG(event_data);

    httpd_encrypted_stop(s_server);
}

static void _accessory_ltk_load(struct hap_accessory* a) 
{
    char acc_id_compact[13] = {0,};
    acc_id_compact[0] = a->id[0];
    acc_id_compact[1] = a->id[1];
    acc_id_compact[2] = a->id[3];
    acc_id_compact[3] = a->id[4];
    acc_id_compact[4] = a->id[6];
    acc_id_compact[5] = a->id[7];
    acc_id_compact[6] = a->id[9];
    acc_id_compact[7] = a->id[10];
    acc_id_compact[8] = a->id[12];
    acc_id_compact[9] = a->id[13];
    acc_id_compact[10] = a->id[15];
    acc_id_compact[11] = a->id[16];

    char nvs_public_key[32] = {0,};
    sprintf(nvs_public_key, "%sPB", acc_id_compact);
    //nvs_erase(nvs_public_key);
    int public_len = nvs_get(nvs_public_key, a->keys.public, ED25519_PUBLIC_KEY_LENGTH);

    char nvs_private_key[32] = {0,};
    sprintf(nvs_private_key, "%sPV", acc_id_compact);
    //nvs_erase(nvs_private_key);
    int private_len = nvs_get(nvs_private_key, a->keys.private, ED28819_PRIVATE_KEY_LENGTH);

    if (public_len == 0 || private_len == 0) {
        ed25519_key_generate(a->keys.public, a->keys.private);
        nvs_set(nvs_public_key, a->keys.public, ED25519_PUBLIC_KEY_LENGTH);
        nvs_set(nvs_private_key, a->keys.private, ED28819_PRIVATE_KEY_LENGTH);
    }
}

int hap_event_response(void* acc_instance, void* ev_handle, void* value)
{
    if (acc_instance != s_accessory) {
        ESP_LOGE(TAG, "Unknown accessory instance.");
        return -1;
    }

    char* res_body = NULL;
    int body_len = 0;

    hap_acc_event_response(ev_handle, value, &res_body, &body_len);
    httpd_encrypted_broadcast_event(s_server, res_body, body_len);

    free(res_body);
    return 0;
}

void* hap_accessory_add(void* acc_instance)
{
    struct hap_accessory* a = acc_instance;

    a->accessories_ojbects = hap_acc_accessory_add(acc_instance);

    return a->accessories_ojbects;
}

void hap_service_and_characteristics_add(void* acc_instance, void* acc_obj,
        enum hap_service_type type, struct hap_characteristic* cs, int nr_cs) 
{
    hap_acc_service_and_characteristics_add(acc_obj, type, cs, nr_cs);
}

void* hap_accessory_register(char* name, char* id, char* pincode, char* vendor, enum hap_accessory_category category,
        uint32_t config_number, void* callback_arg, hap_accessory_callback_t* callback)
{
    if (s_registered) {
        ESP_LOGE(TAG, "Accessory already registered, bailing out");
        return NULL;
    }


    struct hap_accessory* accessory = calloc(1, sizeof(struct hap_accessory));
    if (accessory == NULL) {
        ESP_LOGE(TAG, "calloc failed. size: %d", (int)sizeof(struct hap_accessory));
        return NULL;
    }

    accessory->name = strdup(name);
    strcpy(accessory->id, id);
    strcpy(accessory->pincode, pincode);
    accessory->vendor = strdup(vendor);
    accessory->category = category;
    accessory->config_number = config_number;
    accessory->callback = *callback;
    accessory->callback_arg = callback_arg;

    INIT_LIST_HEAD(&accessory->connections);
    INIT_LIST_HEAD(&accessory->attr_accessories);

    _accessory_ltk_load(accessory);
    accessory->iosdevices = iosdevice_pairings_init(accessory->id);
    accessory->advertise = advertise_accessory_add(accessory->name, accessory->id,
            accessory->vendor, httpd_encrypted_get_port(), accessory->config_number, accessory->category,
            ADVERTISE_ACCESSORY_STATE_NOT_PAIRED);

    s_accessory = accessory;

    ESP_LOGI(TAG, "HAP registered");
    s_registered = true;
    return accessory;
}

void hap_accessory_remove(void* acc_instance) {
    struct hap_accessory* a = acc_instance;

    //no unbind api at mongoose
    advertise_accessory_remove(a->advertise);

    free(a->name);
    free(a->vendor);
    free(a);
}

void hap_advertise(void* handle){
    struct hap_accessory* acc = handle;
    advertise_accessory_state(acc->advertise);
}

void hap_init(int port) {
    httpd_encrypted_init(port);

    // Register listening on wifi start / stop to keep the server up
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &_connect_handler, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, WIFI_EVENT_STA_DISCONNECTED, &_disconnect_handler, NULL));

    // Kick off initial registration, it doesn't matter if this one falls through and WIFI is not on yet,
    // the call back will occur when WiFi is finally up.
    _connect_handler(NULL, NULL, 0, NULL);
}

void hap_terminate() {
    // Unregister listening on wifi start / stop to keep the server up
    ESP_ERROR_CHECK(esp_event_handler_unregister(IP_EVENT, IP_EVENT_STA_GOT_IP, &_connect_handler));
    ESP_ERROR_CHECK(esp_event_handler_unregister(WIFI_EVENT, WIFI_EVENT_STA_DISCONNECTED, &_disconnect_handler));

    httpd_encrypted_stop(s_server);
    httpd_encrypted_terminate(s_server);
    s_server = NULL;
}