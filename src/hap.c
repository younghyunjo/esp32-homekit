#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <cJSON.h>
#include <esp_log.h>

#include "advertise.h"
#include "chacha20_poly1305.h"
#include "ed25519.h"
#include "hap.h"
#include "hap_internal.h"
#include "accessories.h"
#include "httpd.h"
#include "iosdevice.h"
#include "mongoose.h"
#include "nvs.h"
#include "pair_setup.h"
#include "pair_verify.h"
#include "pairings.h"

//#define DEBUG

#define TAG "HAP"

struct hap {
    int nr_accessory;
    SemaphoreHandle_t mutex;
};

static struct hap* _hap_desc;

static void _plain_msg_recv(void* connection, struct mg_connection* nc, char* msg, int len);

static int _decrypt(struct hap_connection* hc, char* encrypted, int len, char* decrypted, uint8_t** saveptr)
{
#define AAD_LENGTH 2
    uint8_t* ptr;
    if (*saveptr == NULL) {
        ptr = (uint8_t*)encrypted;
    }
    else if (*saveptr < encrypted + len) {
        ptr = *saveptr;
    }
    else if (*saveptr == encrypted + len){
        ESP_LOGI(TAG, "_decrypt end %d", (int)((char*)*saveptr - encrypted));
        return 0;
    }
    else {
        ESP_LOGE(TAG, "BUG? BUG? BUG?");
        return 0;
    }

    int decrypted_len = ptr[1] * 256 + ptr[0];
    uint8_t nonce[12] = {0,};
    nonce[4] = hc->decrypt_count % 256;
    nonce[5] = hc->decrypt_count++ / 256;

    if (chacha20_poly1305_decrypt_with_nonce(nonce, hc->decrypt_key, ptr, AAD_LENGTH, 
                ptr+AAD_LENGTH, decrypted_len + CHACHA20_POLY1305_AUTH_TAG_LENGTH, (uint8_t*)decrypted) < 0) {
        ESP_LOGE(TAG, "chacha20_poly1305_decrypt_with_nonce failed");
        return 0;
    }

    *saveptr = ptr + decrypted_len + CHACHA20_POLY1305_AUTH_TAG_LENGTH + AAD_LENGTH;

    return decrypted_len;;
}

static void _encrypted_msg_recv(void* connection, struct mg_connection* nc, char* msg, int len) 
{
    char* decrypted = calloc(1, len);
    if (decrypted == NULL) {
        ESP_LOGE(TAG, "calloc failded. size:%d", len);
        return;
    }

    struct hap_connection* hc = connection;
    uint8_t* saveptr = NULL;
    int decrypted_len = 0;

    for (decrypted_len = _decrypt(hc, msg, len, decrypted, &saveptr); decrypted_len; 
         decrypted_len = _decrypt(hc, msg, len, decrypted, &saveptr)) {
        _plain_msg_recv(connection, nc, decrypted, decrypted_len);
    }

    free(decrypted);
}


static char* _encrypt(struct hap_connection* hc, char* msg, int len, int* encrypted_len)
{
#define AAD_LENGTH 2
    char* encrypted = calloc(1, len + (len / 1024 + 1) * (AAD_LENGTH + CHACHA20_POLY1305_AUTH_TAG_LENGTH) + 1);
    *encrypted_len = 0;

    uint8_t nonce[12] = {0,};
    uint8_t* decrypted_ptr = (uint8_t*)msg;
    uint8_t* encrypted_ptr = (uint8_t*)encrypted;
    while (len > 0) {
        int chunk_len = (len < 1024) ? len : 1024;
        len -= chunk_len;

        uint8_t aad[AAD_LENGTH];
        aad[0] = chunk_len % 256;
        aad[1] = chunk_len / 256;

        memcpy(encrypted_ptr, aad, AAD_LENGTH);
        encrypted_ptr += AAD_LENGTH;
        *encrypted_len += AAD_LENGTH;

        nonce[4] = hc->encrypt_count % 256;
        nonce[5] = hc->encrypt_count++ / 256;

        chacha20_poly1305_encrypt_with_nonce(nonce, hc->encrypt_key, aad, AAD_LENGTH, decrypted_ptr, chunk_len, encrypted_ptr);

        decrypted_ptr += chunk_len;
        encrypted_ptr += chunk_len + CHACHA20_POLY1305_AUTH_TAG_LENGTH;
        *encrypted_len += (chunk_len + CHACHA20_POLY1305_AUTH_TAG_LENGTH);
    }

    return encrypted;
}

static void _encrypt_free(char* msg) 
{
    if (msg)
        free(msg);
}

static void encrypt_send(struct mg_connection* nc, struct hap_connection* hc, char* res_header, int header_len, char* body, int body_len)
{
    char* plain_text = calloc(1, header_len + body_len + 64);
    if (res_header)
        memcpy(plain_text, res_header, header_len);

    if (body)
        memcpy(plain_text + header_len, body, body_len);

    int encrypted_len = 0;
    char* encrypted = _encrypt(hc, plain_text, strlen(plain_text), &encrypted_len);

    free(plain_text);

    mg_send(nc, encrypted, encrypted_len);
    _encrypt_free(encrypted);
}

static void _plain_msg_recv(void* connection, struct mg_connection* nc, char* msg, int len)
{
    struct hap_connection* hc = connection;
    struct hap_accessory* a = hc->a;
    struct http_message shm, *hm = &shm;

    char* http_raw_msg = msg;
    int http_raw_msg_len = len;
    mg_parse_http(http_raw_msg, http_raw_msg_len, hm, 1);

    char addr[32];
    mg_sock_addr_to_str(&nc->sa, addr, sizeof(addr),
            MG_SOCK_STRINGIFY_IP | MG_SOCK_STRINGIFY_PORT);

    ESP_LOGI(TAG, "HTTP request from %s: %.*s %.*s", addr, (int) hm->method.len,
            hm->method.p, (int) hm->uri.len, hm->uri.p);

    if (strncmp(hm->uri.p, "/pair-setup", strlen("/pair-setup")) == 0) {
        if (hc->pair_setup == NULL) {
            hc->pair_setup = pair_setup_init(a->id, a->pincode, a->iosdevices, a->keys.public, a->keys.private);
        }

        char* res_header = NULL;
        int res_header_len = 0;

        char* res_body = NULL;
        int body_len = 0;

        pair_setup_do(hc->pair_setup, hm->body.p, hm->body.len, &res_header, &res_header_len, &res_body, &body_len);

        if (res_header) {
            mg_send(nc, res_header, res_header_len);
        }

        if (res_body) {
            mg_send(nc, res_body, body_len);
        }

        pair_setup_do_free(res_header, res_body);
    }
    else if (strncmp(hm->uri.p, "/pair-verify", hm->uri.len) == 0) {
        if (hc->pair_verify == NULL) {
            hc->pair_verify = pair_verify_init(a->id, a->iosdevices, a->keys.public, a->keys.private);
        }

        char* res_header = NULL;
        int res_header_len = 0;

        char* res_body = NULL;
        int body_len = 0;

        pair_verify_do(hc->pair_verify, hm->body.p, hm->body.len, &res_header, &res_header_len, &res_body, &body_len, &hc->pair_verified, hc->session_key);

        if (res_header) {
            mg_send(nc, res_header, res_header_len);
        }

        if (res_body) {
            mg_send(nc, res_body, body_len);
        }

        if (hc->pair_verified) {
            hkdf_key_get(HKDF_KEY_TYPE_CONTROL_READ, (uint8_t*)hc->session_key, CURVE25519_SECRET_LENGTH, hc->encrypt_key);
            hkdf_key_get(HKDF_KEY_TYPE_CONTROL_WRITE, (uint8_t*)hc->session_key, CURVE25519_SECRET_LENGTH, hc->decrypt_key);
        }

        pair_verify_do_free(res_header, res_body);
    }
    else if (strncmp(hm->uri.p, "/accessories", hm->uri.len) == 0) {
        char* res_header = NULL;
        int res_header_len = 0;

        char* res_body = NULL;
        int body_len = 0;

        hap_acc_accessories_do(a, &res_header, &res_header_len, &res_body, &body_len);
#ifdef DEBUG
        {
            ESP_LOGI(TAG, "RESPONSE");
            ESP_LOGI(TAG, "%s%s", res_header, res_body);
        }
#endif
        encrypt_send(nc, hc, res_header, res_header_len, res_body, body_len);
        hap_acc_accessories_do_free(res_header, res_body);
    }
    else if (strncmp(hm->uri.p, "/characteristics", hm->uri.len) == 0) {
        if (strncmp(hm->method.p, "GET", hm->method.len) == 0) {
            char* query = (char*)hm->query_string.p;
            int query_len = (int)hm->query_string.len;
            char* res_header = NULL;
            int res_header_len = 0;
            char* res_body = NULL;
            int body_len = 0;

            hap_acc_characteristic_get(a, query, query_len, &res_header, &res_header_len, &res_body, &body_len);
#ifdef DEBUG
            {
                ESP_LOGI(TAG, "------REQUEST-----");
                ESP_LOGI(TAG, "%.*s", (int)hm->query_string.len, hm->query_string.p);
                ESP_LOGI(TAG, "------RESPONSE-----");
                ESP_LOGI(TAG, "%s%s", res_header, res_body);
            }
#endif
            encrypt_send(nc, hc, res_header, res_header_len, res_body, body_len);
            hap_acc_characteristic_get_free(res_header, res_body);
        }
        else if (strncmp(hm->method.p, "PUT", hm->method.len) == 0) {
            char* res_header = NULL;
            int res_header_len = 0;
            char* res_body = NULL;
            int body_len = 0;

            hap_acc_characteristic_put(a, (void*)hc, (char*)hm->body.p, hm->body.len, &res_header, &res_header_len, &res_body, &body_len);
#ifdef DEBUG
            {
                ESP_LOGI(TAG, "------REQUEST-----");
                ESP_LOGI(TAG, "%.*s", (int)hm->query_string.len, hm->query_string.p);
                ESP_LOGI(TAG, "%.*s", (int)hm->body.len, (char*)hm->body.p);
                ESP_LOGI(TAG, "------RESPONSE-----");
                ESP_LOGI(TAG, "%s", res_header);
            }
#endif
            encrypt_send(nc, hc, res_header, res_header_len, res_body, body_len);
            hap_acc_characteristic_put_free(res_header, res_body);
        }
    }
    else if (strncmp(hm->uri.p, "/pairings", hm->uri.len) == 0) {
        char* res_header = NULL;
        int res_header_len = 0;

        char* res_body = NULL;
        int body_len = 0;

        pairings_do(a->iosdevices, hm->body.p, hm->body.len, &res_header, &res_header_len, &res_body, &body_len);
        if (res_header) {
            mg_send(nc, res_header, res_header_len);
        }

        if (res_body) {
            mg_send(nc, res_body, body_len);
        }
        encrypt_send(nc, hc, res_header, res_header_len, res_body, body_len);
        pairings_do_free(res_header, res_body);
    }
    else {
        ESP_LOGW(TAG, "NOT HANDLED");
#ifdef DEBUG
        ESP_LOGW(TAG, "%.*s", (int) hm->uri.len, hm->uri.p);
        ESP_LOGW(TAG, "%c%c%c%c", hm->uri.p[0], hm->uri.p[1], hm->uri.p[2], hm->uri.p[3]);
#endif
    }
}

static void _msg_recv(void* connection, struct mg_connection* nc, char* msg, int len)
{
    struct hap_connection* hc = connection;

    if (hc->pair_verified) {
        _encrypted_msg_recv(connection, nc, msg, len);
    }
    else {
        _plain_msg_recv(connection, nc, msg, len);
    }
}

static void _hap_connection_close(void* connection, struct mg_connection* nc)
{
    struct hap_connection* hc = connection;


    if (hc->pair_setup)
        pair_setup_cleanup(hc->pair_setup);

    if (hc->pair_verify)
        pair_verify_cleanup(hc->pair_setup);

    xSemaphoreTake(_hap_desc->mutex, 0);
    list_del(&hc->list);
    xSemaphoreGive(_hap_desc->mutex);

    free(hc);
}

static void _hap_connection_accept(void* accessory, struct mg_connection* nc)
{
    struct hap_accessory* a = accessory;
    struct hap_connection* hc = calloc(1, sizeof(struct hap_connection));

    hc->nc = nc;
    hc->a = a;
    hc->pair_verified = false;


    //INIT_LIST_HEAD(&hc->event_head);
    nc->user_data = hc;

    xSemaphoreTake(_hap_desc->mutex, 0);
    list_add(&hc->list, &a->connections);
    xSemaphoreGive(_hap_desc->mutex);
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
    char* res_header = NULL;
    int res_header_len = 0;
    char* res_body = NULL;
    int body_len = 0;


    hap_acc_event_response(ev_handle, value, &res_header, &res_header_len, &res_body, &body_len);

    struct hap_accessory* a = acc_instance;
    struct hap_connection* hc;

    xSemaphoreTake(_hap_desc->mutex, 0);
    list_for_each_entry(hc, &a->connections, list) {
        encrypt_send(hc->nc, hc, res_header, res_header_len, res_body, body_len);
    }
    xSemaphoreGive(_hap_desc->mutex);

    ESP_LOGI(TAG, "%.*s", res_header_len, res_header);
    ESP_LOGI(TAG, "%.*s", body_len, res_body);

    hap_acc_event_response_free(res_header, res_body);

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
                        int port, uint32_t config_number, void* callback_arg, hap_accessory_callback_t* callback)
{
    if (_hap_desc->nr_accessory != 0) {
        return NULL;
    }

    struct hap_accessory* a = calloc(1, sizeof(struct hap_accessory));
    if (a == NULL) {
        ESP_LOGE(TAG, "calloc failed. size:%d", sizeof(struct hap_accessory));
        return NULL;
    }

    a->name = strdup(name);
    strcpy(a->id, id);
    strcpy(a->pincode, pincode);
    a->vendor = strdup(vendor);
    a->category = category;
    a->port = port;
    a->config_number = config_number;
    a->callback = *callback;
    a->callback_arg = callback_arg;

    INIT_LIST_HEAD(&a->connections);
    INIT_LIST_HEAD(&a->attr_accessories);

    _accessory_ltk_load(a);
    a->iosdevices = iosdevice_pairings_init(a->id);
    a->advertise = advertise_accessory_add(a->name, a->id, a->vendor, a->port, a->config_number, a->category,
                                           ADVERTISE_ACCESSORY_STATE_NOT_PAIRED);
    a->bind = httpd_bind(port, a);
    _hap_desc->nr_accessory = 1;

    return a;
}

void hap_accessory_remove(void* acc_instance) {
    struct hap_accessory* a = acc_instance;

    //no unbind api at mongoose
    advertise_accessory_remove(a->advertise);

    free(a->name);
    free(a->vendor);
    free(a);
}

void hap_init(void)
{
    if (_hap_desc)
        return;

    _hap_desc = calloc(1, sizeof(struct hap));
    if (_hap_desc == NULL)
        return;

    vSemaphoreCreateBinary(_hap_desc->mutex);

    struct httpd_ops httpd_ops = {
        .accept = _hap_connection_accept,
        .close = _hap_connection_close,
        .recv = _msg_recv,
    };

    httpd_init(&httpd_ops);
}
