#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <cJSON.h>
#include <esp_log.h>
#include <esp_http_server.h>

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
#include "httpd.h"

//#define DEBUG

static bool s_registered = false;

static void _plain_msg_recv(void* connection, httpd_req_t* nc, char* msg, int len);

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

static void _encrypted_msg_recv(void* connection, struct httpd_req_t* nc, char* msg, int len) 
{
    char* decrypted = calloc(1, len);
    if (decrypted == NULL) {
        ESP_LOGE(TAG, "calloc failded. size:%d", len);
        return;
    }

    struct hap_connection* hc = connection;
    uint8_t* saveptr = NULL;
    int decrypted_len = 0;

    for (decrypted_len = _decrypt(hc, msg, len, decrypted, &saveptr); decrypted_len;  decrypted_len = _decrypt(hc, msg, len, decrypted, &saveptr)) {
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

static void encrypt_send(struct httpd_req_t* nc, struct hap_connection* hc, char* res_header, int header_len, char* body, int body_len)
{
    char* plain_text = calloc(1, header_len + body_len + 64);
    if (res_header)
        memcpy(plain_text, res_header, header_len);

    if (body)
        memcpy(plain_text + header_len, body, body_len);

    int encrypted_len = 0;


    char* encrypted = _encrypt(hc, plain_text, strlen(plain_text), &encrypted_len);

    free(plain_text);

    //WILLC mg_send(nc, encrypted, encrypted_len);

    _encrypt_free(encrypted);
}

void _free_response(const char *res_header, const char *res_body) {// Clean up
    if (res_body != NULL) {
        free(res_body);
    }
    if (res_header != NULL) {
        free(res_header);
    }
}

static void _plain_msg_recv(void* connection, httpd_req_t* nc, char* msg, int len)
{
    struct hap_connection* hc = connection;
    struct hap_accessory* a = hc->a;

    char* res_header = NULL;
    int res_header_len = 0;
    char* res_body = NULL;
    int body_len = 0;

    char* http_raw_msg = msg;
    int http_raw_msg_len = len;
    //WILLC mg_parse_http(http_raw_msg, http_raw_msg_len, &hm, 1);

    char addr[32];
    //WILLC mg_sock_addr_to_str(&nc->sa, addr, sizeof(addr), (unsigned)MG_SOCK_STRINGIFY_IP | (unsigned)MG_SOCK_STRINGIFY_PORT);
/*
    ESP_LOGI(TAG, "HTTP request from %s: %.*s %.*s", addr, (int) hm.method.len,
            hm.method.p, (int) hm.uri.len, hm.uri.p);



    if (strncmp(hm.uri.p, "/pair-setup", strlen("/pair-setup")) == 0) {
        if (hc->pair_setup == NULL) {
            hc->pair_setup = pair_setup_init(a->id, a->pincode, a->iosdevices, a->keys.public, a->keys.private);
        }

        pair_setup_do(hc->pair_setup, hm.body.p, hm.body.len, &res_header, &res_header_len, &res_body, &body_len);

        if (res_header) {
            //WILLC mg_send(nc, res_header, res_header_len);
        }

        if (res_body) {
            //WILLC mg_send(nc, res_body, body_len);
        }
    }
    else if (strncmp(hm.uri.p, "/pair-verify", hm.uri.len) == 0) {
        if (hc->pair_verify == NULL) {
            hc->pair_verify = pair_verify_init(a->id, a->iosdevices, a->keys.public, a->keys.private);
        }

        pair_verify_do(hc->pair_verify, hm.body.p, hm.body.len, &res_header, &res_header_len, &res_body, &body_len, &hc->pair_verified, hc->session_key);

        if (res_header) {
            //WILLC mg_send(nc, res_header, res_header_len);
        }

        if (res_body) {
            //WILLC mg_send(nc, res_body, body_len);
        }

        if (hc->pair_verified) {
            hkdf_key_get(HKDF_KEY_TYPE_CONTROL_READ, (uint8_t*)hc->session_key, CURVE25519_SECRET_LENGTH, hc->encrypt_key);
            hkdf_key_get(HKDF_KEY_TYPE_CONTROL_WRITE, (uint8_t*)hc->session_key, CURVE25519_SECRET_LENGTH, hc->decrypt_key);
        }

    }  else if (strncmp(hm.uri.p, "/accessories", hm.uri.len) == 0) {

        hap_acc_accessories_do(a, &res_header, &res_header_len, &res_body, &body_len);
        encrypt_send(nc, hc, res_header, res_header_len, res_body, body_len);

    } else if (strncmp(hm.uri.p, "/characteristics", hm.uri.len) == 0) {

        if (strncmp(hm.method.p, "GET", hm.method.len) == 0) {
            char *query = (char *) hm.query_string.p;
            int query_len = (int) hm.query_string.len;
            char *res_header = NULL;
            int res_header_len = 0;
            char *res_body = NULL;
            int body_len = 0;

            hap_acc_characteristic_get(a, query, query_len, &res_header, &res_header_len, &res_body, &body_len);
            ESP_LOGD(TAG, "------REQUEST-----");
            ESP_LOGD(TAG, "%.*s", (int)hm.query_string.len, hm.query_string.p);
            ESP_LOGD(TAG, "------RESPONSE-----");
            ESP_LOGD(TAG, "%s%s", res_header, res_body);

            if (hc->pair_verified) {
                encrypt_send(nc, hc, res_header, res_header_len, res_body, body_len);
            } else {
                //WILLC mg_send(hc->nc, res_body, body_len);
            }
        } else if (strncmp(hm.method.p, "PUT", hm.method.len) == 0) {
            hap_acc_characteristic_put(a, (void *) hc, (char *) hm.body.p, hm.body.len, &res_header, &res_header_len,
                                       &res_body, &body_len);
            ESP_LOGD(TAG, "------REQUEST-----");
            ESP_LOGD(TAG, "%.*s", (int)hm.query_string.len, hm.query_string.p);
            ESP_LOGD(TAG, "%.*s", (int)hm.body.len, (char*)hm.body.p);
            ESP_LOGD(TAG, "------RESPONSE-----");
            ESP_LOGD(TAG, "%s", res_header);
            encrypt_send(nc, hc, res_header, res_header_len, res_body, body_len);
        }
    } else if (strncmp(hm.uri.p, "/pairings", hm.uri.len) == 0) {
        pairings_do(a->iosdevices, hm.body.p, hm.body.len, &res_header, &res_header_len, &res_body, &body_len);
        if (res_header) {
            //WILLC mg_send(nc, res_header, res_header_len);
        }

        if (res_body) {
            //WILLC mg_send(nc, res_body, body_len);
        }
        encrypt_send(nc, hc, res_header, res_header_len, res_body, body_len);
    } else {
        ESP_LOGW(TAG, "Unhandled request: %.*s %c%c%c%c",
                (int) hm.uri.len, hm.uri.p,  hm.uri.p[0], hm.uri.p[1], hm.uri.p[2], hm.uri.p[3]);
    }

    _free_response(res_header, res_body);
    */
}

static void _msg_recv(void* connection, struct httpd_req_t* nc, char* msg, int len)
{
    struct hap_connection* hc = connection;

    if (hc->pair_verified) {
        _encrypted_msg_recv(connection, nc, msg, len);
    }
    else {
        _plain_msg_recv(connection, nc, msg, len);
    }
}

static void _hap_connection_close(void* connection, struct httpd_req_t* nc)
{
    struct hap_connection* hc = connection;


    if (hc->pair_setup)
        pair_setup_cleanup(hc->pair_setup);

    if (hc->pair_verify)
        pair_verify_cleanup(hc->pair_verify);

    ESP_LOGI(TAG, "Resources freed for connection");

    free(hc);
}

static void _hap_connection_accept(void* accessory, httpd_req_t* nc)
{
    struct hap_accessory* a = accessory;
    struct hap_connection* hc = calloc(1, sizeof(struct hap_connection));

    hc->a = a;
    hc->pair_verified = false;


    //INIT_LIST_HEAD(&hc->event_head);
    //WILLC nc->user_data = hc;

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

    // WILLC thread safety required
//    list_for_each_entry(hc, &a->connections, list) {
//        encrypt_send(hc->nc, hc, res_header, res_header_len, res_body, body_len);
//    }

    ESP_LOGI(TAG, "%.*s", res_header_len, res_header);
    ESP_LOGI(TAG, "%.*s", body_len, res_body);

    _free_response(res_header, res_body);
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
    accessory->port = port;
    accessory->config_number = config_number;
    accessory->callback = *callback;
    accessory->callback_arg = callback_arg;

    INIT_LIST_HEAD(&accessory->connections);
    INIT_LIST_HEAD(&accessory->attr_accessories);

    _accessory_ltk_load(accessory);
    accessory->iosdevices = iosdevice_pairings_init(accessory->id);
    accessory->advertise = advertise_accessory_add(accessory->name, accessory->id,
            accessory->vendor, accessory->port, accessory->config_number, accessory->category,
            ADVERTISE_ACCESSORY_STATE_NOT_PAIRED);

    httpd_init(accessory);

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
