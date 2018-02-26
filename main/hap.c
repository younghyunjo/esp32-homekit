#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "advertise.h"
#include "ed25519.h"
#include "hap.h"
#include "hap_internal.h"
#include "httpd.h"
#include "iosdevice.h"
#include "mongoose.h"
#include "nvs.h"
#include "pair_setup.h"
#include "pair_verify.h"

struct hap_accessory {
    char id[HAP_ID_LENGTH+1];
    char pincode[HAP_PINCODE_LENGTH+1];
    char* name;
    char* vendor;
    int port;

    enum hap_accessory_category category;
    uint32_t config_number;

    void* advertise;
    void* bind;
    void* iosdevices;

    struct list_head connections;

    struct {
        uint8_t public[ED25519_PUBLIC_KEY_LENGTH];
        uint8_t private[ED28819_PRIVATE_KEY_LENGTH];
    } keys;

    void* callback_arg;
    hap_accessory_callback_t callback;
};

struct hap {
    void* dummy;
};

static struct hap* _hap_desc;

static void _hap_msg_recv(void* connection, struct mg_connection* nc, char* msg, int len)
{
    struct hap_connection* hc = connection;
    struct hap_accessory* a = hc->a;
    struct http_message shm, *hm = &shm;

    if (hc->pair_verified) {
        printf("DERYPT\n");
        //TODO DECRYPT DATA
    }

    mg_parse_http(msg, len, hm, 1);

    char addr[32];
    mg_sock_addr_to_str(&nc->sa, addr, sizeof(addr),
                        MG_SOCK_STRINGIFY_IP | MG_SOCK_STRINGIFY_PORT);
    printf("[INFO] HTTP request from %s: %.*s %.*s\n", addr, (int) hm->method.len,
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

        pair_verify_do_free(res_header, res_body);
    }
    else {
        printf("WHY????\n");
        printf("%.*s\n", (int) hm->uri.len, hm->uri.p);
        printf("%c%c%c%c\n", hm->uri.p[0], hm->uri.p[1], hm->uri.p[2], hm->uri.p[3]);
    }
}

static void _hap_connection_close(void* connection, struct mg_connection* nc)
{
    struct hap_connection* hc = connection;

    if (hc->pair_setup)
        pair_setup_cleanup(hc->pair_setup);

    if (hc->pair_verify)
        pair_verify_cleanup(hc->pair_setup);

    list_del(&hc->list);
    free(hc);
}

static void _hap_connection_accept(void* accessory, struct mg_connection* nc)
{
    struct hap_accessory* a = accessory;
    struct hap_connection* hc = calloc(1, sizeof(struct hap_connection));

    hc->nc = nc;
    hc->a = a;
    hc->pair_verified = false;

    nc->user_data = hc;


    list_add(&hc->list, &a->connections);
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

void* hap_accessory_add(char* name, char* id, char* pincode, char* vendor, enum hap_accessory_category category,
        int port, uint32_t config_number, void* callback_arg, hap_accessory_callback_t* callback)
{
    struct hap_accessory* a = calloc(1, sizeof(struct hap_accessory));
    if (a == NULL) {
        printf("[ERR] malloc failed. size:%d\n", sizeof(struct hap_accessory));
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

    _accessory_ltk_load(a);
    a->iosdevices = iosdevice_pairings_init(a->id);
    a->advertise = advertise_accessory_add(a->name, a->id, a->vendor, a->port, a->config_number, a->category,
                                           ADVERTISE_ACCESSORY_STATE_NOT_PAIRED);
    a->bind = httpd_bind(port, a);

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

    struct httpd_ops httpd_ops = {
        .accept = _hap_connection_accept,
        .close = _hap_connection_close,
        .recv = _hap_msg_recv,
    };

    httpd_init(&httpd_ops);
}
