#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <cJSON.h>

#include "advertise.h"
#include "chacha20_poly1305.h"
#include "ed25519.h"
#include "hap.h"
#include "hap_internal.h"
#include "httpd.h"
#include "iosdevice.h"
#include "mongoose.h"
#include "nvs.h"
#include "pair_setup.h"
#include "pair_verify.h"

#define HAP_UUID    "%08X-0000-1000-8000-0026BB765291"

struct hap_acc_accessory {
    struct list_head list;
    struct list_head services;

    int aid;
    int last_iid;
};

struct hap_attr_service {
    struct list_head list;

    enum hap_service_type type;
    int iid;
    int nr_character;
    void* characters;
};

struct hap_attr_characteristic {
    int aid;
    int iid;

    enum hap_characteristic_type type;
    void* initial_value;
    void* callback_arg;
    void* (*read)(void* arg);
    void (*write)(void* arg, void* value, int value_len);
    void (*event)(void* arg, void* ev_handle, bool enable);
};


static const char* header_204_fmt = 
    "HTTP/1.1 204 No Content\r\n"
    "Connection: keep-alive\r\n"
    "Content-type: application/hap+json\r\n"
    "\r\n";

static const char* header_200_fmt = 
    "HTTP/1.1 200 OK\r\n"
    "Content-Length: %d\r\n"
    "Connection: keep-alive\r\n"
    "Content-type: application/hap+json\r\n"
    "\r\n";

int accessories_do(struct hap_accessory* a, char** res_header, int* res_header_len, char** res_body, int* res_body_len);
void accessories_do_free(char* res_header, char* res_body);

static struct hap_attr_characteristic* _attr_character_find(struct list_head* attr_accessories, int aid, int iid)
{
    struct hap_acc_accessory* a_ptr;
    struct hap_attr_service* s_ptr;
    list_for_each_entry(a_ptr, attr_accessories, list) {
        if (a_ptr->aid != aid)
            continue;

        list_for_each_entry(s_ptr, &a_ptr->services, list) {
            struct hap_attr_characteristic* c = (struct hap_attr_characteristic*)&s_ptr->characters;
            for (int i=0; i<s_ptr->nr_character; i++, c++) {
                if (c->iid == iid)
                    return c;
            }
        }
    }
    return NULL;
}

static cJSON* _attr_characterisic_to_json(struct hap_attr_characteristic* c)
{
    cJSON* root = cJSON_CreateObject();

    char type[37] = {0,};
    sprintf(type, HAP_UUID, c->type);
    cJSON_AddStringToObject(root, "type", type);
    cJSON_AddNumberToObject(root, "iid", c->iid);
    cJSON* perms = cJSON_CreateArray(); 
    cJSON_AddItemToObject(root, "perms", perms);

    switch(c->type) {
        case HAP_CHARACTER_ON:
            cJSON_AddItemToArray(perms, cJSON_CreateString("pr"));
            cJSON_AddItemToArray(perms, cJSON_CreateString("pw"));
            cJSON_AddItemToArray(perms, cJSON_CreateString("ev"));
            cJSON_AddStringToObject(root, "format", "bool");
            cJSON_AddItemToObject(root, "value", cJSON_CreateBool(1));
            break;
        case HAP_CHARACTER_IDENTIFY:
            //cJSON_AddNullToObject(root, "value");
            cJSON_AddStringToObject(root, "format", "bool");
            cJSON_AddItemToArray(perms, cJSON_CreateString("pw"));
            break;
        case HAP_CHARACTER_MANUFACTURER:
            cJSON_AddStringToObject(root, "value", (char*)c->initial_value);
            cJSON_AddStringToObject(root, "format", "string");
            cJSON_AddNumberToObject(root, "maxLen", 64);
            cJSON_AddItemToArray(perms, cJSON_CreateString("pr"));
            break;
        case HAP_CHARACTER_MODEL:
            cJSON_AddStringToObject(root, "value", (char*)c->initial_value);
            cJSON_AddStringToObject(root, "format", "string");
            cJSON_AddNumberToObject(root, "maxLen", 64);
            cJSON_AddItemToArray(perms, cJSON_CreateString("pr"));
            break;
        case HAP_CHARACTER_NAME:
            cJSON_AddStringToObject(root, "value", (char*)c->initial_value);
            cJSON_AddStringToObject(root, "format", "string");
            cJSON_AddNumberToObject(root, "maxLen", 64);
            cJSON_AddItemToArray(perms, cJSON_CreateString("pr"));
            break;
        case HAP_CHARACTER_SERIAL_NUMBER:
            cJSON_AddStringToObject(root, "value", (char*)c->initial_value);
            cJSON_AddStringToObject(root, "format", "string");
            cJSON_AddNumberToObject(root, "maxLen", 64);
            cJSON_AddItemToArray(perms, cJSON_CreateString("pr"));
            break;
        case HAP_CHARACTER_FIRMWARE_REVISION:
            cJSON_AddStringToObject(root, "value", (char*)c->initial_value);
            cJSON_AddStringToObject(root, "format", "string");
            cJSON_AddNumberToObject(root, "maxLen", 64);
            cJSON_AddItemToArray(perms, cJSON_CreateString("pr"));
            break;
        default:
            break;
    }

    return root;
}

static cJSON* _attr_accessories_to_json(struct list_head* attr_accessories)
{
    cJSON* root = cJSON_CreateObject();
    cJSON* accessories = cJSON_CreateArray();
    cJSON_AddItemToObject(root, "accessories", accessories);

    struct hap_acc_accessory* a_ptr;
    struct hap_attr_service* s_ptr;
    list_for_each_entry(a_ptr, attr_accessories, list) {
        cJSON* accessory = cJSON_CreateObject();
        cJSON* services = cJSON_CreateArray();

        cJSON_AddItemToArray(accessories, accessory);
        cJSON_AddNumberToObject(accessory, "aid", a_ptr->aid);
        cJSON_AddItemToObject(accessory, "services", services);

        list_for_each_entry(s_ptr, &a_ptr->services, list) {
            cJSON* service = cJSON_CreateObject();
            cJSON_AddItemToArray(services, service);

            char type[37] = {0,};
            sprintf(type, HAP_UUID, s_ptr->type);
            cJSON_AddStringToObject(service, "type", type);
            cJSON_AddNumberToObject(service, "iid", s_ptr->iid);

            cJSON* characteristics = cJSON_CreateArray();
            cJSON_AddItemToObject(service, "characteristics", characteristics);

            int i;
            struct hap_attr_characteristic* c = (struct hap_attr_characteristic*)&s_ptr->characters;
            for (i=0; i<s_ptr->nr_character; i++, c++) {
                cJSON* characteristic = _attr_characterisic_to_json(c);
                cJSON_AddItemToArray(characteristics, characteristic);
            }
        }
    }

    return root;
}

struct cJSON* _characteristic_value_to_json(int aid, int iid, enum hap_characteristic_type type, void* value)
{
    cJSON* char_json = cJSON_CreateObject();
    cJSON_AddNumberToObject(char_json, "aid", aid);
    cJSON_AddNumberToObject(char_json, "iid", iid);

    switch(type) {
    case HAP_CHARACTER_ON:
        if (value)
            cJSON_AddBoolToObject(char_json, "value", true);
        else 
            cJSON_AddBoolToObject(char_json, "value", false);
        break;
    default:
        break;
    }

    return char_json;
}

static cJSON* _characteristic_read(struct hap_attr_characteristic* c)
{
    if (!c->read)
        return NULL;

    void* value = c->read(c->callback_arg);
    return _characteristic_value_to_json(c->aid, c->iid, c->type, value);
}

int hap_acc_characteristic_get(struct hap_accessory* a, char* query, int len, char** res_header, int* res_header_len, char** res_body, int* res_body_len)
{
    int aid = 0, iid = 0;

    cJSON* root = cJSON_CreateObject();
    cJSON* characteristics = cJSON_CreateArray();
    cJSON_AddItemToObject(root, "characteristics", characteristics);

    sscanf(query, "id=%d.%d", &aid, &iid);
    struct hap_attr_characteristic* c = _attr_character_find(&a->attr_accessories, aid, iid);
    if (c != NULL) {
        cJSON* char_json = _characteristic_read(c);
        cJSON_AddItemToArray(characteristics, char_json);
    }

    int nr_skip = 6;
    if (aid / 10)
        nr_skip++;
    if (iid / 10)
        nr_skip++;

    query += nr_skip;
    len -= nr_skip;

    while (len > 0) {
        sscanf(query, ",%d.%d", &aid, &iid);
        c = _attr_character_find(&a->attr_accessories, aid, iid);
        if (c != NULL) {
            cJSON* char_json = _characteristic_read(c);
            cJSON_AddItemToArray(characteristics, char_json);
        }

        nr_skip = 4;
        if (aid / 10)
            nr_skip++;
        if (iid / 10)
            nr_skip++;

        query += nr_skip;
        len -= nr_skip;
    }


    *res_body = cJSON_PrintUnformatted(root);
    *res_body_len = strlen(*res_body);
    cJSON_Delete(root);

    *res_header = calloc(1, strlen(header_200_fmt) + 16);
    sprintf(*res_header, header_200_fmt, *res_body_len);
    *res_header_len = strlen(*res_header);

    {
        printf("%s%s\n", *res_header, *res_body);
    }

    return 0;
}

void hap_acc_characteristic_get_free(char* res_header, char* res_body)
{
    if (res_header)
        free(res_header);
    if (res_body)
        free(res_body);
}

int hap_acc_characteristic_put(struct hap_accessory* a, struct hap_connection* hc, char* req_body, int req_body_len, char** res_header, int* res_header_len, char** res_body, int* res_body_len)
{
    printf("%.*s\n", req_body_len, req_body);
    cJSON* root = cJSON_Parse(req_body);
    cJSON* char_array_json = cJSON_GetObjectItem(root, "characteristics");
    int nr_char = cJSON_GetArraySize(char_array_json);
    for (int i=0; i<nr_char; i++) {
        cJSON* char_json = cJSON_GetArrayItem(char_array_json, i);
        int aid = cJSON_GetObjectItem(char_json, "aid")->valueint;
        int iid = cJSON_GetObjectItem(char_json, "iid")->valueint;

        struct hap_attr_characteristic* c = _attr_character_find(&a->attr_accessories, aid, iid);
        if (c == NULL)
            continue;

        if (!c->write)
            continue;

        cJSON* ev_json = cJSON_GetObjectItem(char_json, "ev");
        if (ev_json && c->event) {
            if (ev_json->valueint) {
                struct hap_event* ev_handle = calloc(1, sizeof(struct hap_event));
                ev_handle->hc = hc;
                ev_handle->aid = c->aid;
                ev_handle->iid = c->iid;
                ev_handle->type = c->type;
                list_add(&ev_handle->list, &hc->event_head);

                c->event(c->callback_arg, ev_handle, (bool)ev_json->valueint);
            }
            else {
                struct hap_event* ev_handle = NULL;
                struct hap_event* saveptr;
                list_for_each_entry_safe(ev_handle, saveptr, &hc->event_head, list) {
                    if (ev_handle->aid == aid && ev_handle->iid == iid) {
                        c->event(c->callback_arg, ev_handle, (bool)ev_json->valueint);
                        list_del(&ev_handle->list);
                        free(ev_handle);
                        break;
                    }
                }
            }



        }

        cJSON* value_json = cJSON_GetObjectItem(char_json, "value");
        if (value_json) {
            c->write(c->callback_arg, (void*)value_json->valueint, 0);
        }
    }

    *res_header = calloc(1, strlen(header_204_fmt) + 1);
    strcpy(*res_header, header_204_fmt);

    printf("%s\n", *res_header);

    *res_body = NULL;
    *res_body_len = 0;

    return 0;
}

void hap_acc_characteristic_put_free(char* res_header, char* res_body)
{
    if (res_header)
        free(res_header);
    if (res_body)
        free(res_body);
}

int hap_acc_accessories_do(struct hap_accessory* a, char** res_header, int* res_header_len, char** res_body, int* res_body_len)
{
    if (list_empty(&a->attr_accessories)) {
        a->callback.hap_object_init(a->callback_arg);
        a->attr_accessories_json = _attr_accessories_to_json(&a->attr_accessories);
    }

    *res_body = cJSON_PrintUnformatted(a->attr_accessories_json);
    *res_body_len = strlen(*res_body);

    *res_header = calloc(1, strlen(header_200_fmt) + 16);
    sprintf(*res_header, header_200_fmt, *res_body_len);
    *res_header_len = strlen(*res_header);

    return 0;
}

void hap_acc_accessories_do_free(char* res_header, char* res_body)
{
    if (res_header)
        free(res_header);
    if (res_body)
        free(res_body);
}

void hap_acc_event_response(struct hap_event* ev, void* value, char** res_header, int* res_header_len, char** res_body, int* res_body_len)
{
    cJSON* root = cJSON_CreateObject();
    cJSON* characteristics = cJSON_CreateArray();
    cJSON_AddItemToObject(root, "characteristics", characteristics);
    cJSON* char_json = _characteristic_value_to_json(ev->aid, ev->iid, ev->type, value);
    cJSON_AddItemToArray(characteristics, char_json);

    *res_body = cJSON_PrintUnformatted(root);
    *res_body_len = strlen(*res_body);
    cJSON_Delete(root);

    *res_header = calloc(1, strlen(header_200_fmt) + 16);
    sprintf(*res_header, header_200_fmt, *res_body_len);
    *res_header_len = strlen(*res_header);
}

void hap_acc_event_response_free(char* res_header, char* res_body)
{
    if (res_header)
        free(res_header);
    if (res_body)
        free(res_body);
}

void hap_acc_event_free(struct hap_connection* hc)
{
    struct hap_event* ev_handle = NULL;
    struct hap_event* saveptr;

    list_for_each_entry_safe(ev_handle, saveptr, &hc->event_head, list) {
        list_del(&ev_handle->list);
        free(ev_handle);
    }
}

void* hap_acc_accessory_add(void* acc_instance)
{
    struct hap_accessory* a = acc_instance;

    struct hap_acc_accessory* attr_a = calloc(1, sizeof(struct hap_acc_accessory));
    attr_a->aid = ++a->last_aid;
    list_add_tail(&attr_a->list, &a->attr_accessories);
    INIT_LIST_HEAD(&attr_a->services);

    return (void*)attr_a;
}

void* hap_acc_service_and_characteristics_add(void* _attr_a,
        enum hap_service_type type, struct hap_characteristic* cs, int nr_cs) 
{
    struct hap_acc_accessory* attr_a = _attr_a;
    struct hap_attr_service* attr_s = calloc(1, sizeof(struct hap_attr_service) + sizeof(struct hap_attr_characteristic) * nr_cs);
    attr_s->iid = ++attr_a->last_iid;
    attr_s->type = type;;
    attr_s->nr_character = nr_cs;
    list_add_tail(&attr_s->list, &attr_a->services);

    struct hap_attr_characteristic* c = (struct hap_attr_characteristic*)&attr_s->characters;
    for (int i=0; i<nr_cs; i++) {
        c->iid = ++attr_a->last_iid;
        c->type = cs[i].type;
        c->initial_value = cs[i].initial_value;
        c->read = cs[i].read;
        c->write = cs[i].write;
        c->event = cs[i].event;
        c->aid = attr_a->aid;
        c++;
    }

    return NULL;
}
