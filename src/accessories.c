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
    enum {
        PERMS_READ = 0x01,
        PERMS_WRITE = 0x02,
        PERMS_EVENT = 0x04,
    } perms;

    enum {
        FORMAT_BOOL,
        FORMAT_UINT8,
        FORMAT_UINT32,
        FORMAT_UINT64,
        FORMAT_INT,
        FORMAT_FLOAT,
        FORMAT_STRING,
        FORMAT_TLV8,
        FORMAT_DATA,
    } format;

    enum hap_characteristic_type type;
    void* initial_value;
    void* callback_arg;
    void* (*read)(void* arg);
    void (*write)(void* arg, void* value, int value_len);
    void (*event)(void* arg, void* ev_handle, bool enable);
};


static const char* header_204_fmt = 
    "HTTP/1.1 204 No Content\r\n"
    //"Connection: keep-alive\r\n"
    //"Content-type: application/hap+json\r\n"
    "\r\n";

static const char* header_200_fmt = 
    "HTTP/1.1 200 OK\r\n"
    //"Connection: keep-alive\r\n"
    "Content-Type: application/hap+json\r\n"
    "Content-Length: %d\r\n"
    "\r\n";

static const char* header_event_200_fmt = 
    "EVENT/1.0 200 OK\r\n"
    "Content-Type: application/hap+json\r\n"
    "Content-Length: %d\r\n"
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

static cJSON* _value_to_formatized_json(struct hap_attr_characteristic* c, void* value)
{
    switch (c->format) {
        case FORMAT_BOOL:
            return cJSON_CreateBool(value);
        case FORMAT_UINT8:
        case FORMAT_UINT32:
        case FORMAT_UINT64:
        case FORMAT_INT:
            return cJSON_CreateNumber((int)value);
        case FORMAT_FLOAT: {
            int value_interger = (int)value;
            double floating_value = (double)value_interger / 100;
            return cJSON_CreateNumber(floating_value);
        }
        case FORMAT_STRING:
            return cJSON_CreateString((char*)value);
        default:
            printf("Unimplemented charac format(%d)\n", c->format);
            return cJSON_CreateNull();
    }
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
    if (c->perms & PERMS_READ)
        cJSON_AddItemToArray(perms, cJSON_CreateString("pr"));
    if (c->perms & PERMS_WRITE)
        cJSON_AddItemToArray(perms, cJSON_CreateString("pw"));
    if (c->perms & PERMS_EVENT)
        cJSON_AddItemToArray(perms, cJSON_CreateString("ev"));

    switch (c->format) {
        case FORMAT_BOOL:
            cJSON_AddStringToObject(root, "format", "bool");
            break;
        case FORMAT_UINT8:
            cJSON_AddStringToObject(root, "format", "uint8");
            break;
        case FORMAT_UINT32:
            cJSON_AddStringToObject(root, "format", "uint32");
            break;
        case FORMAT_UINT64:
            cJSON_AddStringToObject(root, "format", "uint64");
            break;
        case FORMAT_INT:
            cJSON_AddStringToObject(root, "format", "int");
            break;
        case FORMAT_FLOAT:
            cJSON_AddStringToObject(root, "format", "float");
            break;
        case FORMAT_STRING:
            cJSON_AddStringToObject(root, "format", "string");
            break;
        case FORMAT_TLV8:
            cJSON_AddStringToObject(root, "format", "tlv8");
            break;
        case FORMAT_DATA:
            cJSON_AddStringToObject(root, "format", "data");
            break;
    }

    if (c->perms & PERMS_READ) {
        void* value = NULL;
        if (c->read)
            value = c->read(c->callback_arg);
        else
            value = c->initial_value;

        cJSON_AddItemToObject(root, "value", _value_to_formatized_json(c, value));
    }
    else {
        if (c->type != HAP_CHARACTER_IDENTIFY)
            cJSON_AddNullToObject(root, "value");
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

struct cJSON* _characteristic_value_to_json(struct hap_attr_characteristic* c, void* value)
{
    cJSON* char_json = cJSON_CreateObject();
    cJSON_AddNumberToObject(char_json, "aid", c->aid);
    cJSON_AddNumberToObject(char_json, "iid", c->iid);
    cJSON_AddItemToObject(char_json, "value", _value_to_formatized_json(c, value));
    return char_json;
}

static cJSON* _characteristic_read(struct hap_attr_characteristic* c)
{
    if (!c->read)
        return NULL;

    void* value = c->read(c->callback_arg);
    return _characteristic_value_to_json(c, value);
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

        cJSON* ev_json = cJSON_GetObjectItem(char_json, "ev");
        if (ev_json && c->event) {
            if (ev_json->valueint) {
                c->event(c->callback_arg, (void*)c, (bool)ev_json->valueint);
            }
            else {
                c->event(c->callback_arg, (void*)c, (bool)ev_json->valueint);
            }
        }

        cJSON* value_json = cJSON_GetObjectItem(char_json, "value");
        if (value_json && c->write) {
            c->write(c->callback_arg, (void*)value_json->valueint, 0);
        }
    }

    *res_header = calloc(1, strlen(header_204_fmt) + 1);
    strcpy(*res_header, header_204_fmt);
    *res_header_len = strlen(*res_header);

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
    }
    cJSON* attr_accessories_json = _attr_accessories_to_json(&a->attr_accessories);

    *res_body = cJSON_PrintUnformatted(attr_accessories_json);
    *res_body_len = strlen(*res_body);
    free(attr_accessories_json);

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

void hap_acc_event_response(void* ev, void* value, char** res_header, int* res_header_len, char** res_body, int* res_body_len)
{
    struct hap_attr_characteristic* c = ev;
    cJSON* root = cJSON_CreateObject();
    cJSON* characteristics = cJSON_CreateArray();
    cJSON_AddItemToObject(root, "characteristics", characteristics);
    cJSON* char_json = _characteristic_value_to_json(c, value);
    cJSON_AddItemToArray(characteristics, char_json);

    *res_body = cJSON_PrintUnformatted(root);
    *res_body_len = strlen(*res_body);
    cJSON_Delete(root);

    *res_header = calloc(1, strlen(header_event_200_fmt) + 16);
    sprintf(*res_header, header_event_200_fmt, *res_body_len);
    *res_header_len = strlen(*res_header);
}

void hap_acc_event_response_free(char* res_header, char* res_body)
{
    if (res_header)
        free(res_header);
    if (res_body)
        free(res_body);
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

static void _characteristic_properties_define(struct hap_attr_characteristic* c)
{
    switch (c->type) {
        case HAP_CHARACTER_ADMINISTRATOR_ONLY_ACCESS:
            c->perms = (PERMS_READ | PERMS_WRITE | PERMS_EVENT);
            c->format = FORMAT_BOOL;
            break;
        case HAP_CHARACTER_AUDIO_FEEDBACK:
            c->perms = (PERMS_READ | PERMS_WRITE | PERMS_EVENT);
            c->format = FORMAT_BOOL;
            break;
        case HAP_CHARACTER_BRIGHTNESS:
            c->perms = (PERMS_READ | PERMS_WRITE | PERMS_EVENT);
            c->format = FORMAT_INT;
            break;
        case HAP_CHARACTER_COOLING_THRESHOLD_TEMPERATURE:
            c->perms = (PERMS_READ | PERMS_WRITE | PERMS_EVENT);
            c->format = FORMAT_FLOAT;
            break;
        case HAP_CHARACTER_CURRENT_DOOR_STATE:
            c->perms = (PERMS_READ | PERMS_EVENT);
            c->format = FORMAT_UINT8;
            break;
        case HAP_CHARACTER_CURRENT_HEATING_COOLING_STATE:
            c->perms = (PERMS_READ | PERMS_EVENT);
            c->format = FORMAT_UINT8;
            break;
        case HAP_CHARACTER_CURRENT_RELATIVE_HUMIDITY:
            c->perms = (PERMS_READ | PERMS_EVENT);
            c->format = FORMAT_FLOAT;
            break;
        case HAP_CHARACTER_CURRENT_TEMPERATURE:
            c->perms = (PERMS_READ | PERMS_EVENT);
            c->format = FORMAT_FLOAT;
            break;
        case HAP_CHARACTER_FIRMWARE_REVISION:
            c->perms = PERMS_READ;
            c->format = FORMAT_STRING;
            break;
        case HAP_CHARACTER_HARDWARE_REVISION:
            c->perms = PERMS_READ;
            c->format = FORMAT_STRING;
            break;
        case HAP_CHARACTER_HEATING_THRESHOLD_TEMPERATURE:
            c->perms = (PERMS_READ | PERMS_WRITE | PERMS_EVENT);
            c->format = FORMAT_FLOAT;
            break;
        case HAP_CHARACTER_HUE:
            c->perms = (PERMS_READ | PERMS_WRITE | PERMS_EVENT);
            c->format = FORMAT_FLOAT;
            break;
        case HAP_CHARACTER_IDENTIFY:
            c->perms = PERMS_WRITE;
            c->format = FORMAT_BOOL;
            break;
        case HAP_CHARACTER_LOCK_CONTROL_POINT:
            c->perms = PERMS_WRITE;
            c->format = FORMAT_TLV8;
            break;
        case HAP_CHARACTER_LOCK_CURRENT_STATE:
            c->perms = (PERMS_READ | PERMS_EVENT);
            c->format = FORMAT_UINT8;
            break;
        case HAP_CHARACTER_LOCK_LAST_KNOWN_ACTION:
            c->perms = (PERMS_READ | PERMS_EVENT);
            c->format = FORMAT_UINT8;
            break;
        case HAP_CHARACTER_LOCK_MANAGEMENT_AUTO_SECURITY_TIMEOUT:
            c->perms = (PERMS_READ | PERMS_WRITE | PERMS_EVENT);
            c->format = FORMAT_UINT32;
            break;
        case HAP_CHARACTER_LOCK_TARGET_STATE:
            c->perms = (PERMS_READ | PERMS_WRITE | PERMS_EVENT);
            c->format = FORMAT_UINT8;
            break;
        case HAP_CHARACTER_LOGS:
            c->perms = (PERMS_READ | PERMS_EVENT);
            c->format = FORMAT_TLV8;
            break;
        case HAP_CHARACTER_MANUFACTURER:
            c->perms = PERMS_READ;
            c->format = FORMAT_STRING;
            break;
        case HAP_CHARACTER_MODEL:
            c->perms = PERMS_READ;
            c->format = FORMAT_STRING;
            break;
        case HAP_CHARACTER_MOTION_DETECTED:
            c->perms = (PERMS_READ | PERMS_EVENT);
            c->format = FORMAT_BOOL;
            break;
        case HAP_CHARACTER_NAME:
            c->perms = PERMS_READ;
            c->format = FORMAT_STRING;
            break;
        case HAP_CHARACTER_OBSTRUCTION_DETECTED:
            c->perms = (PERMS_READ | PERMS_EVENT);
            c->format = FORMAT_BOOL;
            break;
        case HAP_CHARACTER_ON:
            c->perms = (PERMS_READ | PERMS_WRITE | PERMS_EVENT);
            c->format = FORMAT_BOOL;
            break;
        case HAP_CHARACTER_OUTLET_IN_USE:
            c->perms = (PERMS_READ | PERMS_EVENT);
            c->format = FORMAT_BOOL;
            break;
        case HAP_CHARACTER_ROTATION_DIRECTION:
            c->perms = (PERMS_READ | PERMS_WRITE | PERMS_EVENT);
            c->format = FORMAT_INT;
            break;
        case HAP_CHARACTER_ROTATION_SPEED:
            c->perms = (PERMS_READ | PERMS_WRITE | PERMS_EVENT);
            c->format = FORMAT_FLOAT;
            break;
        case HAP_CHARACTER_SATURATION:
            c->perms = (PERMS_READ | PERMS_WRITE | PERMS_EVENT);
            c->format = FORMAT_FLOAT;
            break;
        case HAP_CHARACTER_SERIAL_NUMBER:
            c->perms = PERMS_READ;
            c->format = FORMAT_STRING;
            break;
        case HAP_CHARACTER_TARGET_DOORSTATE:
            c->perms = (PERMS_READ | PERMS_WRITE | PERMS_EVENT);
            c->format = FORMAT_UINT8;
            break;
        case HAP_CHARACTER_TARGET_HEATING_COOLING_STATE:
            c->perms = (PERMS_READ | PERMS_WRITE | PERMS_EVENT);
            c->format = FORMAT_UINT8;
            break;
        case HAP_CHARACTER_TARGET_RELATIVE_HUMIDITY:
            c->perms = (PERMS_READ | PERMS_WRITE | PERMS_EVENT);
            c->format = FORMAT_FLOAT;
            break;
        case HAP_CHARACTER_TARGET_TEMPERATURE:
            c->perms = (PERMS_READ | PERMS_WRITE | PERMS_EVENT);
            c->format = FORMAT_FLOAT;
            break;
        case HAP_CHARACTER_TEMPERATURE_DISPLAY_UNITS:
            c->perms = (PERMS_READ | PERMS_WRITE | PERMS_EVENT);
            c->format = FORMAT_UINT8;
            break;
        case HAP_CHARACTER_VERSION:
            c->perms = PERMS_READ;
            c->format = FORMAT_STRING;
            break;
        case HAP_CHARACTER_AIR_PARTICULATE_DENSITY:
            c->perms = (PERMS_READ | PERMS_EVENT);
            c->format = FORMAT_FLOAT;
            break;
        case HAP_CHARACTER_AIR_PARTICULATE_SIZE:
            c->perms = (PERMS_READ | PERMS_EVENT);
            c->format = FORMAT_UINT8;
            break;
        case HAP_CHARACTER_SECURITY_SYSTEM_CURRENT_STATE:
            c->perms = (PERMS_READ | PERMS_EVENT);
            c->format = FORMAT_UINT8;
            break;
        case HAP_CHARACTER_SECURITY_SYSTEM_TARGET_STATE:
            c->perms = (PERMS_READ | PERMS_WRITE | PERMS_EVENT);
            c->format = FORMAT_UINT8;
            break;
        case HAP_CHARACTER_BATTERY_LEVER:
            c->perms = (PERMS_READ | PERMS_EVENT);
            c->format = FORMAT_UINT8;
            break;
        case HAP_CHARACTER_CARBON_MONOXIDE_DETECTED:
            c->perms = (PERMS_READ | PERMS_EVENT);
            c->format = FORMAT_UINT8;
            break;
        case HAP_CHARACTER_CONTACT_SENSOR_STATE:
            c->perms = (PERMS_READ | PERMS_EVENT);
            c->format = FORMAT_UINT8;
            break;
        case HAP_CHARACTER_CURRENT_AMBIENT_LIGHT_LEVEL:
            c->perms = (PERMS_READ | PERMS_EVENT);
            c->format = FORMAT_FLOAT;
            break;
        case HAP_CHARACTER_CURRENT_HORIZONTAL_TILT_ANGLE:
            c->perms = (PERMS_READ | PERMS_EVENT);
            c->format = FORMAT_INT;
            break;
        case HAP_CHARACTER_CURRENT_POSITION:
            c->perms = (PERMS_READ | PERMS_EVENT);
            c->format = FORMAT_UINT8;
            break;
        case HAP_CHARACTER_CURRENT_VERTICAL_TILT_ANGLE:
            c->perms = (PERMS_READ | PERMS_EVENT);
            c->format = FORMAT_INT;
            break;
        case HAP_CHARACTER_HOLD_POSITION:
            c->perms = PERMS_WRITE;
            c->format = FORMAT_BOOL;
            break;
        case HAP_CHARACTER_LEAK_DETECTED:
            c->perms = (PERMS_READ | PERMS_EVENT);
            c->format = FORMAT_UINT8;
            break;
        case HAP_CHARACTER_OCCUPANCY_DETECTED:
            c->perms = (PERMS_READ | PERMS_EVENT);
            c->format = FORMAT_UINT8;
            break;
        case HAP_CHARACTER_POSITION_STATE:
            c->perms = (PERMS_READ | PERMS_EVENT);
            c->format = FORMAT_UINT8;
            break;
        case HAP_CHARACTER_PROGRAMMABLE_SWITCH_EVENT:
            c->perms = (PERMS_READ | PERMS_EVENT);
            c->format = FORMAT_UINT8;
            break;
        case HAP_CHARACTER_STATUS_ACTIVE:
            c->perms = (PERMS_READ | PERMS_EVENT);
            c->format = FORMAT_BOOL;
            break;
        case HAP_CHARACTER_SMOKE_DETECTED:
            c->perms = (PERMS_READ | PERMS_EVENT);
            c->format = FORMAT_UINT8;
            break;
        case HAP_CHARACTER_STATUS_FAULT:
            c->perms = (PERMS_READ | PERMS_EVENT);
            c->format = FORMAT_UINT8;
            break;
        case HAP_CHARACTER_STATUS_JAMMED:
            c->perms = (PERMS_READ | PERMS_EVENT);
            c->format = FORMAT_UINT8;
            break;
        case HAP_CHARACTER_STATUS_LOW_BATTERY:
            c->perms = (PERMS_READ | PERMS_EVENT);
            c->format = FORMAT_UINT8;
            break;
        case HAP_CHARACTER_STATUS_TAMPERED:
            c->perms = (PERMS_READ | PERMS_EVENT);
            c->format = FORMAT_UINT8;
            break;
        case HAP_CHARACTER_TARGET_HORIZONTAL_TILT_ANGLE:
            c->perms = (PERMS_READ | PERMS_WRITE | PERMS_EVENT);
            c->format = FORMAT_INT;
            break;
        case HAP_CHARACTER_TARGET_POSITION:
            c->perms = (PERMS_READ | PERMS_WRITE | PERMS_EVENT);
            c->format = FORMAT_UINT8;
            break;
        case HAP_CHARACTER_TARGET_VERTICAL_TILT_ANGLE:
            c->perms = (PERMS_READ | PERMS_WRITE | PERMS_EVENT);
            c->format = FORMAT_INT;
            break;
        case HAP_CHARACTER_SECURITY_SYSTEM_ALARM_TYPE:
            c->perms = (PERMS_READ | PERMS_EVENT);
            c->format = FORMAT_UINT8;
            break;
        case HAP_CHARACTER_CHARGING_STATE:
            c->perms = (PERMS_READ | PERMS_EVENT);
            c->format = FORMAT_UINT8;
            break;
        case HAP_CHARACTER_CARBON_MONOXIDE_LEVEL:
            c->perms = (PERMS_READ | PERMS_EVENT);
            c->format = FORMAT_FLOAT;
            break;
        case HAP_CHARACTER_CARBON_MONOXIDE_PEAK_LEVEL:
            c->perms = (PERMS_READ | PERMS_EVENT);
            c->format = FORMAT_FLOAT;
            break;
        case HAP_CHARACTER_CARBON_DIOXIDE_DETECTED:
            c->perms = (PERMS_READ | PERMS_EVENT);
            c->format = FORMAT_UINT8;
            break;
        case HAP_CHARACTER_CARBON_DIOXIDE_LEVEL:
            c->perms = (PERMS_READ | PERMS_EVENT);
            c->format = FORMAT_FLOAT;
            break;
        case HAP_CHARACTER_CARBON_DIOXIDE_PEAK_LEVEL:
            c->perms = (PERMS_READ | PERMS_EVENT);
            c->format = FORMAT_FLOAT;
            break;
        case HAP_CHARACTER_AIR_QUALITY:
            c->perms = (PERMS_READ | PERMS_EVENT);
            c->format = FORMAT_UINT8;
            break;
        case HAP_CHARACTER_STREAMING_STATUS:
            c->perms = (PERMS_READ | PERMS_EVENT);
            c->format = FORMAT_TLV8;
            break;
        case HAP_CHARACTER_SUPPORTED_VIDEO_STREAMING_CONFIGURATION:
            c->perms = PERMS_READ;
            c->format = FORMAT_TLV8;
            break;
        case HAP_CHARACTER_SUPPORTED_AUDIO_STREAMING_CONFIGURATION:
            c->perms = (PERMS_READ);
            c->format = FORMAT_TLV8;
            break;
        case HAP_CHARACTER_SUPPORTED_RTP_CONFIGURATION:
            c->perms = (PERMS_READ);
            c->format = FORMAT_TLV8;
            break;
        case HAP_CHARACTER_SETUP_ENDPOINTS:
            c->perms = (PERMS_READ | PERMS_EVENT);
            c->format = FORMAT_TLV8;
            break;
        case HAP_CHARACTER_SELECTED_RTP_STREAM_CONFIGURATION:
            c->perms = (PERMS_WRITE);
            c->format = FORMAT_TLV8;
            break;
        case HAP_CHARACTER_VOLUME:
            c->perms = (PERMS_READ | PERMS_WRITE | PERMS_EVENT);
            c->format = FORMAT_UINT8;
            break;
        case HAP_CHARACTER_MUTE:
            c->perms = (PERMS_READ | PERMS_WRITE | PERMS_EVENT);
            c->format = FORMAT_BOOL;
            break;
        case HAP_CHARACTER_NIGHT_VISION:
            c->perms = (PERMS_READ | PERMS_WRITE | PERMS_EVENT);
            c->format = FORMAT_BOOL;
            break;
        case HAP_CHARACTER_OPTICAL_ZOOM:
            c->perms = (PERMS_READ | PERMS_WRITE | PERMS_EVENT);
            c->format = FORMAT_FLOAT;
            break;
        case HAP_CHARACTER_DIGITAL_ZOOM:
            c->perms = (PERMS_READ | PERMS_WRITE | PERMS_EVENT);
            c->format = FORMAT_FLOAT;
            break;
        case HAP_CHARACTER_IMAGE_ROTATION:
            c->perms = (PERMS_READ | PERMS_WRITE | PERMS_EVENT);
            c->format = FORMAT_FLOAT;
            break;
        case HAP_CHARACTER_IMAGE_MIRRORING:
            c->perms = (PERMS_READ | PERMS_WRITE | PERMS_EVENT);
            c->format = FORMAT_BOOL;
            break;
        case HAP_CHARACTER_ACCESSORY_FLAGS:
            c->perms = (PERMS_READ | PERMS_EVENT);
            c->format = FORMAT_UINT32;
            break;
        case HAP_CHARACTER_LOCK_PHYSICAL_CONTROLS:
            c->perms = (PERMS_READ | PERMS_WRITE | PERMS_EVENT);
            c->format = FORMAT_UINT8;
            break;
        case HAP_CHARACTER_CURRENT_AIR_PURIFIER_STATE:
            c->perms = (PERMS_READ | PERMS_EVENT);
            c->format = FORMAT_UINT8;
            break;
        case HAP_CHARACTER_CURRENT_SLAT_STATE:
            c->perms = (PERMS_READ | PERMS_EVENT);
            c->format = FORMAT_UINT8;
            break;
        case HAP_CHARACTER_SLAT_TYPE:
            c->perms = PERMS_READ;
            c->format = FORMAT_UINT8;
            break;
        case HAP_CHARACTER_FILTER_LIFE_LEVEL:
            c->perms = (PERMS_READ | PERMS_EVENT);
            c->format = FORMAT_FLOAT;
            break;
        case HAP_CHARACTER_FILTER_CHANGE_INDICATION:
            c->perms = (PERMS_READ | PERMS_EVENT);
            c->format = FORMAT_UINT8;
            break;
        case HAP_CHARACTER_RESET_FILTER_INDICATION:
            c->perms = PERMS_WRITE;
            c->format = FORMAT_UINT8;
            break;
        case HAP_CHARACTER_TARGET_AIR_PURIFIER_STATE:
            c->perms = (PERMS_READ | PERMS_WRITE | PERMS_EVENT);
            c->format = FORMAT_UINT8;
            break;
        case HAP_CHARACTER_TARGET_FAN_STATE:
            c->perms = (PERMS_READ | PERMS_WRITE | PERMS_EVENT);
            c->format = FORMAT_UINT8;
            break;
        case HAP_CHARACTER_CURRENT_FAN_STATE:
            c->perms = (PERMS_READ | PERMS_EVENT);
            c->format = FORMAT_UINT8;
            break;
        case HAP_CHARACTER_ACTIVE:
            c->perms = (PERMS_READ | PERMS_WRITE | PERMS_EVENT);
            c->format = FORMAT_UINT8;
            break;
        case HAP_CHARACTER_SWING_MODE:
            c->perms = (PERMS_READ | PERMS_WRITE | PERMS_EVENT);
            c->format = FORMAT_UINT8;
            break;
        case HAP_CHARACTER_CURRENT_TILT_ANGLE:
            c->perms = (PERMS_READ | PERMS_EVENT);
            c->format = FORMAT_INT;
            break;
        case HAP_CHARACTER_TARGET_TILT_ANGLE:
            c->perms = (PERMS_READ | PERMS_WRITE | PERMS_EVENT);
            c->format = FORMAT_INT;
            break;
        case HAP_CHARACTER_OZONE_DENSITY:
            c->perms = (PERMS_READ | PERMS_EVENT);
            c->format = FORMAT_FLOAT;
            break;
        case HAP_CHARACTER_NITROGEN_DIOXIDE_DENSITY:
            c->perms = (PERMS_READ | PERMS_EVENT);
            c->format = FORMAT_FLOAT;
            break;
        case HAP_CHARACTER_SULPHUR_DIOXIDE_DENSITY:
            c->perms = (PERMS_READ | PERMS_EVENT);
            c->format = FORMAT_FLOAT;
            break;
        case HAP_CHARACTER_PM2_5_DENSITY:
            c->perms = (PERMS_READ | PERMS_EVENT);
            c->format = FORMAT_FLOAT;
            break;
        case HAP_CHARACTER_PM10_DENSITY:
            c->perms = (PERMS_READ | PERMS_EVENT);
            c->format = FORMAT_FLOAT;
            break;
        case HAP_CHARACTER_VOC_DENSITY:
            c->perms = (PERMS_READ | PERMS_EVENT);
            c->format = FORMAT_FLOAT;
            break;
        case HAP_CHARACTER_SERVICE_LABEL_INDEX:
            c->perms = PERMS_READ;
            c->format = FORMAT_UINT8;
            break;
        case HAP_CHARACTER_SERVICE_LABEL_NAMESPACE:
            c->perms = PERMS_READ;
            c->format = FORMAT_UINT8;
            break;
        case HAP_CHARACTER_COLOR_TEMPERATURE:
            c->perms = (PERMS_READ | PERMS_WRITE | PERMS_EVENT);
            c->format = FORMAT_UINT32;
            break;
        default:
            break;
    }
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
        c->callback_arg = cs[i].callback_arg;
        c->iid = ++attr_a->last_iid;
        c->type = cs[i].type;
        c->initial_value = cs[i].initial_value;
        c->read = cs[i].read;
        c->write = cs[i].write;
        c->event = cs[i].event;
        c->aid = attr_a->aid;
        _characteristic_properties_define(c);
        c++;
    }

    return NULL;
}
