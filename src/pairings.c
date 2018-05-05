#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "hap_internal.h"
#include "iosdevice.h"
#include "pair_error.h"
#include "tlv.h"

static const char* header_fmt = 
    "HTTP/1.1 200 OK\r\n"
    "Content-Length: %d\r\n"
    "Content-Type: application/pairing+tlv8\r\n"
    "\r\n";

static uint8_t _state_get(uint8_t* device_msg, int device_msg_length)
{
    struct tlv* state_tlv = tlv_decode((uint8_t*)device_msg, device_msg_length, 
            HAP_TLV_TYPE_STATE);
    if (state_tlv == NULL) {
        printf("tlv_decode failed. type:%d\n", HAP_TLV_TYPE_STATE);
        return 0;
    }

    uint8_t state = ((uint8_t*)&state_tlv->value)[0];

    tlv_decoded_item_free(state_tlv);
    return state;
}

static enum hap_pairing_method _method_get(uint8_t* device_msg, int device_msg_length)
{
    struct tlv* method_tlv = tlv_decode((uint8_t*)device_msg, device_msg_length, 
            HAP_TLV_TYPE_METHOD);
    if (method_tlv == NULL) {
        printf("tlv_decode failed. type:%d\n", HAP_TLV_TYPE_METHOD);
        return 0;
    }

    uint8_t method = ((uint8_t*)&method_tlv->value)[0];

    tlv_decoded_item_free(method_tlv);
    return (enum hap_pairing_method)method;
}

#if 0
static int _list(void* iosdevices, uint8_t* device_msg, int device_msg_length, uint8_t** acc_msg, int* acc_msg_length) {
    struct iosdevice idevices[IOSDEVICE_PER_ACCESSORY_MAX];
    int nr_devices = iosdevice_pairings(iosdevices, idevices);

    int tlv_length_for_one_device = tlv_encode_length(IOSDEVICE_ID_LEN);
    tlv_length_for_one_device += tlv_encode_length(ED25519_PUBLIC_KEY_LENGTH);
    tlv_length_for_one_device += tlv_encode_length(sizeof(uint8_t)); /* length for KTLVType_Permission */
    tlv_length_for_one_device += tlv_encode_length(0); /* length for KTLVType_Seperator */

    uint8_t state[] = {2};
    *acc_msg_length = tlv_encode_length(sizeof(state));
    *acc_msg_length += tlv_length_for_one_device * nr_devices; 

    (*acc_msg) = malloc(*acc_msg_length);
    if (*acc_msg == NULL) {
        printf("malloc failed\n");
        return pair_error(HAP_TLV_ERROR_UNKNOWN, acc_msg, acc_msg_length);
    }

    uint8_t* tlv_encode_ptr = *acc_msg;
    tlv_encode_ptr += tlv_encode(HAP_TLV_TYPE_STATE, sizeof(state), state, tlv_encode_ptr);
    tlv_encode_ptr += tlv_encode(HAP_TLV_TYPE_IDENTIFIER, IOSDEVICE_ID_LEN, idevices[0].id, tlv_encode_ptr);
    tlv_encode_ptr += tlv_encode(HAP_TLV_TYPE_PUBLICKEY, ED25519_PUBLIC_KEY_LENGTH, idevices[0].key, tlv_encode_ptr);
    tlv_encode_ptr += tlv_encode(HAP_TLV_TYPE_PERMISSION, sizeof(uint8_t), &idevices[0].permission, tlv_encode_ptr);

    //TODO FIXME
    return 0;
}
#endif

static int _add(void* iosdevices, uint8_t* device_msg, int device_msg_length, uint8_t** acc_msg, int* acc_msg_length) {
    struct tlv* identifier = tlv_decode(device_msg, device_msg_length, HAP_TLV_TYPE_IDENTIFIER);
    struct tlv* public_key = tlv_decode(device_msg, device_msg_length, HAP_TLV_TYPE_PUBLICKEY);
    struct tlv* permission = tlv_decode(device_msg, device_msg_length, HAP_TLV_TYPE_PERMISSION);
    printf("[PAIRINGS] ADD ID:%.*s KEY:%.*s PERM:0x%x,%d\n", 
            identifier->length, (uint8_t*)&identifier->value,
            public_key->length, (uint8_t*)&public_key->value,
            (uint8_t*)&permission->value, (uint8_t*)&permission->value);

    iosdevice_pairings_add(iosdevices, (uint8_t*)&identifier->value, (uint8_t*)&public_key->value);

    uint8_t state[] = {2};
    *acc_msg_length = tlv_encode_length(sizeof(state));

    (*acc_msg) = malloc(*acc_msg_length);
    if (*acc_msg == NULL) {
        printf("malloc failed\n");
        return pair_error(HAP_TLV_ERROR_UNKNOWN, acc_msg, acc_msg_length);
    }

    uint8_t* tlv_encode_ptr = *acc_msg;
    tlv_encode_ptr += tlv_encode(HAP_TLV_TYPE_STATE, sizeof(state), state, tlv_encode_ptr);

    return 0;
}

static int _remove(void* iosdevices, uint8_t* device_msg, int device_msg_length, uint8_t** acc_msg, int* acc_msg_length) {
    struct tlv* remove_identifier = tlv_decode(device_msg, device_msg_length, HAP_TLV_TYPE_IDENTIFIER);
    if (!remove_identifier) {
        printf("tlv_decode failed. type:%d\n", HAP_TLV_TYPE_IDENTIFIER);
        return -1;
    }
    printf("%.*s\n",remove_identifier->length , ((uint8_t*)&remove_identifier->value));
    iosdevice_pairings_remove(iosdevices, (uint8_t*)&remove_identifier->value);
#if 0
    for (int i=0; i<remove_identifier->length; i++) {
        printf("%X ", ((uint8_t*)&remove_identifier->value)[i]);
    }
#endif

    uint8_t state[] = {2};
    *acc_msg_length = tlv_encode_length(sizeof(state));

    (*acc_msg) = malloc(*acc_msg_length);
    if (*acc_msg == NULL) {
        printf("malloc failed\n");
        return pair_error(HAP_TLV_ERROR_UNKNOWN, acc_msg, acc_msg_length);
    }

    uint8_t* tlv_encode_ptr = *acc_msg;
    tlv_encode_ptr += tlv_encode(HAP_TLV_TYPE_STATE, sizeof(state), state, tlv_encode_ptr);

    return 0;
}

int pairings_do(void* iosdevices, char* req_body, int req_body_len, 
        char** res_header, int* res_header_len, char** res_body, int* res_body_len)
{
    uint8_t state = _state_get((uint8_t*)req_body, req_body_len);
    enum hap_pairing_method method = _method_get((uint8_t*)req_body, req_body_len);

    printf("[PAIRINGS] STATE:%d METHOD:%d\n", state, method);

    if (method == HAP_PAIRING_METHOD_ADD) {
        _add(iosdevices, (uint8_t*)req_body, req_body_len, (uint8_t**)res_body, res_body_len);
        *res_header = malloc(strlen(header_fmt) + 16);
        sprintf(*res_header, header_fmt, *res_body_len);
        *res_header_len = strlen(*res_header);
    }
    else if (method == HAP_PAIRING_METHOD_REMOVE) {
        _remove(iosdevices, (uint8_t*)req_body, req_body_len, (uint8_t**)res_body, res_body_len);
        *res_header = malloc(strlen(header_fmt) + 16);
        sprintf(*res_header, header_fmt, *res_body_len);
        *res_header_len = strlen(*res_header);
    }
    /*
    else if (method == HAP_PAIRING_METHOD_LIST) {
        _list(iosdevices, (uint8_t*)req_body, req_body_len, (uint8_t**)res_body, res_body_len);
        *res_header = malloc(strlen(header_fmt) + 16);
        sprintf(*res_header, header_fmt, *res_body_len);
        *res_header_len = strlen(*res_header);
    }
    */

    return 0;
}

void pairings_do_free(char* res_header, char*res_body)
{
    if (res_header)
        free(res_header);

    if (res_body)
        free(res_body);
}
