#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "hap_internal.h"
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

static int _remove(uint8_t* device_msg, int device_msg_length, uint8_t** acc_msg, int* acc_msg_length) {
    struct tlv* remove_identifier = tlv_decode(device_msg, device_msg_length, HAP_TLV_TYPE_IDENTIFIER);
    printf("%.*s\n",remove_identifier->length , ((uint8_t*)&remove_identifier->value));
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

int pairings_do(char* req_body, int req_body_len, 
        char** res_header, int* res_header_len, char** res_body, int* res_body_len)
{
    uint8_t state = _state_get((uint8_t*)req_body, req_body_len);
    enum hap_pairing_method method = _method_get((uint8_t*)req_body, req_body_len);

    printf("[PAIRINGS] STATE:%d METHOD:%d\n", state, method);

    if (method == HAP_PAIRING_METHOD_REMOVE) {
        _remove((uint8_t*)req_body, req_body_len, (uint8_t**)res_body, res_body_len);
        *res_header = malloc(strlen(header_fmt) + 16);
        sprintf(*res_header, header_fmt, *res_body_len);
        *res_header_len = strlen(*res_header);
    }

    return 0;
}

void pairings_do_free(char* res_header, char*res_body)
{
    if (res_header)
        free(res_header);

    if (res_body)
        free(res_body);
}
