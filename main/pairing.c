#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <freertos/FreeRTOS.h>

#include "hap.h"
#include "tlv.h"
#include "srp.h"

//#define DEBUG

static const char* header = 
    "HTTP/1.1 200 OK\r\n"
    "Content-type: application/pairing+tlv8\r\n"
    "Connection: keep-alive\r\n"
    "Transfer-Encoding: chunked\r\n"
    "\r\n";

static int _pairing_setup_m4(char* req_body, int req_body_length, 
        char** res_header, char** res_body, int* body_len)
{
    struct tlv* proof = tlv_decode((uint8_t*)req_body, req_body_length, 
            HAP_TLV_TYPE_PROOF);

    struct tlv* public_key = tlv_decode((uint8_t*)req_body, req_body_length, 
            HAP_TLV_TYPE_PUBLICKEY);

    printf("pubkey len:%d proof len:%d\n", public_key->length, proof->length);

    if (public_key)
        tlv_decoded_item_free(public_key);

    if (proof)
        tlv_decoded_item_free(proof);

    return 200;
}

static int _pairing_setup_m2(char* req_body, int req_body_length, 
        char** res_header, char** res_body, int* body_len)
{
    int res_body_length = 30;

    uint8_t state[] = {0x02};
    res_body_length += tlv_encode_length(sizeof(state));
    res_body_length += tlv_encode_length(SRP_PUBLICH_KEY_LENGTH);
    res_body_length += tlv_encode_length(SRP_SALT_LENGTH);

#ifdef DEBUG
    printf("[PAIRING]m2 response body length:%d\n", res_body_length);
#endif

    (*res_body) = malloc(res_body_length);
    if (*res_body == NULL) {
        printf("malloc failed. size:%d\n", res_body_length);
        return 500;
    }
    memset(*res_body, 0, res_body_length);

    static uint8_t publick_key[SRP_PUBLICH_KEY_LENGTH] = {0,};
    srp_publich_key_get(publick_key);

    uint8_t salt[SRP_SALT_LENGTH] = {0,};
    srp_salt_get(salt);

    uint8_t* tlv_encode_ptr = (uint8_t*)(*res_body);

    tlv_encode_ptr += sprintf((char*)tlv_encode_ptr, "%lX\r\n", (unsigned long)tlv_encode_length(SRP_SALT_LENGTH));
    tlv_encode_ptr += tlv_encode(HAP_TLV_TYPE_SALT, SRP_SALT_LENGTH, salt, tlv_encode_ptr);
    tlv_encode_ptr += sprintf((char*)tlv_encode_ptr, "\r\n");

    tlv_encode_ptr += sprintf((char*)tlv_encode_ptr, "%lX\r\n", (unsigned long)tlv_encode_length(SRP_PUBLICH_KEY_LENGTH));
    tlv_encode_ptr += tlv_encode(HAP_TLV_TYPE_PUBLICKEY, SRP_PUBLICH_KEY_LENGTH, publick_key, tlv_encode_ptr);
    tlv_encode_ptr += sprintf((char*)tlv_encode_ptr, "\r\n");


    tlv_encode_ptr += sprintf((char*)tlv_encode_ptr, "%lX\r\n", (unsigned long)tlv_encode_length(sizeof(state)));
    tlv_encode_ptr += tlv_encode(HAP_TLV_TYPE_STATE, sizeof(state), state, tlv_encode_ptr);
    tlv_encode_ptr += sprintf((char*)tlv_encode_ptr, "\r\n");

    tlv_encode_ptr += sprintf((char*)tlv_encode_ptr, "0\r\n\r\n");

    *body_len = (int)((char*)tlv_encode_ptr - *res_body);

#ifdef DEBUG
    for (int i=0; i<*body_len; i++) {
        if (i != 0 && (i % 0x16) == 0)
            printf("\n");
        printf("0x%02X ", (*res_body)[i]);
    }
    printf("\n");
#endif

    *res_header = (char*)header;
    return 200;
}

static uint8_t _state_get(char* req_body, int req_body_length)
{
    struct tlv* state_tlv = tlv_decode((uint8_t*)req_body, req_body_length, 
            HAP_TLV_TYPE_STATE);
    if (state_tlv == NULL)
        return 0;

    uint8_t state = ((uint8_t*)&state_tlv->value)[0];

    tlv_decoded_item_free(state_tlv);
    return state;
}

int pairing_setup(char* req_body, int req_body_length, 
        char** res_header, char** res_body, int* body_len)
{
    *res_header = NULL;
    *res_body = NULL;
    *body_len = 0;

#ifdef DEBUG
    printf("[PAIRING]body len:%d\n", req_body_length);
    printf("[PAIRING]body start\n");
    for (int i=0; i<req_body_length; i++) {
        if (i != 0 && (i % 0x16) == 0)
            printf("\n");
        printf("0x%02X ", req_body[i]);
    }
    printf("\n[PAIRING]body end\n");
#endif

    uint8_t state = _state_get(req_body, req_body_length);
#ifdef DEBUG
    printf("[PAIRING] state:%d\n", state);
#endif

    switch (state) {
    case 0x01:
        return _pairing_setup_m2(req_body, req_body_length,
                res_header, res_body, body_len);
    case 0x03:
        return _pairing_setup_m4(req_body, req_body_length,
                res_header, res_body, body_len);
    default:
        return 500;
    }
}

void pairing_setup_free(char* res_header, char* res_body)
{
    if (res_body)
        free(res_body);
}

