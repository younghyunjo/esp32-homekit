#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "chacha20_poly1305.h"
#include "concat.h"
#include "curve25519.h"
#include "ed25519.h"
#include "hap_internal.h"
#include "hkdf.h"
#include "iosdevice.h"
#include "pair_error.h"
#include "tlv.h"

struct pair_verify {
    char* acc_id;
    void* iosdevices;
    
    struct {
        uint8_t* public;
        uint8_t* private;
    } keys;
    uint8_t session_key[CURVE25519_SECRET_LENGTH];
};

static const char* header_fmt = 
    "HTTP/1.1 200 OK\r\n"
    "Content-Length: %d\r\n"
    "Content-Type: application/pairing+tlv8\r\n"
    "\r\n";

static void _subtlv_free(uint8_t* subtlv)
{
    if (subtlv)
        free(subtlv);
}

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

static int _verify_m2(struct pair_verify* pv, 
        uint8_t* device_msg, int device_msg_length, 
        uint8_t** acc_msg, int* acc_msg_length)
{
    uint8_t acc_curve_public_key[CURVE25519_KEY_LENGTH] = {0,};
    uint8_t acc_curve_private_key[CURVE25519_KEY_LENGTH] = {0,};
    if (curve25519_key_generate(acc_curve_public_key, acc_curve_private_key) < 0) {
        printf("curve25519_key_generate failed\n");
        return -1;
    }

    struct tlv* ios_device_curve_key = tlv_decode((uint8_t*)device_msg, 
            device_msg_length, HAP_TLV_TYPE_PUBLICKEY);
    if (!ios_device_curve_key) {
        printf("tlv_decode failed. type:%d\n", HAP_TLV_TYPE_PUBLICKEY);
        return -1;
    }

    uint8_t session_key[CURVE25519_SECRET_LENGTH] = {0,};
    int session_key_length = CURVE25519_SECRET_LENGTH;
    if (curve25519_shared_secret((uint8_t*)&ios_device_curve_key->value,
            acc_curve_private_key, session_key, &session_key_length) < 0) {
        printf("curve25519_shared_secret failed\n");
        return -1;
    }

    int acc_info_len;
    uint8_t* acc_info = concat3(acc_curve_public_key, CURVE25519_KEY_LENGTH,
            (uint8_t*)pv->acc_id, strlen(pv->acc_id),
            (uint8_t*)&ios_device_curve_key->value, ios_device_curve_key->length,
            &acc_info_len);

    tlv_decoded_item_free(ios_device_curve_key);

    int acc_signature_length = ED25519_SIGN_LENGTH;
    uint8_t acc_signature[ED25519_SIGN_LENGTH] = {0,};
    ed25519_sign(pv->keys.public, pv->keys.private, 
            acc_info, acc_info_len,
            acc_signature, &acc_signature_length);

    concat_free(acc_info);

    int acc_plain_subtlv_length = tlv_encode_length(strlen(pv->acc_id));
    acc_plain_subtlv_length += tlv_encode_length(acc_signature_length);

    uint8_t* acc_plain_subtlv = malloc(acc_plain_subtlv_length);
    uint8_t* sub_tlv_write_ptr = acc_plain_subtlv;

    sub_tlv_write_ptr += tlv_encode(HAP_TLV_TYPE_IDENTIFIER, strlen(pv->acc_id), (uint8_t*)pv->acc_id, sub_tlv_write_ptr);
    sub_tlv_write_ptr += tlv_encode(HAP_TLV_TYPE_SIGNATURE, ED25519_SIGN_LENGTH, acc_signature, sub_tlv_write_ptr);

    int acc_subtlv_length = acc_plain_subtlv_length + CHACHA20_POLY1305_AUTH_TAG_LENGTH;
    uint8_t* acc_subtlv = (uint8_t*)calloc(1, acc_subtlv_length);

    uint8_t subtlv_key[HKDF_KEY_LEN] = {0,};
    hkdf_key_get(HKDF_KEY_TYPE_PAIR_VERIFY_ENCRYPT, session_key, CURVE25519_SECRET_LENGTH, subtlv_key);
    chacha20_poly1305_encrypt(CHACHA20_POLY1305_TYPE_PV02, subtlv_key, NULL, 0, acc_plain_subtlv, acc_plain_subtlv_length, acc_subtlv);

    free(acc_plain_subtlv);

    uint8_t state[] = {0x02};
    *acc_msg_length = tlv_encode_length(sizeof(state));
    *acc_msg_length += tlv_encode_length(acc_subtlv_length);
    *acc_msg_length += tlv_encode_length(CURVE25519_KEY_LENGTH);

    (*acc_msg) = malloc(*acc_msg_length);
    if (*acc_msg == NULL) {
        printf("malloc failed. size:%d\n", *acc_msg_length);
        return pair_error(HAP_TLV_ERROR_UNKNOWN, acc_msg, acc_msg_length);
    }

    uint8_t* tlv_encode_ptr = *acc_msg;
    tlv_encode_ptr += tlv_encode(HAP_TLV_TYPE_STATE, sizeof(state), state, tlv_encode_ptr);
    tlv_encode_ptr += tlv_encode(HAP_TLV_TYPE_PUBLICKEY, CURVE25519_KEY_LENGTH, acc_curve_public_key, tlv_encode_ptr);
    tlv_encode_ptr += tlv_encode(HAP_TLV_TYPE_ENCRYPTED_DATA, acc_subtlv_length, acc_subtlv, tlv_encode_ptr);

    _subtlv_free(acc_subtlv);

    memcpy(pv->session_key, session_key, CURVE25519_SECRET_LENGTH);
    
    return 0;
}

static int _verify_m4(struct pair_verify* pv, 
        uint8_t* device_msg, int device_msg_length, 
        uint8_t** acc_msg, int* acc_msg_length)
{
    struct tlv* encrypted_tlv = tlv_decode((uint8_t*)device_msg, device_msg_length,
            HAP_TLV_TYPE_ENCRYPTED_DATA);
    if (encrypted_tlv == NULL) {
        printf("tlv_devoce HAP_TLV_TYPE_ENCRYPTED_DATA failed\n");
        return pair_error(HAP_TLV_ERROR_UNKNOWN, acc_msg, acc_msg_length);
    }

    uint8_t subtlv_key[HKDF_KEY_LEN] = {0,};
    hkdf_key_get(HKDF_KEY_TYPE_PAIR_VERIFY_ENCRYPT, pv->session_key, CURVE25519_SECRET_LENGTH, subtlv_key);
    uint8_t* subtlv = malloc(encrypted_tlv->length);
    chacha20_poly1305_decrypt(CHACHA20_POLY1305_TYPE_PV03, subtlv_key, NULL, 0, (uint8_t*)&encrypted_tlv->value, encrypted_tlv->length, subtlv);

    tlv_decoded_item_free(encrypted_tlv);

    int subtlv_length = strlen((char*)subtlv);;
    struct tlv* ios_device_pairng_id = tlv_decode(subtlv, subtlv_length, 
            HAP_TLV_TYPE_IDENTIFIER);
    if (ios_device_pairng_id == NULL) {
        printf("tlv_devoce HAP_TLV_TYPE_IDENTIFIER failed\n");
        free(subtlv);
        return pair_error(HAP_TLV_ERROR_UNKNOWN, acc_msg, acc_msg_length);
    }

    struct tlv* ios_device_signature = tlv_decode(subtlv, subtlv_length, 
            HAP_TLV_TYPE_SIGNATURE);
    if (ios_device_signature == NULL) {
        printf("tlv_devoce HAP_TLV_TYPE_SIGNATURE failed\n");
        free(subtlv);
        return pair_error(HAP_TLV_ERROR_UNKNOWN, acc_msg, acc_msg_length);
    }

    free(subtlv);

    //TODO MATCH pairiing_id, signature

    tlv_decoded_item_free(ios_device_pairng_id);
    tlv_decoded_item_free(ios_device_signature);

    uint8_t state[] = {4};
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

int pair_verify_do(void* _pv, const char* req_body, int req_body_len, 
        char** res_header, int* res_header_len, char** res_body, int* res_body_len, 
        bool* verified, char* session_key)
{
    struct pair_verify* pv = _pv;
    uint8_t state = _state_get((uint8_t*)req_body, req_body_len);

    int error = 0;
    switch (state) {
    case 0x01:
        error = _verify_m2(pv, (uint8_t*)req_body, req_body_len, (uint8_t**)res_body, res_body_len); 
        break;
    case 0x03:
        error = _verify_m4(pv, (uint8_t*)req_body, req_body_len, (uint8_t**)res_body, res_body_len); 
        if (error == 0) {
            *verified = true;
            memcpy(session_key, pv->session_key, CURVE25519_SECRET_LENGTH);
        }
        break;
    default:
        printf("[PAIR-VERIFY][ERR] Invalid state number. %d\n", state);
        return -1;
    }

    if (error) {
        return -1;
    }

    *res_header = malloc(strlen(header_fmt) + 16);
    sprintf(*res_header, header_fmt, *res_body_len);
    *res_header_len = strlen(*res_header);

    return 0;
}

void pair_verify_do_free(char* res_header, char*res_body)
{
    if (res_header)
        free(res_header);

    if (res_body)
        free(res_body);
}

void* pair_verify_init(char* acc_id, void* iosdevices, uint8_t* public_key, uint8_t* private_key)
{
    struct pair_verify* pv = calloc(1, sizeof(struct pair_verify));
    if (pv == NULL) {
        return NULL;
    }

    pv->acc_id = acc_id;
    pv->iosdevices = iosdevices;
    pv->keys.public = public_key;
    pv->keys.private = private_key;

    return pv;
}

void pair_verify_cleanup(void* _pv)
{
    struct pair_verify* pv = _pv;

    free(pv);
}

