#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>


#include "nvs.h"
#include "hap.h"
#include "tlv.h"
#include "srp.h"
#include "hkdf.h"
#include "chacha20_poly1305.h"
#include "ed25519.h"
#include "pairing.h"

#define DEBUG


struct ltpk {
    uint8_t private[ED25519_KEY_LENGTH];
    uint8_t public[ED25519_KEY_LENGTH];
};

struct pair_desc {
    char* accessory_id;

    uint8_t* srp_session_key;
    struct ltpk acc_ltpk;
    struct pair_db_ops db_ops;
};
static struct pair_desc _pair_desc;

static const char* header = 
    "HTTP/1.1 200 OK\r\n"
    "Content-type: application/pairing+tlv8\r\n"
    "Connection: keep-alive\r\n"
    "Transfer-Encoding: chunked\r\n"
    "\r\n";
static void _array_print(char* a, int len)
{
    for (int i=0; i<len; i++) {
        if (i != 0 && (i % 0x10) == 0) {
            printf("\n");
        }
        printf("%02X ", a[i]);
    }
    printf("\n");
}

static void _accessory_ltpk_init(struct ltpk* ltpk)
{
    int signature_public_len = nvs_get("SIGN_PUBLIC", ltpk->public, ED25519_KEY_LENGTH);
    int signature_private_len = nvs_get("SIGN_PRIVATE", ltpk->private, ED25519_KEY_LENGTH);

    if (signature_public_len == 0 || signature_private_len == 0) {
        ed25519_key_generate(ltpk->public, ltpk->private);
        nvs_set("SIGN_PUBLIC", ltpk->private, ED25519_KEY_LENGTH);
        nvs_set("SIGN_PRIVATE", ltpk->private, ED25519_KEY_LENGTH);
    }
}

uint8_t* _concat3(uint8_t* m1, int m1_len, uint8_t* m2, int m2_len, uint8_t* m3, int m3_len, int* concateated_len)
{
    *concateated_len = m1_len + m2_len + m3_len;
    uint8_t* concatenated = malloc(*concateated_len);
    if (concatenated == NULL) {
        printf("malloc failed\n");
        *concateated_len = 0;
        return NULL;
    }

    memcpy(concatenated, m1, m1_len);
    memcpy(concatenated + m1_len, m2, m2_len);
    memcpy(concatenated + m1_len + m2_len, m3, m3_len);

    return concatenated;
}

void _concat_free(uint8_t* concatenated)
{
    if (concatenated)
        free(concatenated);
}

static int _pairing_setup_m6(char* req_body, int req_body_length, 
        char** res_header, char** res_body, int* body_len)
{
    uint8_t* srp_key = srp_session_key();
    uint8_t subtlv_key[HKDF_KEY_LEN] = {0,};

    hkdf_key_get(HKDF_KEY_TYPE_PAIR_SETUP_ENCRYPT, srp_key, SRP_SESSION_KEY_LENGTH, 
            subtlv_key);

    struct tlv* encrypted_tlv = tlv_decode((uint8_t*)req_body, req_body_length,
            HAP_TLV_TYPE_ENCRYPTED_DATA);
    if (encrypted_tlv == NULL) {
        printf("tlv_devoce HAP_TLV_TYPE_ENCRYPTED_DATA failed\n");
        return 500;
    }

    uint8_t sub_tlv[180] = {0,};
    chacha20_poly1305_decrypt(subtlv_key, (uint8_t*)&encrypted_tlv->value, encrypted_tlv->length, sub_tlv);
    tlv_decoded_item_free(encrypted_tlv);
    //sub tlv decode end


    struct tlv* ios_device_pairing_id = tlv_decode(sub_tlv, strlen((char*)sub_tlv), HAP_TLV_TYPE_IDENTIFIER);
    struct tlv* ios_device_ltpk = tlv_decode(sub_tlv, strlen((char*)sub_tlv), HAP_TLV_TYPE_PUBLICKEY);
    struct tlv* ios_device_signature = tlv_decode(sub_tlv, strlen((char*)sub_tlv), HAP_TLV_TYPE_SIGNATURE);

    uint8_t ios_devicex[HKDF_KEY_LEN] = {0,};
    hkdf_key_get(HKDF_KEY_TYPE_PAIR_SETUP_CONTROLLER, srp_key, SRP_SESSION_KEY_LENGTH, 
            ios_devicex);

    //TODO pairing id, ltpk save
    int ios_device_info_len = 0;
    uint8_t* ios_device_info = _concat3(ios_devicex, sizeof(ios_devicex), 
            ios_device_pairing_id->value, ios_device_pairing_id->length, 
            ios_device_ltpk->value, ios_device_ltpk->length,
            &ios_device_info_len);

    int verified = ed25519_verify((uint8_t*)&ios_device_ltpk->value, ios_device_ltpk->length,
            (uint8_t*)&ios_device_signature->value, ios_device_signature->length,
            ios_device_info, ios_device_info_len);
    printf("verified : %d\n", verified);
    free(ios_device_info);
    tlv_decoded_item_free(ios_device_pairing_id);
    tlv_decoded_item_free(ios_device_ltpk);
    tlv_decoded_item_free(ios_device_signature);
    //signature verification end

    uint8_t accessoryx[HKDF_KEY_LEN] = {0,};
    hkdf_key_get(HKDF_KEY_TYPE_PAIR_SETUP_ACCESSORY, srp_key, SRP_SESSION_KEY_LENGTH, 
            accessoryx);

    int accessory_device_info_len = 0;
    uint8_t* accessory_device_info = _concat3(accessoryx, sizeof(accessoryx), 
            (uint8_t*)_pair_desc.accessory_id, strlen(_pair_desc.accessory_id), 
            _pair_desc.acc_ltpk.public, ED25519_KEY_LENGTH, &accessory_device_info_len);

    int acc_signature_length = 128;
    uint8_t acc_signature[128] = {0,};
    ed25519_sign(_pair_desc.acc_ltpk.public, _pair_desc.acc_ltpk.private, accessory_device_info, accessory_device_info_len,
            acc_signature, &acc_signature_length);

    free(accessory_device_info);

    int sub_tlv_length = tlv_encode_length(strlen(_pair_desc.accessory_id));
    sub_tlv_length += tlv_encode_length(ED25519_KEY_LENGTH);
    sub_tlv_length += tlv_encode_length(acc_signature_length);
    uint8_t* sub_tlv_response = malloc(sub_tlv_length);
    uint8_t* sub_tlv_write_ptr = sub_tlv_response;
    //TODO ERROR CHECK

    sub_tlv_write_ptr += tlv_encode(HAP_TLV_TYPE_IDENTIFIER, strlen(_pair_desc.accessory_id), (uint8_t*)_pair_desc.accessory_id, sub_tlv_write_ptr);
    sub_tlv_write_ptr += tlv_encode(HAP_TLV_TYPE_PUBLICKEY, ED25519_KEY_LENGTH, _pair_desc.acc_ltpk.public, sub_tlv_write_ptr);
    sub_tlv_write_ptr += tlv_encode(HAP_TLV_TYPE_SIGNATURE, acc_signature_length, acc_signature, sub_tlv_write_ptr);


    //TODO FIXME
    uint8_t* encrypted_sub_tlv = malloc(sub_tlv_length + 16);
    chacha20_poly1305_encrypt(accessoryx, sub_tlv, sub_tlv_length, encrypted_sub_tlv, encrypted_sub_tlv + sub_tlv_length);





#if 0
    //make last tlv 

    //send
#endif
    return 0;
}

static int _pairing_setup_m4(char* req_body, int req_body_length, 
        char** res_header, char** res_body, int* body_len)
{
    int error = 0;
    struct tlv* A = tlv_decode((uint8_t*)req_body, req_body_length, 
            HAP_TLV_TYPE_PUBLICKEY);
    srp_A_set((uint8_t*)&A->value);
    tlv_decoded_item_free(A);

    struct tlv* proof = tlv_decode((uint8_t*)req_body, req_body_length, 
            HAP_TLV_TYPE_PROOF);
    bool authenticated = srp_verify((uint8_t*)&proof->value);
    tlv_decoded_item_free(proof);

    if (authenticated == false) {
        printf("AUTH FAILED\n");
        return 500;
    }

    uint8_t* accessory_proof = srp_response();
    if (accessory_proof == NULL) {
        printf("ACC PROOF NULL\n");
        return 500;
    }

    int res_body_length = 30;

    uint8_t state[] = {0x04};
    res_body_length += tlv_encode_length(sizeof(state));
    res_body_length += tlv_encode_length(SRP_PROOF_LENGTH);

    (*res_body) = malloc(res_body_length);
    if (*res_body == NULL) {
        printf("malloc failed. size:%d\n", res_body_length);
        return 500;
    }
    memset(*res_body, 0, res_body_length);

    uint8_t* tlv_encode_ptr = (uint8_t*)(*res_body);

    tlv_encode_ptr += sprintf((char*)tlv_encode_ptr, "%lX\r\n", (unsigned long)tlv_encode_length(sizeof(state)));
    tlv_encode_ptr += tlv_encode(HAP_TLV_TYPE_STATE, sizeof(state), state, tlv_encode_ptr);
    tlv_encode_ptr += sprintf((char*)tlv_encode_ptr, "\r\n");

    if (error) {
        uint8_t error[] = {0x2};

        tlv_encode_ptr += sprintf((char*)tlv_encode_ptr, "%lX\r\n", (unsigned long)tlv_encode_length(sizeof(error)));
        tlv_encode_ptr += tlv_encode(HAP_TLV_TYPE_ERROR, sizeof(error), error, tlv_encode_ptr);
        tlv_encode_ptr += sprintf((char*)tlv_encode_ptr, "\r\n");
    }
    else {
        tlv_encode_ptr += sprintf((char*)tlv_encode_ptr, "%lX\r\n", (unsigned long)tlv_encode_length(SRP_PROOF_LENGTH));
        tlv_encode_ptr += tlv_encode(HAP_TLV_TYPE_PROOF, SRP_PROOF_LENGTH, accessory_proof, tlv_encode_ptr);
        tlv_encode_ptr += sprintf((char*)tlv_encode_ptr, "\r\n");
    }

    tlv_encode_ptr += sprintf((char*)tlv_encode_ptr, "0\r\n\r\n");

    *body_len = (int)((char*)tlv_encode_ptr - *res_body);

#if 1
    printf("[PAIRING] m4 res start\n");
    for (int i=0; i<*body_len; i++) {
        if (i != 0 && (i % 0x10) == 0)
            printf("\n");
        printf("0x%02X ", (*res_body)[i]);
    }
    printf("\n[PAIRING res end(%d)\n", *body_len);
#endif

    *res_header = (char*)header;
    return 200;
}

static int _pairing_setup_m2(char* req_body, int req_body_length, 
        char** res_header, char** res_body, int* body_len)
{
    int res_body_length = 30;

    uint8_t state[] = {0x02};
    res_body_length += tlv_encode_length(sizeof(state));
    res_body_length += tlv_encode_length(SRP_PUBLIC_KEY_LENGTH);
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

    uint8_t* salt = srp_salt();
    uint8_t* B = srp_B();

    uint8_t* tlv_encode_ptr = (uint8_t*)(*res_body);

    tlv_encode_ptr += sprintf((char*)tlv_encode_ptr, "%lX\r\n", (unsigned long)tlv_encode_length(SRP_SALT_LENGTH));
    tlv_encode_ptr += tlv_encode(HAP_TLV_TYPE_SALT, SRP_SALT_LENGTH, salt, tlv_encode_ptr);
    tlv_encode_ptr += sprintf((char*)tlv_encode_ptr, "\r\n");

    tlv_encode_ptr += sprintf((char*)tlv_encode_ptr, "%lX\r\n", (unsigned long)tlv_encode_length(SRP_PUBLIC_KEY_LENGTH));
    tlv_encode_ptr += tlv_encode(HAP_TLV_TYPE_PUBLICKEY, SRP_PUBLIC_KEY_LENGTH, B, tlv_encode_ptr);
    tlv_encode_ptr += sprintf((char*)tlv_encode_ptr, "\r\n");


    tlv_encode_ptr += sprintf((char*)tlv_encode_ptr, "%lX\r\n", (unsigned long)tlv_encode_length(sizeof(state)));
    tlv_encode_ptr += tlv_encode(HAP_TLV_TYPE_STATE, sizeof(state), state, tlv_encode_ptr);
    tlv_encode_ptr += sprintf((char*)tlv_encode_ptr, "\r\n");

    tlv_encode_ptr += sprintf((char*)tlv_encode_ptr, "0\r\n\r\n");

    *body_len = (int)((char*)tlv_encode_ptr - *res_body);

#ifdef DEBUG
    printf("[PAIRING] res start\n");
    for (int i=0; i<*body_len; i++) {
        if (i != 0 && (i % 0x10) == 0)
            printf("\n");
        printf("0x%02X ", (*res_body)[i]);
    }
    printf("res end\n");
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

    printf("[PAIRING]body len:%d\n", req_body_length);
#ifdef DEBUG
    printf("[PAIRING]body start\n");
    for (int i=0; i<req_body_length; i++) {
        if (i != 0 && (i % 0x10) == 0)
            printf("\n");
        printf("0x%02X ", req_body[i]);
    }
    printf("\n[PAIRING]body end\n");
#endif

    uint8_t state = _state_get(req_body, req_body_length);
//#ifdef DEBUG
    printf("[PAIRING] state:%d\n", state);
//#endif

    switch (state) {
    case 0x01:
        return _pairing_setup_m2(req_body, req_body_length,
                res_header, res_body, body_len);
    case 0x03:
        return _pairing_setup_m4(req_body, req_body_length,
                res_header, res_body, body_len);
    case 0x05:
        return _pairing_setup_m6(req_body, req_body_length,
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

void pairing_init(char* accessory_id, char* setup_code)
{
    _pair_desc.accessory_id = strdup(accessory_id);

    srp_init(setup_code);
    _pair_desc.srp_session_key = srp_session_key();

    _accessory_ltpk_init(&_pair_desc.acc_ltpk);
}
