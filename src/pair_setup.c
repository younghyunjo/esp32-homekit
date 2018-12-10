#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "chacha20_poly1305.h"
#include "concat.h"
#include "curve25519.h"
#include "ed25519.h"
#include "hap_internal.h"
#include "hkdf.h"
#include "iosdevice.h"
#include "pair_error.h"
#include "srp.h"
#include "tlv.h"

//#define DEBUG

struct pair_setup {
    char* acc_id;
    char* setup_code;
    void* iosdevices;
    void* srp;

    struct {
        uint8_t* public;
        uint8_t* private;
    } keys;
};

static const char* header_fmt = 
    "HTTP/1.1 200 OK\r\n"
    "Content-Length: %d\r\n"
    "Content-Type: application/pairing+tlv8\r\n"
    "\r\n";

static void _dump_hex(uint8_t* data, int len)
{
#ifdef DEBUG
    for (int i=0; i<len; i++) {
        if (i != 0 && i & 8 == 0)
            printf("\n");
        printf("0x%02X ", data[i]);
    }
#endif
}

static int _subtlv_decrypt(enum hkdf_key_type htype,
        enum chacha20_poly1305_type cptype,
        uint8_t* srp_key, uint8_t* device_msg, int device_msg_length, uint8_t** subtlv, int* subtlv_length)
{
    struct tlv* encrypted_tlv = tlv_decode((uint8_t*)device_msg, device_msg_length,
            HAP_TLV_TYPE_ENCRYPTED_DATA);
    if (encrypted_tlv == NULL) {
        printf("tlv_devoce HAP_TLV_TYPE_ENCRYPTED_DATA failed\n");
        return -1;
    }

    uint8_t subtlv_key[HKDF_KEY_LEN] = {0,};
    hkdf_key_get(htype, srp_key, SRP_SESSION_KEY_LENGTH, subtlv_key);

    *subtlv = malloc(encrypted_tlv->length);
    int err = chacha20_poly1305_decrypt(cptype, subtlv_key, NULL, 0,
            (uint8_t*)&encrypted_tlv->value, encrypted_tlv->length, *subtlv);
    tlv_decoded_item_free(encrypted_tlv);
    if (err < 0) {
        printf("chacha20_poly1305_decrypt failed\n");
        free(*subtlv);
        return -1;
    }
    *subtlv_length = encrypted_tlv->length;

    return 0;
}

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

static int _ios_device_signature_verify(void* iosdevices, uint8_t* srp_key, uint8_t* subtlv, int subtlv_length)
{
    uint8_t ios_devicex[HKDF_KEY_LEN] = {0,};
    hkdf_key_get(HKDF_KEY_TYPE_PAIR_SETUP_CONTROLLER, srp_key, SRP_SESSION_KEY_LENGTH, 
            ios_devicex);

    struct tlv* ios_device_pairing_id = tlv_decode(subtlv, subtlv_length, HAP_TLV_TYPE_IDENTIFIER);
    if (!ios_device_pairing_id) { 
        printf("tlv_decode failed. type:%d\n", HAP_TLV_TYPE_IDENTIFIER);
        printf("tlv length:%d 0x%02X", subtlv_length, subtlv_length);
        _dump_hex(subtlv, subtlv_length);
        return -1;
    }
    struct tlv* ios_device_ltpk = tlv_decode(subtlv, subtlv_length, HAP_TLV_TYPE_PUBLICKEY);
    if (!ios_device_ltpk) { 
        printf("tlv_decode failed. type:%d\n", HAP_TLV_TYPE_PUBLICKEY);
        printf("tlv length:%d 0x%02X", subtlv_length, subtlv_length);
        _dump_hex(subtlv, subtlv_length);
        return -1;
    }
    struct tlv* ios_device_signature = tlv_decode(subtlv, subtlv_length, HAP_TLV_TYPE_SIGNATURE);
    if (!ios_device_signature) { 
        printf("tlv_decode failed. type:%d\n", HAP_TLV_TYPE_SIGNATURE);
        printf("tlv length:%d 0x%02X", subtlv_length, subtlv_length);
        _dump_hex(subtlv, subtlv_length);
        return -1;
    }

    int ios_device_info_len = 0;
    uint8_t* ios_device_info = concat3(ios_devicex, sizeof(ios_devicex), 
            (uint8_t*)&ios_device_pairing_id->value, ios_device_pairing_id->length, 
            (uint8_t*)&ios_device_ltpk->value, ios_device_ltpk->length,
            &ios_device_info_len);

    int verified = ed25519_verify((uint8_t*)&ios_device_ltpk->value, ios_device_ltpk->length,
            (uint8_t*)&ios_device_signature->value, ios_device_signature->length,
            ios_device_info, ios_device_info_len);

    concat_free(ios_device_info);

    iosdevice_pairings_add(iosdevices, (char*)&ios_device_pairing_id->value, 
            (char*)&ios_device_ltpk->value);

    tlv_decoded_item_free(ios_device_pairing_id);
    tlv_decoded_item_free(ios_device_ltpk);
    tlv_decoded_item_free(ios_device_signature);

    return verified;
}

static int _acc_m6_subtlv(uint8_t* srp_key, char* acc_id, uint8_t* acc_ltk_public, uint8_t* acc_ltk_private,  uint8_t** acc_subtlv, int* acc_subtlv_length)
{
    uint8_t accessoryx[HKDF_KEY_LEN] = {0,};
    hkdf_key_get(HKDF_KEY_TYPE_PAIR_SETUP_ACCESSORY, srp_key, SRP_SESSION_KEY_LENGTH, 
            accessoryx);

    int acc_info_len = 0;
    uint8_t* acc_info = concat3(accessoryx, sizeof(accessoryx), 
            (uint8_t*)acc_id, 17, 
            acc_ltk_public, ED25519_PUBLIC_KEY_LENGTH, &acc_info_len);

    int acc_signature_length = ED25519_SIGN_LENGTH;
    uint8_t acc_signature[ED25519_SIGN_LENGTH] = {0,};
    ed25519_sign(acc_ltk_public, acc_ltk_private, acc_info, acc_info_len,
            acc_signature, &acc_signature_length);

    concat_free(acc_info);

    int acc_plain_subtlv_length = tlv_encode_length(strlen(acc_id));
    acc_plain_subtlv_length += tlv_encode_length(ED25519_PUBLIC_KEY_LENGTH);
    acc_plain_subtlv_length += tlv_encode_length(acc_signature_length);

    uint8_t* acc_plain_subtlv = malloc(acc_plain_subtlv_length);
    uint8_t* sub_tlv_write_ptr = acc_plain_subtlv;

    sub_tlv_write_ptr += tlv_encode(HAP_TLV_TYPE_IDENTIFIER, strlen(acc_id), (uint8_t*)acc_id, sub_tlv_write_ptr);
    sub_tlv_write_ptr += tlv_encode(HAP_TLV_TYPE_PUBLICKEY, ED25519_PUBLIC_KEY_LENGTH, acc_ltk_public, sub_tlv_write_ptr);
    sub_tlv_write_ptr += tlv_encode(HAP_TLV_TYPE_SIGNATURE, ED25519_SIGN_LENGTH, acc_signature, sub_tlv_write_ptr);

#if 0
    printf("ACC PLAIN SUBTLV LEN:%d\n", acc_plain_subtlv_length);
    _array_print((char*)acc_plain_subtlv, acc_plain_subtlv_length);
#endif

    *acc_subtlv_length = acc_plain_subtlv_length + CHACHA20_POLY1305_AUTH_TAG_LENGTH;
    *acc_subtlv = (uint8_t*)calloc(1, *acc_subtlv_length);

    uint8_t subtlv_key[HKDF_KEY_LEN] = {0,};
    hkdf_key_get(HKDF_KEY_TYPE_PAIR_SETUP_ENCRYPT, srp_key, SRP_SESSION_KEY_LENGTH, subtlv_key);
    chacha20_poly1305_encrypt(CHACHA20_POLY1305_TYPE_PS06, subtlv_key, NULL, 0, acc_plain_subtlv, acc_plain_subtlv_length, *acc_subtlv);
    
#if 0
    printf("ACC SUBTLV LEN:%d\n", *acc_subtlv_length);
    _array_print((char*)*acc_subtlv, *acc_subtlv_length);
#endif

    free(acc_plain_subtlv);

    return 0;
}

static int _setup_m6(struct pair_setup* ps,
        uint8_t* device_msg, int device_msg_length, 
        uint8_t** acc_msg, int* acc_msg_length)
{
    uint8_t srp_key[SRP_SESSION_KEY_LENGTH] = {0,};
    srp_host_session_key(ps->srp, srp_key);

    int device_subtlv_length = 0;;
    uint8_t* device_subtlv;
    int err = _subtlv_decrypt(HKDF_KEY_TYPE_PAIR_SETUP_ENCRYPT, 
            CHACHA20_POLY1305_TYPE_PS05,
            srp_key, device_msg, device_msg_length, &device_subtlv, &device_subtlv_length);
    if (err < 0) {
        printf("_subtlv_decrypt failed\n");
        return pair_error(HAP_TLV_ERROR_AUTHENTICATION, acc_msg, acc_msg_length);
    }

    if (_ios_device_signature_verify(ps->iosdevices, srp_key, device_subtlv, device_subtlv_length) < 0) {
        printf("_ios_device_signature_verify failed\n");
        return pair_error(HAP_TLV_ERROR_AUTHENTICATION, acc_msg, acc_msg_length);
    }
    _subtlv_free(device_subtlv);

    uint8_t* acc_subtlv;
    int acc_subtlv_length = 0;
    _acc_m6_subtlv(srp_key, ps->acc_id, ps->keys.public, ps->keys.private, &acc_subtlv, &acc_subtlv_length);

    uint8_t state[] = {0x06};
    *acc_msg_length = tlv_encode_length(sizeof(state));
    *acc_msg_length += tlv_encode_length(acc_subtlv_length);

    (*acc_msg) = malloc(*acc_msg_length);
    if (*acc_msg == NULL) {
        printf("malloc failed. size:%d\n", *acc_msg_length);
        return pair_error(HAP_TLV_ERROR_UNKNOWN, acc_msg, acc_msg_length);
    }

    uint8_t* tlv_encode_ptr = *acc_msg;
    tlv_encode_ptr += tlv_encode(HAP_TLV_TYPE_STATE, sizeof(state), state, tlv_encode_ptr);
    tlv_encode_ptr += tlv_encode(HAP_TLV_TYPE_ENCRYPTED_DATA, acc_subtlv_length, acc_subtlv, tlv_encode_ptr);

    _subtlv_free(acc_subtlv);
    return 0;
}

static int _setup_m4(struct pair_setup* ps, 
        uint8_t* device_msg, int device_msg_length, 
        uint8_t** acc_msg, int* acc_msg_length)
{
    struct tlv* ios_srp_public_key = tlv_decode(device_msg, device_msg_length, 
            HAP_TLV_TYPE_PUBLICKEY);
    if (!ios_srp_public_key) {
        printf("tlv_decode failed. type:%d\n", HAP_TLV_TYPE_PUBLICKEY);
        return -1;
    }
#if 0
    ESP_LOGI(TAG, "A");
    _array_print((char*)&ios_srp_public_key->value, ios_srp_public_key->length);
#endif

    int err = srp_client_key_set(ps->srp, (uint8_t*)&ios_srp_public_key->value);
    tlv_decoded_item_free(ios_srp_public_key);
    if (err < 0) {
        printf("srp_client_key_set failed");
        return pair_error(HAP_TLV_ERROR_AUTHENTICATION, acc_msg, acc_msg_length);
    }

    struct tlv* ios_srp_proof = tlv_decode((uint8_t*)device_msg, device_msg_length, 
            HAP_TLV_TYPE_PROOF);
    if (!ios_srp_proof) {
        printf("tlv_decode failed. type:%d\n", HAP_TLV_TYPE_PROOF);
        return -1;
    }
#if 0
    ESP_LOGI(TAG, "IOS PROOF");
    _array_print((char*)&ios_srp_proof->value, ios_srp_proof->length);
#endif
    err = srp_client_proof_verify(ps->srp, (uint8_t*)&ios_srp_proof->value);
    tlv_decoded_item_free(ios_srp_proof);
    if (err < 0) {
        printf("srp_client_proof_verify failed\n");
        return pair_error(HAP_TLV_ERROR_AUTHENTICATION, acc_msg, acc_msg_length);
    }

    uint8_t acc_srp_proof[SRP_PROOF_LENGTH] = {0,};
    err = srp_host_proof_get(ps->srp, acc_srp_proof);
    if (err < 0) {
        printf("srp_host_proof_get failed\n");
        return pair_error(HAP_TLV_ERROR_UNKNOWN, acc_msg, acc_msg_length);
    }
    *acc_msg_length = tlv_encode_length(SRP_PROOF_LENGTH);

    uint8_t state[] = {0x04};
    *acc_msg_length += tlv_encode_length(sizeof(state));

    (*acc_msg) = malloc(*acc_msg_length);
    if (*acc_msg == NULL) {
        printf("malloc failed. size:%d\n", *acc_msg_length);
        return pair_error(HAP_TLV_ERROR_UNKNOWN, acc_msg, acc_msg_length);
    }

    uint8_t* tlv_encode_ptr = *acc_msg;
    tlv_encode_ptr += tlv_encode(HAP_TLV_TYPE_PROOF, SRP_PROOF_LENGTH, acc_srp_proof, tlv_encode_ptr);
    tlv_encode_ptr += tlv_encode(HAP_TLV_TYPE_STATE, sizeof(state), state, tlv_encode_ptr);
    
    return 0;
}

static int _setup_m2(struct pair_setup* ps, 
        uint8_t* device_msg, int device_msg_length, 
        uint8_t** acc_msg, int* acc_msg_length)
{
    if (ps->srp) {
        srp_cleanup(ps->srp);
    }

    ps->srp = srp_init(ps->setup_code);
    uint8_t host_public_key[SRP_PUBLIC_KEY_LENGTH] = {0,};
    if (srp_host_key_get(ps->srp, host_public_key) < 0) {
        printf("srp_host_key_get failed\n");
        return pair_error(HAP_TLV_ERROR_UNKNOWN, acc_msg, acc_msg_length);
    }
    *acc_msg_length = tlv_encode_length(SRP_PUBLIC_KEY_LENGTH);

#if 0
    ESP_LOGI(TAG, "SRP_PUBLIC_KEY_LENGTH");
    _array_print((char*)host_public_key, SRP_PUBLIC_KEY_LENGTH);
#endif

    uint8_t salt[SRP_SALT_LENGTH] = {0,};
    if (srp_salt(ps->srp, salt) < 0) {
        printf("srp_salt failed\n");
        return pair_error(HAP_TLV_ERROR_UNKNOWN, acc_msg, acc_msg_length);
    }
    *acc_msg_length += tlv_encode_length(SRP_SALT_LENGTH);

#if 0
    ESP_LOGI(TAG, "SALT");
    _array_print((char*)salt, SRP_SALT_LENGTH);
#endif

    uint8_t state[] = {0x02};
    *acc_msg_length += tlv_encode_length(sizeof(state));

    (*acc_msg) = malloc(*acc_msg_length);
    if (*acc_msg == NULL) {
        printf("malloc failed\n");
        return pair_error(HAP_TLV_ERROR_UNKNOWN, acc_msg, acc_msg_length);
    }

    uint8_t* tlv_encode_ptr = *acc_msg;
    tlv_encode_ptr += tlv_encode(HAP_TLV_TYPE_SALT, SRP_SALT_LENGTH, salt, tlv_encode_ptr);
    tlv_encode_ptr += tlv_encode(HAP_TLV_TYPE_PUBLICKEY, SRP_PUBLIC_KEY_LENGTH, host_public_key, tlv_encode_ptr);
    tlv_encode_ptr += tlv_encode(HAP_TLV_TYPE_STATE, sizeof(state), state, tlv_encode_ptr);

    return 0;
}

int pair_setup_do(void* _ps, char* req_body, int req_body_len, 
        char** res_header, int* res_header_len, char** res_body, int* res_body_len)
{
    struct pair_setup* ps = _ps;

    uint8_t state = _state_get((uint8_t*)req_body, req_body_len);
    printf("[PAIR-SETUP] STATE:%d", state);

    int error = 0;
    switch (state) {
    case 0x01:
        error = _setup_m2(ps, (uint8_t*)req_body, req_body_len, (uint8_t**)res_body, res_body_len);
        break;
    case 0x03:
        error = _setup_m4(ps, (uint8_t*)req_body, req_body_len, (uint8_t**)res_body, res_body_len);
        break;
    case 0x05:
        error = _setup_m6(ps, (uint8_t*)req_body, req_body_len, (uint8_t**)res_body, res_body_len);
        break;
    default:
        printf("[PAIR-SETUP][ERR] Invalid state number. %d\n", state);
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

void pair_setup_do_free(char* res_header, char*res_body)
{
    if (res_header)
        free(res_header);

    if (res_body)
        free(res_body);
}

void* pair_setup_init(char* acc_id, char* setup_code, void* iosdevices, uint8_t* public_key, uint8_t* private_key)
{
    struct pair_setup* ps = calloc(1, sizeof(struct pair_setup));
    if (ps == NULL) {
        return NULL;
    }

    ps->keys.public = public_key;
    ps->keys.private = private_key;
    ps->acc_id = acc_id;
    ps->setup_code = setup_code;
    ps->iosdevices = iosdevices;
    ps->srp = srp_init(setup_code);


    printf("[INFO][PAIR-SETUP] init\n");

    return ps;
}

void pair_setup_cleanup(void* _ps)
{
    struct pair_setup* ps = _ps;
    if (ps->srp)
        srp_cleanup(ps->srp);

    free(ps);
}
