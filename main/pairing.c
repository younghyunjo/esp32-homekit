#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#include <os.h>
#include <esp_log.h>

#include "hap.h"
#include "tlv.h"
#include "srp.h"
#include "hkdf.h"
#include "chacha20_poly1305.h"
#include "ed25519.h"
#include "curve25519.h"
#include "pair_devices.h"
#include "pairing.h"
#include "pair_error.h"
#include "discovery.h"

#define TAG "PAIR"
int write_cnt = 0;
int read_cnt = 0;

struct longterm_key {
    uint8_t public[ED25519_PUBLIC_KEY_LENGTH];
    uint8_t private[ED28819_PRIVATE_KEY_LENGTH];
};

struct pair_desc {
    bool paired;
    char* acc_id;
    struct pairing_db_ops db_ops;

    void* srp;
    struct longterm_key acc_ltk;
    void* paired_devices;

    //TODO FIXME MULTI SESSION
    uint8_t session_key[CURVE25519_SECRET_LENGTH];
};
static struct pair_desc* _pair = NULL;

static const char* header_fmt = 
    "HTTP/1.1 200 OK\r\n"
    "Content-Length: %d\r\n"
    "Content-Type: application/pairing+tlv8\r\n"
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

static uint8_t _state_get(uint8_t* device_msg, int device_msg_length)
{
    struct tlv* state_tlv = tlv_decode((uint8_t*)device_msg, device_msg_length, 
            HAP_TLV_TYPE_STATE);
    if (state_tlv == NULL) {
        ESP_LOGE(TAG, "tlv_decode failed. type:%d\n", HAP_TLV_TYPE_STATE);
        return 0;
    }

    uint8_t state = ((uint8_t*)&state_tlv->value)[0];

    tlv_decoded_item_free(state_tlv);
    return state;
}

uint8_t* _concat3(uint8_t* m1, int m1_len, 
        uint8_t* m2, int m2_len, 
        uint8_t* m3, int m3_len, int* concateated_len)
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

static int _ios_device_signature_verify(void* paired_devices, uint8_t* srp_key, uint8_t* subtlv, int subtlv_length)
{
    uint8_t ios_devicex[HKDF_KEY_LEN] = {0,};
    hkdf_key_get(HKDF_KEY_TYPE_PAIR_SETUP_CONTROLLER, srp_key, SRP_SESSION_KEY_LENGTH, 
            ios_devicex);

    struct tlv* ios_device_pairing_id = tlv_decode(subtlv, subtlv_length, HAP_TLV_TYPE_IDENTIFIER);
    struct tlv* ios_device_ltpk = tlv_decode(subtlv, subtlv_length, HAP_TLV_TYPE_PUBLICKEY);
    struct tlv* ios_device_signature = tlv_decode(subtlv, subtlv_length, HAP_TLV_TYPE_SIGNATURE);

    int ios_device_info_len = 0;
    uint8_t* ios_device_info = _concat3(ios_devicex, sizeof(ios_devicex), 
            (uint8_t*)&ios_device_pairing_id->value, ios_device_pairing_id->length, 
            (uint8_t*)&ios_device_ltpk->value, ios_device_ltpk->length,
            &ios_device_info_len);

    int verified = ed25519_verify((uint8_t*)&ios_device_ltpk->value, ios_device_ltpk->length,
            (uint8_t*)&ios_device_signature->value, ios_device_signature->length,
            ios_device_info, ios_device_info_len);

    _concat_free(ios_device_info);

    pair_devices_add(paired_devices, (uint8_t*)&ios_device_pairing_id->value, 
            (uint8_t*)&ios_device_ltpk->value);

    tlv_decoded_item_free(ios_device_pairing_id);
    tlv_decoded_item_free(ios_device_ltpk);
    tlv_decoded_item_free(ios_device_signature);

    return verified;
}

static int _subtlv_decrypt(enum hkdf_key_type htype,
        enum chacha20_poly1305_type cptype,
        uint8_t* srp_key, uint8_t* device_msg, int device_msg_length, uint8_t** subtlv, int* subtlv_length)
{
    struct tlv* encrypted_tlv = tlv_decode((uint8_t*)device_msg, device_msg_length,
            HAP_TLV_TYPE_ENCRYPTED_DATA);
    if (encrypted_tlv == NULL) {
        ESP_LOGE(TAG, "tlv_devoce HAP_TLV_TYPE_ENCRYPTED_DATA failed\n");
        return -1;
    }

    uint8_t subtlv_key[HKDF_KEY_LEN] = {0,};
    hkdf_key_get(htype, srp_key, SRP_SESSION_KEY_LENGTH, subtlv_key);

    *subtlv = malloc(encrypted_tlv->length);
    int err = chacha20_poly1305_decrypt(cptype, subtlv_key, 
            (uint8_t*)&encrypted_tlv->value, encrypted_tlv->length, *subtlv);
    tlv_decoded_item_free(encrypted_tlv);
    if (err < 0) {
        ESP_LOGE(TAG, "chacha20_poly1305_decrypt failed\n");
        free(*subtlv);
        return -1;
    }
    *subtlv_length = strlen((char*)*subtlv);

    return 0;
}

static int _acc_m6_subtlv(uint8_t* srp_key, char* acc_id, uint8_t* acc_ltk_public, uint8_t* acc_ltk_private,  uint8_t** acc_subtlv, int* acc_subtlv_length)
{
    uint8_t accessoryx[HKDF_KEY_LEN] = {0,};
    hkdf_key_get(HKDF_KEY_TYPE_PAIR_SETUP_ACCESSORY, srp_key, SRP_SESSION_KEY_LENGTH, 
            accessoryx);

    int acc_info_len = 0;
    uint8_t* acc_info = _concat3(accessoryx, sizeof(accessoryx), 
            (uint8_t*)acc_id, 17, 
            acc_ltk_public, ED25519_PUBLIC_KEY_LENGTH, &acc_info_len);

    int acc_signature_length = ED25519_SIGN_LENGTH;
    uint8_t acc_signature[ED25519_SIGN_LENGTH] = {0,};
    ed25519_sign(acc_ltk_public, acc_ltk_private, acc_info, acc_info_len,
            acc_signature, &acc_signature_length);

    _concat_free(acc_info);

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
    chacha20_poly1305_encrypt(CHACHA20_POLY1305_TYPE_PS06, subtlv_key, acc_plain_subtlv, acc_plain_subtlv_length, *acc_subtlv, ((uint8_t*)*acc_subtlv) + acc_plain_subtlv_length);
    
#if 0
    printf("ACC SUBTLV LEN:%d\n", *acc_subtlv_length);
    _array_print((char*)*acc_subtlv, *acc_subtlv_length);
#endif

    free(acc_plain_subtlv);

    return 0;
}

static void _subtlv_free(uint8_t* subtlv)
{
    if (subtlv)
        free(subtlv);
}

static int _setup_m6(struct pair_desc* pair,
        uint8_t* device_msg, int device_msg_length, 
        uint8_t** acc_msg, int* acc_msg_length)
{
    uint8_t srp_key[SRP_SESSION_KEY_LENGTH] = {0,};
    srp_host_session_key(pair->srp, srp_key);

    int device_subtlv_length = 0;;
    uint8_t* device_subtlv;
    int err = _subtlv_decrypt(HKDF_KEY_TYPE_PAIR_SETUP_ENCRYPT, 
            CHACHA20_POLY1305_TYPE_PS05,
            srp_key, device_msg, device_msg_length, &device_subtlv, &device_subtlv_length);
    if (err < 0) {
        ESP_LOGE(TAG, "_subtlv_decrypt failed\n");
        return pair_error(HAP_TLV_ERROR_AUTHENTICATION, acc_msg, acc_msg_length);
    }

    if (_ios_device_signature_verify(pair->paired_devices, srp_key, device_subtlv, device_subtlv_length) < 0) {
        ESP_LOGE(TAG, "_ios_device_signature_verify failed\n");
        return pair_error(HAP_TLV_ERROR_AUTHENTICATION, acc_msg, acc_msg_length);
    }
    _subtlv_free(device_subtlv);

    uint8_t* acc_subtlv;
    int acc_subtlv_length = 0;
    _acc_m6_subtlv(srp_key, pair->acc_id, pair->acc_ltk.public, pair->acc_ltk.private, &acc_subtlv, &acc_subtlv_length);

    uint8_t state[] = {0x06};
    *acc_msg_length = tlv_encode_length(sizeof(state));
    *acc_msg_length += tlv_encode_length(acc_subtlv_length);

    (*acc_msg) = malloc(*acc_msg_length);
    if (*acc_msg == NULL) {
        ESP_LOGE(TAG, "malloc failed. size:%d\n", *acc_msg_length);
        return pair_error(HAP_TLV_ERROR_UNKNOWN, acc_msg, acc_msg_length);
    }

    uint8_t* tlv_encode_ptr = *acc_msg;
    tlv_encode_ptr += tlv_encode(HAP_TLV_TYPE_STATE, sizeof(state), state, tlv_encode_ptr);
    tlv_encode_ptr += tlv_encode(HAP_TLV_TYPE_ENCRYPTED_DATA, acc_subtlv_length, acc_subtlv, tlv_encode_ptr);

    _subtlv_free(acc_subtlv);
    return 0;
}

static int _setup_m4(struct pair_desc* pair, 
        uint8_t* device_msg, int device_msg_length, 
        uint8_t** acc_msg, int* acc_msg_length)
{
    struct tlv* ios_srp_public_key = tlv_decode(device_msg, device_msg_length, 
            HAP_TLV_TYPE_PUBLICKEY);
#if 0
    ESP_LOGI(TAG, "A");
    _array_print((char*)&ios_srp_public_key->value, ios_srp_public_key->length);
#endif

    int err = srp_client_key_set(pair->srp, (uint8_t*)&ios_srp_public_key->value);
    tlv_decoded_item_free(ios_srp_public_key);
    if (err < 0) {
        ESP_LOGE(TAG, "srp_client_key_set failed");
        return pair_error(HAP_TLV_ERROR_AUTHENTICATION, acc_msg, acc_msg_length);
    }

    struct tlv* ios_srp_proof = tlv_decode((uint8_t*)device_msg, device_msg_length, 
            HAP_TLV_TYPE_PROOF);
#if 0
    ESP_LOGI(TAG, "IOS PROOF");
    _array_print((char*)&ios_srp_proof->value, ios_srp_proof->length);
#endif
    err = srp_client_proof_verify(pair->srp, (uint8_t*)&ios_srp_proof->value);
    tlv_decoded_item_free(ios_srp_proof);
    if (err < 0) {
        ESP_LOGE(TAG, "srp_client_proof_verify failed\n");
        return pair_error(HAP_TLV_ERROR_AUTHENTICATION, acc_msg, acc_msg_length);
    }

    uint8_t acc_srp_proof[SRP_PROOF_LENGTH] = {0,};
    err = srp_host_proof_get(pair->srp, acc_srp_proof);
    if (err < 0) {
        ESP_LOGE(TAG, "srp_host_proof_get failed\n");
        return pair_error(HAP_TLV_ERROR_UNKNOWN, acc_msg, acc_msg_length);
    }
    *acc_msg_length = tlv_encode_length(SRP_PROOF_LENGTH);

    uint8_t state[] = {0x04};
    *acc_msg_length += tlv_encode_length(sizeof(state));

    (*acc_msg) = malloc(*acc_msg_length);
    if (*acc_msg == NULL) {
        ESP_LOGE(TAG, "malloc failed. size:%d\n", *acc_msg_length);
        return pair_error(HAP_TLV_ERROR_UNKNOWN, acc_msg, acc_msg_length);
    }

    uint8_t* tlv_encode_ptr = *acc_msg;
    tlv_encode_ptr += tlv_encode(HAP_TLV_TYPE_PROOF, SRP_PROOF_LENGTH, acc_srp_proof, tlv_encode_ptr);
    tlv_encode_ptr += tlv_encode(HAP_TLV_TYPE_STATE, sizeof(state), state, tlv_encode_ptr);
    
    return 0;
}

static int _setup_m2(struct pair_desc* pair, 
        uint8_t* device_msg, int device_msg_length, 
        uint8_t** acc_msg, int* acc_msg_length)
{
    if (pair->srp) {
        srp_cleanup(pair->srp);
    }
    pair->srp = srp_init("053-58-197");
    uint8_t host_public_key[SRP_PUBLIC_KEY_LENGTH] = {0,};
    if (srp_host_key_get(pair->srp, host_public_key) < 0) {
        ESP_LOGE(TAG, "srp_host_key_get failed\n");
        return pair_error(HAP_TLV_ERROR_UNKNOWN, acc_msg, acc_msg_length);
    }
    *acc_msg_length = tlv_encode_length(SRP_PUBLIC_KEY_LENGTH);

#if 0
    ESP_LOGI(TAG, "SRP_PUBLIC_KEY_LENGTH");
    _array_print((char*)host_public_key, SRP_PUBLIC_KEY_LENGTH);
#endif

    uint8_t salt[SRP_SALT_LENGTH] = {0,};
    if (srp_salt(pair->srp, salt) < 0) {
        ESP_LOGE(TAG, "srp_salt failed\n");
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
        ESP_LOGE(TAG, "malloc failed\n");
        return pair_error(HAP_TLV_ERROR_UNKNOWN, acc_msg, acc_msg_length);
    }

    uint8_t* tlv_encode_ptr = *acc_msg;
    tlv_encode_ptr += tlv_encode(HAP_TLV_TYPE_SALT, SRP_SALT_LENGTH, salt, tlv_encode_ptr);
    tlv_encode_ptr += tlv_encode(HAP_TLV_TYPE_PUBLICKEY, SRP_PUBLIC_KEY_LENGTH, host_public_key, tlv_encode_ptr);
    tlv_encode_ptr += tlv_encode(HAP_TLV_TYPE_STATE, sizeof(state), state, tlv_encode_ptr);

    return 0;
}

static void _acc_ltk_init(struct pairing_db_ops* ops, struct longterm_key* ltk)
{
#if 1
    {
        ops->erase("SIGN_PUBLIC");
        ops->erase("SIGN_PRIVATE");
    }
#endif

    int signature_public_len = ops->get("SIGN_PUBLIC", ltk->public, ED25519_PUBLIC_KEY_LENGTH);
    int signature_private_len = ops->get("SIGN_PRIVATE", ltk->private, ED28819_PRIVATE_KEY_LENGTH);

    if (signature_public_len == 0 || signature_private_len == 0) {
        ed25519_key_generate(ltk->public, ltk->private);
        ops->set("SIGN_PUBLIC", ltk->public, ED25519_PUBLIC_KEY_LENGTH);
        ops->set("SIGN_PRIVATE", ltk->private, ED28819_PRIVATE_KEY_LENGTH);
    }

#if 0
    for (int i=0; i<ED25519_PUBLIC_KEY_LENGTH; i++)
        printf("%02X ", ltk->public[i]);
    printf("\n");
    for (int i=0; i<ED28819_PRIVATE_KEY_LENGTH; i++)
        printf("%02X ", ltk->private[i]);
    printf("\n");
#endif
}

static int _pairing_setup(struct pair_desc* pair, uint8_t* device_msg, int device_msg_length, 
        uint8_t** acc_msg, int* acc_msg_length)
{
    if (!pair || !device_msg || device_msg_length == 0 || !acc_msg || !acc_msg_length) {
        ESP_LOGE(TAG, "Invalid arguments\n");
        return -1;
    }

    uint8_t state = _state_get(device_msg, device_msg_length);
    ESP_LOGI(TAG, "STATE:%d", state);
    switch (state) {
    case 0x01:
        return _setup_m2(pair, device_msg, device_msg_length,
                acc_msg, acc_msg_length);
    case 0x03:
        return _setup_m4(pair, device_msg, device_msg_length,
                acc_msg, acc_msg_length);
    case 0x05:
        return _setup_m6(pair, device_msg, device_msg_length,
                 acc_msg, acc_msg_length);
    default:
        ESP_LOGE(TAG, "Invalid state number. %d\n", state);
        return -1;
    }
}

int pairing_over_ip_setup(
        char* req_body, int req_body_length, 
        char** res_header, int* res_header_len, char** res_body, int* res_body_len)
{
    if (!_pair) {
        ESP_LOGE(TAG, "pairing module is not initialized\n");
        return -1;
    }

    int err = _pairing_setup(_pair, (uint8_t*)req_body, req_body_length, (uint8_t**)res_body, res_body_len);
    if (err < 0) {
        ESP_LOGE(TAG, "_pairing_setup failed\n");
        return -1;
    }

    *res_header = malloc(strlen(header_fmt) + 16);
    sprintf(*res_header, header_fmt, *res_body_len);
    *res_header_len = strlen(*res_header);

    return 0;
}

static int _verify_m4(struct pair_desc* pair, 
        uint8_t* device_msg, int device_msg_length, 
        uint8_t** acc_msg, int* acc_msg_length)
{
#if 1
    struct tlv* encrypted_tlv = tlv_decode((uint8_t*)device_msg, device_msg_length,
            HAP_TLV_TYPE_ENCRYPTED_DATA);
    if (encrypted_tlv == NULL) {
        ESP_LOGE(TAG, "tlv_devoce HAP_TLV_TYPE_ENCRYPTED_DATA failed\n");
        return -1;
    }

    uint8_t subtlv_key[HKDF_KEY_LEN] = {0,};
    hkdf_key_get(HKDF_KEY_TYPE_PAIR_VERIFY_ENCRYPT, pair->session_key, CURVE25519_SECRET_LENGTH, subtlv_key);

    uint8_t* subtlv = malloc(encrypted_tlv->length);

    chacha20_poly1305_decrypt(CHACHA20_POLY1305_TYPE_PV03, subtlv_key, (uint8_t*)&encrypted_tlv->value, encrypted_tlv->length, subtlv);

    tlv_decoded_item_free(encrypted_tlv);

    int subtlv_length = strlen((char*)subtlv);;


    struct tlv* ios_device_pairng_id = tlv_decode(subtlv, subtlv_length, 
            HAP_TLV_TYPE_IDENTIFIER);
    if (ios_device_pairng_id == NULL) {
        ESP_LOGE(TAG, "tlv_devoce HAP_TLV_TYPE_IDENTIFIER failed\n");
        return -1;
    }

    struct tlv* ios_device_signature = tlv_decode(subtlv, subtlv_length, 
            HAP_TLV_TYPE_SIGNATURE);
    if (ios_device_signature == NULL) {
        ESP_LOGE(TAG, "tlv_devoce HAP_TLV_TYPE_SIGNATURE failed\n");
        return -1;
    }

    free(subtlv);

    tlv_decoded_item_free(ios_device_pairng_id);
    tlv_decoded_item_free(ios_device_signature);
#endif

    uint8_t state[] = {4};
    *acc_msg_length = tlv_encode_length(sizeof(state));

    //uint8_t error[] = {HAP_TLV_ERROR_AUTHENTICATION};
    //*acc_msg_length += tlv_encode_length(sizeof(error));

    (*acc_msg) = malloc(*acc_msg_length);
    if (*acc_msg == NULL) {
        ESP_LOGE(TAG, "malloc failed\n");
        return pair_error(HAP_TLV_ERROR_UNKNOWN, acc_msg, acc_msg_length);
    }

    uint8_t* tlv_encode_ptr = *acc_msg;
    tlv_encode_ptr += tlv_encode(HAP_TLV_TYPE_STATE, sizeof(state), state, tlv_encode_ptr);

    //tlv_encode_ptr += tlv_encode(HAP_TLV_TYPE_ERROR, sizeof(error), error, tlv_encode_ptr);
#if 1
    _array_print((char*)*acc_msg, *acc_msg_length);
#endif
    pair->paired = true;

    return 0;
}

static int _verify_m2(struct pair_desc* pair, 
        uint8_t* device_msg, int device_msg_length, 
        uint8_t** acc_msg, int* acc_msg_length)
{
    uint8_t acc_curve_public_key[CURVE25519_KEY_LENGTH] = {0,};
    uint8_t acc_curve_private_key[CURVE25519_KEY_LENGTH] = {0,};
    if (curve25519_key_generate(acc_curve_public_key, acc_curve_private_key) < 0) {
        ESP_LOGE(TAG, "curve25519_key_generate failed\n");
        return -1;
    }

    struct tlv* ios_device_curve_key = tlv_decode((uint8_t*)device_msg, 
            device_msg_length, HAP_TLV_TYPE_PUBLICKEY);

    uint8_t session_key[CURVE25519_SECRET_LENGTH] = {0,};
    int session_key_length = CURVE25519_SECRET_LENGTH;
    if (curve25519_shared_secret((uint8_t*)&ios_device_curve_key->value,
            acc_curve_private_key, session_key, &session_key_length) < 0) {
        ESP_LOGE(TAG, "curve25519_shared_secret failed\n");
        return -1;
    }

    int acc_info_len;
    uint8_t* acc_info = _concat3(acc_curve_public_key, CURVE25519_KEY_LENGTH,
            (uint8_t*)pair->acc_id, strlen(pair->acc_id),
            (uint8_t*)&ios_device_curve_key->value, ios_device_curve_key->length,
            &acc_info_len);

    tlv_decoded_item_free(ios_device_curve_key);

    int acc_signature_length = ED25519_SIGN_LENGTH;
    uint8_t acc_signature[ED25519_SIGN_LENGTH] = {0,};
    ed25519_sign(pair->acc_ltk.public, pair->acc_ltk.private, 
            acc_info, acc_info_len,
            acc_signature, &acc_signature_length);

    _concat_free(acc_info);

    int acc_plain_subtlv_length = tlv_encode_length(strlen(pair->acc_id));
    acc_plain_subtlv_length += tlv_encode_length(acc_signature_length);

    uint8_t* acc_plain_subtlv = malloc(acc_plain_subtlv_length);
    uint8_t* sub_tlv_write_ptr = acc_plain_subtlv;

    sub_tlv_write_ptr += tlv_encode(HAP_TLV_TYPE_IDENTIFIER, strlen(pair->acc_id), (uint8_t*)pair->acc_id, sub_tlv_write_ptr);
    sub_tlv_write_ptr += tlv_encode(HAP_TLV_TYPE_SIGNATURE, ED25519_SIGN_LENGTH, acc_signature, sub_tlv_write_ptr);

    int acc_subtlv_length = acc_plain_subtlv_length + CHACHA20_POLY1305_AUTH_TAG_LENGTH;
    uint8_t* acc_subtlv = (uint8_t*)calloc(1, acc_subtlv_length);

    uint8_t subtlv_key[HKDF_KEY_LEN] = {0,};
    hkdf_key_get(HKDF_KEY_TYPE_PAIR_VERIFY_ENCRYPT, session_key, CURVE25519_SECRET_LENGTH, subtlv_key);
    chacha20_poly1305_encrypt(CHACHA20_POLY1305_TYPE_PV02, subtlv_key, acc_plain_subtlv, acc_plain_subtlv_length, acc_subtlv, acc_subtlv + acc_plain_subtlv_length);

    free(acc_plain_subtlv);

    uint8_t state[] = {0x02};
    *acc_msg_length = tlv_encode_length(sizeof(state));
    *acc_msg_length += tlv_encode_length(acc_subtlv_length);
    *acc_msg_length += tlv_encode_length(CURVE25519_KEY_LENGTH);

    (*acc_msg) = malloc(*acc_msg_length);
    if (*acc_msg == NULL) {
        ESP_LOGE(TAG, "malloc failed. size:%d\n", *acc_msg_length);
        return pair_error(HAP_TLV_ERROR_UNKNOWN, acc_msg, acc_msg_length);
    }

    uint8_t* tlv_encode_ptr = *acc_msg;
    tlv_encode_ptr += tlv_encode(HAP_TLV_TYPE_STATE, sizeof(state), state, tlv_encode_ptr);
    tlv_encode_ptr += tlv_encode(HAP_TLV_TYPE_PUBLICKEY, CURVE25519_KEY_LENGTH, acc_curve_public_key, tlv_encode_ptr);
    tlv_encode_ptr += tlv_encode(HAP_TLV_TYPE_ENCRYPTED_DATA, acc_subtlv_length, acc_subtlv, tlv_encode_ptr);

    _subtlv_free(acc_subtlv);

    //TODO FIXME MULTI SESSION
    memcpy(pair->session_key, session_key, CURVE25519_SECRET_LENGTH);
    
    return 0;
}

static int _pairing_verify(struct pair_desc* pair, 
        uint8_t* device_msg, int device_msg_length, 
        uint8_t** acc_msg, int* acc_msg_length)
{
    if (!pair || !device_msg || device_msg_length == 0 || !acc_msg || !acc_msg_length) {
        ESP_LOGE(TAG, "Invalid arguments\n");
        return -1;
    }

    uint8_t state = _state_get(device_msg, device_msg_length);
    ESP_LOGI(TAG, "VERIFY STATE:%d", state);
    switch (state) {
    case 0x01:
        return _verify_m2(pair, device_msg, device_msg_length,
                acc_msg, acc_msg_length);
    case 0x03:
        return _verify_m4(pair, device_msg, device_msg_length,
                acc_msg, acc_msg_length);
    default:
        ESP_LOGE(TAG, "Invalid state number. %d\n", state);
        return -1;
    }
}

int pairing_over_ip_verify(char* req_body, int req_body_length, 
        char** res_header, int* res_header_len, char** res_body, int* res_body_len)
{
    if (!_pair) {
        ESP_LOGE(TAG, "pairing module is not initialized\n");
        return -1;
    }

    int err = _pairing_verify(_pair, (uint8_t*)req_body, req_body_length, (uint8_t**)res_body, res_body_len);
    if (err < 0) {
        ESP_LOGE(TAG, "_pairing_verify failed\n");
        return -1;
    }

    *res_header = calloc(1, strlen(header_fmt) + 16);
    sprintf(*res_header, header_fmt, *res_body_len);
    *res_header_len = strlen(*res_header);

    return 0;
}

void pairing_over_ip_free(char* res_header, char*res_body)
{
    if (res_header)
        free(res_header);

    if (res_body)
        free(res_body);
}

int pairing_init(char* setup_code, char* acc_id, struct pairing_db_ops* ops)
{
    if (_pair) {
        ESP_LOGW(TAG, "Already Initialized\n");
        return 0;
    }

    if (!acc_id || !ops) {
        ESP_LOGE(TAG, "Invalid arguments\n");
        return -1;
    }

    _pair = malloc(sizeof(struct pair_desc));
    if (!_pair) {
        ESP_LOGE(TAG, "malloc failed.\n");
        return -1;
    }

    _pair->paired_devices = pair_devices_init(ops);

    _pair->srp = NULL;
    _pair->db_ops = *ops;

    _pair->acc_id = strdup(acc_id);
    _acc_ltk_init(&_pair->db_ops, &_pair->acc_ltk);

    discovery_init("lights", 661, "HOME ACC", acc_id, 1, HAP_ACCESSORY_CATEGORY_LIGHTBULB);
    return 0;
}

void pairing_cleanup(void)
{
    free(_pair->acc_id);
    if (_pair->srp)
        srp_cleanup(_pair->srp);
    free(_pair);
}

void paired_msg(int len, char* msg)
{
#if 0
    struct pair_desc *pair = _pair;
    if (pair->paired == false)
        return;

    uint8_t key[HKDF_KEY_LEN] = {0,};

    hkdf_key_get(HKDF_KEY_TYPE_CONTROL_READ, pair->session_key, CURVE25519_SECRET_LENGTH, key);

    uint8_t* tmp = (uint8_t*)msg;
    uint8_t* decrypted;
    decrypted = malloc(len);
    int offset = 0;
    int l = 0;

    uint8_t nonce[CHACHA20_POLY1305_NONCE_LENGTH] = {0,};
    while (offset < len) {
        l = msg[0]  + msg[1]*256;
        nonce[4] = write_cnt % 256;
        nonce[4] = write_cnt++ / 256;


        //chacha20_poly1305_decrypt_with_nonce(nonce, key, msg, l, )



    }

#endif

}

void pairing_test(void)
{
}
