#ifndef _HAP_INTERNAL_H_
#define _HAP_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>

#include <cJSON.h>

#include "curve25519.h"
#include "ed25519.h"
#include "hap.h"
#include "hkdf.h"
#include "list.h"

struct events {
    struct list_head list;
};

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

    int last_aid;
    struct list_head attr_accessories;
    struct list_head connections;

    struct {
        uint8_t public[ED25519_PUBLIC_KEY_LENGTH];
        uint8_t private[ED28819_PRIVATE_KEY_LENGTH];
    } keys;

    void* callback_arg;
    hap_accessory_callback_t callback;
    void* accessories_ojbects;
};

struct hap_connection {
    bool pair_verified;

    struct mg_connection* nc;
    struct hap_accessory *a;
    struct list_head list;
    char session_key[CURVE25519_SECRET_LENGTH];
    uint8_t encrypt_key[HKDF_KEY_LEN];
    uint8_t decrypt_key[HKDF_KEY_LEN];
    int decrypt_count;
    int encrypt_count;

    void* pair_setup;
    void* pair_verify;
};

enum hap_pairing_method {
    HAP_PAIRING_METHOD_SETUP = 1,
    HAP_PAIRING_METHOD_VERIFY,
    HAP_PAIRING_METHOD_ADD,
    HAP_PAIRING_METHOD_REMOVE,
    HAP_PAIRING_METHOD_LIST,
};

enum hap_tlv_type {
    HAP_TLV_TYPE_METHOD,
    HAP_TLV_TYPE_IDENTIFIER,
    HAP_TLV_TYPE_SALT,
    HAP_TLV_TYPE_PUBLICKEY,
    HAP_TLV_TYPE_PROOF,
    HAP_TLV_TYPE_ENCRYPTED_DATA,
    HAP_TLV_TYPE_STATE,
    HAP_TLV_TYPE_ERROR,
    HAP_TLV_TYPE_RETRY_DELAY,
    HAP_TLV_TYPE_CERTIFICATE,
    HAP_TLV_TYPE_SIGNATURE,
    HAP_TLV_TYPE_PERMISSION,
    HAP_TLV_TYPE_FRAGMENT_DATA,
    HAP_TLV_TYPE_FRAGMENT_LAST,
    HAP_TLV_TYPE_SEPARATOR = 0xff,
};

enum hap_tlv_error_codes {
    HAP_TLV_ERROR_UNKNOWN = 1,
    HAP_TLV_ERROR_AUTHENTICATION,
    HAP_TLV_ERROR_BACKOFF,
    HAP_TLV_ERROR_MAX_PEERS,
    HAP_TLV_ERROR_MAX_TRIES,
    HAP_TLV_ERROR_UNAVAILABLE,
    HAP_TLV_ERROR_BUSY,
};

#ifdef __cplusplus
}
#endif

#endif  //#ifndef _HAP_INTERNAL_H_

