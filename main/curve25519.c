#include <esp_log.h>
#include <wolfssl/wolfcrypt/curve25519.h>

#include "curve25519.h"

#define TAG "CURVE25519"

int curve25519_key_generate(uint8_t public_key[], uint8_t private_key[])
{
    WC_RNG rng;
    wc_InitRng(&rng);

    curve25519_key key;
    wc_curve25519_init(&key);

    int err = wc_curve25519_make_key(&rng, 32, &key);
    if (err < 0) {
        ESP_LOGE(TAG, "wc_curve25519_make_key failed. err:%d\n", err);
        return -1;
    }

    uint32_t key_length = CURVE25519_KEY_LENGTH;
    err = wc_curve25519_export_public_ex(&key, public_key, &key_length,
            EC25519_LITTLE_ENDIAN);
    if (err < 0) {
        ESP_LOGE(TAG, "wc_curve25519_export_public failed. err:%d\n", err);
        return -1;
    }

    key_length = CURVE25519_KEY_LENGTH;
    err = wc_curve25519_export_private_raw_ex(&key, private_key, &key_length,
            EC25519_LITTLE_ENDIAN);
    if (err < 0) {
        ESP_LOGE(TAG, "wc_curve25519_export_private_raw_ex failed. err:%d\n", err);
        return -1;
    }

    return 0;
}


int curve25519_shared_secret(uint8_t public_key[], uint8_t private_key[], 
        uint8_t* secret, int* secret_length)
{
    curve25519_key public;;
    wc_curve25519_init(&public);
    int err = wc_curve25519_import_public_ex(public_key, CURVE25519_KEY_LENGTH, 
            &public, EC25519_LITTLE_ENDIAN);
    if (err < 0) {
        ESP_LOGE(TAG, "wc_curve25519_import_public_ex failed. err:%d\n", err);
        return -1;
    }

    curve25519_key private;;
    wc_curve25519_init(&private);
    err = wc_curve25519_import_private_ex(private_key, CURVE25519_KEY_LENGTH, 
            &private, EC25519_LITTLE_ENDIAN);
    if (err < 0) {
        ESP_LOGE(TAG, "wc_curve25519_import_private_ex failed. err:%d\n", err);
        return -1;
    }

    err = wc_curve25519_shared_secret_ex(&private, &public, 
            secret, (uint32_t*)secret_length, EC25519_LITTLE_ENDIAN);
    if (err < 0) {
        ESP_LOGE(TAG, "wc_curve25519_shared_secret_ex failed. err:%d\n", err);
        return -1;
    }

    return 0;
}
