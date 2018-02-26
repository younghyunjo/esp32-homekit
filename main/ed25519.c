#include <stdint.h>
#include <esp_log.h>

#include <wolfssl/wolfcrypt/ed25519.h>
#include <wolfssl/wolfcrypt/curve25519.h>

#include "ed25519.h"

#define TAG "ED25519"

int ed25519_key_generate(uint8_t public_key[], uint8_t private_key[])
{
    ed25519_key ed25519_key;
    int err = wc_ed25519_init(&ed25519_key);
    if (err < 0) {
        ESP_LOGE(TAG, "wc_ed25519_init failed. err:%d\n", err);
        return -1;
    }

    WC_RNG rng;
    wc_InitRng(&rng);
    err = wc_ed25519_make_key(&rng, ED25519_KEY_SIZE, &ed25519_key);
    if (err < 0) {
        ESP_LOGE(TAG, "wc_ed25519_make_key failed. err:%d\n", err);
        return -1;
    }

    int key_length = ED25519_PUBLIC_KEY_LENGTH;
    err = wc_ed25519_export_public(&ed25519_key, (byte*)public_key, (word32*)&key_length);
    if (err < 0)
    {
        ESP_LOGE(TAG, "wc_ed25519_export_public failed. err:%d\n", err);
        return -1;
    }

    key_length = ED28819_PRIVATE_KEY_LENGTH;
    err = wc_ed25519_export_private(&ed25519_key, (byte*)private_key, (word32*)&key_length);
    if (err < 0)
    {
        ESP_LOGE(TAG, "wc_ed25519_export_private failed. err:%d\n", err);
        return -1;
    }

    wc_FreeRng(&rng);
    return 0;
}

int ed25519_verify(uint8_t* public_key, int key_len, uint8_t* signature, int signature_len, uint8_t* msg, int msg_len)
{
    ed25519_key ed25519_key;
    int err = wc_ed25519_init(&ed25519_key);
    if (err < 0) {
        ESP_LOGE(TAG, "wc_ed25519_init. err:%d\n", err);
        return err;
    }

    err = wc_ed25519_import_public(public_key, key_len, &ed25519_key);
    if (err < 0) {
        ESP_LOGE(TAG, "wc_ed25519_import_public. err:%d\n", err);
        return err;
    }

    int verified = 0;
    err = wc_ed25519_verify_msg(signature, signature_len, msg, msg_len, 
            &verified, &ed25519_key);
    if (err < 0) {
        ESP_LOGE(TAG, "wc_ed25519_verify_msg. err:%d\n", err);
        return err;
    }
    
    if (verified == 0) {
        ESP_LOGE(TAG, "verification failed. err:%d\n", err);
        return -1;
    }

    return 0;
}

int ed25519_sign(uint8_t public_key[], uint8_t private_key[], uint8_t* in, int in_len, uint8_t* signatured, int* signatured_len)
{
    ed25519_key ed25519_key;
    int err = wc_ed25519_init(&ed25519_key);
    if (err < 0) {
        ESP_LOGE(TAG, "wc_ed25519_init. err:%d\n", err);
        return err;
    }
    
    err = wc_ed25519_import_private_key(private_key, ED25519_KEY_SIZE, private_key + ED25519_KEY_SIZE, ED25519_KEY_SIZE, &ed25519_key);
    if (err < 0) {
        ESP_LOGE(TAG, "wc_ed25519_import_private_key. err:%d\n", err);
        return err;
    }
    
    err = wc_ed25519_sign_msg(in, in_len, signatured, (word32*)signatured_len, &ed25519_key);
    if (err < 0) {
        ESP_LOGE(TAG, "wc_ed25519_sign_msg. err:%d\n", err);
        return err;
    }

    //printf("VERIFIED:%d\n", ed25519_verify(public_key, 32, signatured, *signatured_len, in, in_len));

    return 0;
}
