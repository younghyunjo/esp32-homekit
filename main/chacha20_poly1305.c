#include <stdio.h>
#include <stdint.h>

#include <esp_log.h>
#include <wolfssl/wolfcrypt/chacha20_poly1305.h>

#include "chacha20_poly1305.h"

#define TAG "CHACHA20_POLY1305"

#define NONCE_LENGTH    12

static uint8_t nonce[][NONCE_LENGTH] = {
    {0, 0, 0, 0, 'P', 'S', '-', 'M', 's', 'g', '0', '5'},
    {0, 0, 0, 0, 'P', 'S', '-', 'M', 's', 'g', '0', '6'},
    {0, 0, 0, 0, 'P', 'V', '-', 'M', 's', 'g', '0', '2'},
    {0, 0, 0, 0, 'P', 'V', '-', 'M', 's', 'g', '0', '3'},
};

static uint8_t* _type_to_nonce(enum chacha20_poly1305_type type) {
    return nonce[type];
}

int chacha20_poly1305_decrypt(enum chacha20_poly1305_type type, uint8_t* key, 
        uint8_t* encrypted, int encrypted_len, uint8_t* decrypted)
{
    uint8_t* nonce = _type_to_nonce(type);
    uint8_t* cipher_text = encrypted;
    int cipher_text_len = encrypted_len - CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE;
    uint8_t* auth_tag = encrypted + cipher_text_len;

    int err = wc_ChaCha20Poly1305_Decrypt(key, nonce, NULL, 0, cipher_text, cipher_text_len, auth_tag, decrypted);
    if (err < 0) {
        ESP_LOGE(TAG, "wc_ChaCha20Poly1305_Decrypt failed. err:%d\n", err);
        return -1;
    }

    return 0;
}

int chacha20_poly1305_encrypt(enum chacha20_poly1305_type type, uint8_t* key, 
        uint8_t* plain_text, int plain_text_length, 
        uint8_t* encrypted, uint8_t* auth_tag)
{
    uint8_t* nonce = _type_to_nonce(type);
    int err = wc_ChaCha20Poly1305_Encrypt(key, nonce, NULL, 0, plain_text, plain_text_length, encrypted, auth_tag);
    if (err < 0) {
        ESP_LOGE(TAG, "wc_ChaCha20Poly1305_Encrypt failed. err:%d\n", err);
        return -1;
    }
    return 0;
}
