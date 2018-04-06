#include <stdio.h>
#include <stdint.h>

#include <esp_log.h>
#include <wolfssl/wolfcrypt/chacha20_poly1305.h>

#include "chacha20_poly1305.h"

#define TAG "CHACHA20_POLY1305"

static uint8_t nonce[][CHACHA20_POLY1305_NONCE_LENGTH] = {
    {0, 0, 0, 0, 'P', 'S', '-', 'M', 's', 'g', '0', '5'},
    {0, 0, 0, 0, 'P', 'S', '-', 'M', 's', 'g', '0', '6'},
    {0, 0, 0, 0, 'P', 'V', '-', 'M', 's', 'g', '0', '2'},
    {0, 0, 0, 0, 'P', 'V', '-', 'M', 's', 'g', '0', '3'},
};

static uint8_t* _type_to_nonce(enum chacha20_poly1305_type type) {
    return nonce[type];
}

int chacha20_poly1305_decrypt_with_nonce(uint8_t* nonce, uint8_t* key, uint8_t* aad, int aad_len, uint8_t* encrypted, int encrypted_len, uint8_t* decrypted)
{
    uint8_t* cipher_text = encrypted;
    int cipher_text_len = encrypted_len - CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE;
    uint8_t* auth_tag = encrypted + cipher_text_len;

    int err = wc_ChaCha20Poly1305_Decrypt(key, nonce, aad, aad_len, cipher_text, cipher_text_len, auth_tag, decrypted);
    if (err < 0) {
        ESP_LOGE(TAG, "wc_ChaCha20Poly1305_Decrypt failed. err:%d\n", err);
        return -1;
    }

    return 0;
}

int chacha20_poly1305_decrypt(enum chacha20_poly1305_type type, uint8_t* key, 
        uint8_t* aad, int aad_len,
        uint8_t* encrypted, int encrypted_len, uint8_t* decrypted)
{
    uint8_t* nonce = _type_to_nonce(type);
    return chacha20_poly1305_decrypt_with_nonce(nonce, key, aad, aad_len, encrypted, encrypted_len, decrypted);
}

int chacha20_poly1305_encrypt_with_nonce(uint8_t nonce[CHACHA20_POLY1305_NONCE_LENGTH], 
        uint8_t* key, uint8_t* aad, int aad_len,
        uint8_t* plain_text, int plain_text_length, 
        uint8_t* encrypted)
{
    uint8_t* auth_tag = encrypted + plain_text_length;
    int err = wc_ChaCha20Poly1305_Encrypt(key, nonce, aad, aad_len, plain_text, plain_text_length, encrypted, auth_tag);
    if (err < 0) {
        ESP_LOGE(TAG, "wc_ChaCha20Poly1305_Encrypt failed. err:%d\n", err);
        return -1;
    }
    return 0;
}


int chacha20_poly1305_encrypt(enum chacha20_poly1305_type type, uint8_t* key, 
        uint8_t* aad, int aad_len,
        uint8_t* plain_text, int plain_text_length, 
        uint8_t* encrypted)
{
    uint8_t* nonce = _type_to_nonce(type);
    return chacha20_poly1305_encrypt_with_nonce(nonce, key, aad, aad_len, plain_text, plain_text_length, encrypted);
}
