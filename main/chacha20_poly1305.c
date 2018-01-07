#include <stdio.h>
#include <stdint.h>

#include <esp_log.h>
#include <wolfssl/wolfcrypt/chacha20_poly1305.h>

#define TAG "CHACHA20_POLY1305"


int chacha20_poly1305_decrypt(uint8_t* key, uint8_t* encrypted, int encrypted_len, uint8_t* decrypted)
{
    uint8_t nonce[]= "0000PS-Msg05";
    nonce[0]=0;
    nonce[1]=0;
    nonce[2]=0;
    nonce[3]=0;

    {
        printf("%s\n", __func__);
        printf("encrypted:%p\n", encrypted);
        printf("encrypted_len:%d\n", encrypted_len);
        printf("decrypted:%p\n", decrypted);
    }

    uint8_t* cipher_text = encrypted;
    int cipher_text_len = encrypted_len - CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE;
    uint8_t* auth_tag = encrypted + cipher_text_len;

    int err = wc_ChaCha20Poly1305_Decrypt(key, nonce, NULL, 0, cipher_text, cipher_text_len, auth_tag, decrypted);
    if (err < 0) {
        ESP_LOGE(TAG, "wc_ChaCha20Poly1305_Decrypt failed. err:%d\n", err);
        return -1;
    }

    printf("end\n");

    return 0;
}

int chacha20_poly1305_encrypt(uint8_t* key, uint8_t* plain_text, int plain_text_length, uint8_t* encrypted, uint8_t* auth_tag)
{
    uint8_t nonce[]= "0000PS-Msg06";
    nonce[0]=0;
    nonce[1]=0;
    nonce[2]=0;
    nonce[3]=0;

    wc_ChaCha20Poly1305_Encrypt(key, nonce, NULL, 0, plain_text, plain_text_length, encrypted, auth_tag);
    return 0;
}
