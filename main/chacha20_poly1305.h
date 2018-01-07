#ifndef _CHACHA20_POLY1305_H_
#define _CHACHA20_POLY1305_H_

#ifdef __cplusplus
extern "C" {
#endif

int chacha20_poly1305_decrypt(uint8_t* key, 
        uint8_t* encrypted, int encrypted_len, uint8_t* decrypted);
int chacha20_poly1305_encrypt(uint8_t* key, uint8_t* plain_text, int plain_text_length, uint8_t* encrypted, uint8_t* auth_tag);

#ifdef __cplusplus
}
#endif

#endif //#ifndef _CHACHA20_POLY1305_H_
