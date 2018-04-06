#ifndef _ED25519_H_
#define _ED25519_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#define ED25519_PUBLIC_KEY_LENGTH   32
#define ED28819_PRIVATE_KEY_LENGTH  64
#define ED25519_SIGN_LENGTH         64

int ed25519_key_generate(uint8_t public_key[], uint8_t private_key[]);
int ed25519_verify(uint8_t* public_key, int key_len, 
        uint8_t* signature, int signature_len, uint8_t* msg, int msg_len);

int ed25519_sign(uint8_t public_key[], uint8_t private_key[], uint8_t* in, int in_len, uint8_t* signatured, int* signated_len);

#ifdef __cplusplus
}
#endif

#endif //#ifndef _ED25519_H_
