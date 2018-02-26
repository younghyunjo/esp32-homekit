#ifndef _CURVE25519_H_
#define _CURVE25519_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#define CURVE25519_KEY_LENGTH       32
#define CURVE25519_SECRET_LENGTH    32

int curve25519_key_generate(uint8_t public_key[], uint8_t private_key[]);
int curve25519_shared_secret(uint8_t public_key[], uint8_t private_key[], 
        uint8_t* secret, int* secret_length);

#ifdef __cplusplus
}
#endif

#endif //#ifndef _CURVE25519_H_
