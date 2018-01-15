#ifndef _SRP_H_
#define _SRP_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stdint.h>

#define SRP_SALT_LENGTH         16
#define SRP_PUBLIC_KEY_LENGTH   384
#define SRP_PROOF_LENGTH        64
#define SRP_SESSION_KEY_LENGTH  64

int srp_client_proof_verify(void* instance, uint8_t* proof);
int srp_host_proof_get(void* instance, uint8_t proof[]);

int srp_client_key_set(void* instance, uint8_t* client_public_key);
int srp_host_key_get(void* instance, uint8_t host_public_key[]);

int srp_host_session_key(void* instance, uint8_t session_key[]);
int srp_salt(void* instance, uint8_t salt[]);

void* srp_init(const char* setup_code);
void srp_cleanup(void* instance);

#ifdef __cplusplus
}
#endif

#endif //#ifndef _SRP_H_
