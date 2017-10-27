#ifndef _SRP_H_
#define _SRP_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#define SRP_SALT_LENGTH 16
#define SRP_PUBLICH_KEY_LENGTH  384
#define SRP_PROOF_LENGTH    64

int srp_init(const char* setup_code);
int srp_salt_get(uint8_t salt[SRP_SALT_LENGTH]);
int srp_publich_key_get(uint8_t key[SRP_PUBLICH_KEY_LENGTH]);

int srp_compute_peer_key(uint8_t key[SRP_PUBLICH_KEY_LENGTH]);
int srp_peer_proof_verify(uint8_t proof[SRP_PROOF_LENGTH]);

#ifdef __cplusplus
}
#endif

#endif //#ifndef _SRP_H_

