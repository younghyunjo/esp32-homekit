#ifndef _SRP_H_
#define _SRP_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>


#define HSRP_SALT_LENGTH 16
#define HSRP_B_LENGTH  384
#define HSRP_PROOF_LENGTH    64
#define SRP_PROOF_LENGTH    64

int hsrp_init(const char* setup_code);
uint8_t* hsrp_salt(void);
uint8_t* hsrp_B(void);

int hsrp_verify_A(uint8_t* bytes_A, int len_A);
int hsrp_verify_session( uint8_t * user_M );
uint8_t* hsrp_hamk(void);
/*
int srp_compute_peer_key(uint8_t key[SRP_PUBLICH_KEY_LENGTH]);
int srp_peer_proof_verify(uint8_t proof[SRP_PROOF_LENGTH]);
int srp_proof_get(uint8_t proof[SRP_PROOF_LENGTH]);
*/

int srp_test(void);
#ifdef __cplusplus
}
#endif

#endif //#ifndef _SRP_H_

