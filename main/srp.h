#ifndef _SRP_H_
#define _SRP_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stdint.h>

#define SRP_SALT_LENGTH 16
#define SRP_PUBLIC_KEY_LENGTH  384
#define SRP_PROOF_LENGTH    64
#define SRP_SESSION_KEY_LENGTH  64

int srp_init(const char* setup_code);

/*
 * Make salt
 */
uint8_t* srp_salt(void);

/*
 * Make ESP32 public key. Length is 384
 */
uint8_t* srp_B(void);

/*
 * Set iOS Public key
 */
bool srp_A_set(uint8_t* A);

/*
 * Verify iOS Device proof
 */
bool srp_verify(uint8_t* proof);

/*
 * Return ESP32 proof for iOS Device. Length is 64
 */
uint8_t* srp_response(void);

uint8_t* srp_session_key(void);

#ifdef __cplusplus
}
#endif

#endif //#ifndef _SRP_H_
