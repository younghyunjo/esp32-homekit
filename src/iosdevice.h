#ifndef _IOSDEVICE_H_
#define _IOSDEVICE_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>

#include "ed25519.h"

#define IOSDEVICE_PER_ACCESSORY_MAX  8
#define IOSDEVICE_ID_LEN       36

struct iosdevice {
    char id[IOSDEVICE_ID_LEN];
    char key[ED25519_PUBLIC_KEY_LENGTH];
};

/* idevice is array pointer. array size is IOSDEVICE_PER_ACCESSORY_MAX */
int iosdevice_pairings(void* handle, struct iosdevice *idevice);

int iosdevice_pairings_remove(void* handle, char id[]);
int iosdevice_pairings_add(void* handle, char id[], char key[]);
bool iosdevice_pairing_match(void* handle, char id[], char key[]);
void* iosdevice_pairings_init(char accessory_id[]);

#ifdef __cplusplus
}
#endif

#endif //#ifndef _IOSDEVICE_H_
