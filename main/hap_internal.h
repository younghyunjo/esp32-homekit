#ifndef _HAP_INTERNAL_H_
#define _HAP_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>

#include "curve25519.h"
#include "list.h"

struct hap_accessory;

struct hap_connection {
    bool pair_verified;

    struct mg_connection* nc;
    struct hap_accessory *a;
    struct list_head list;
    char session_key[CURVE25519_SECRET_LENGTH];

    void* pair_setup;
    void* pair_verify;
};

#ifdef __cplusplus
}
#endif

#endif  //#ifndef _HAP_INTERNAL_H_
