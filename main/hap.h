#ifndef _HAP_H_
#define _HAP_H_

#ifdef __cplusplus
extern "C" {
#endif

#define HAP_ID_LENGTH       17
#define HAP_PINCODE_LENGTH  10

#include "hap_types.h"


typedef struct {
    void* dummy;
} hap_accessory_callback_t;

#ifdef __cplusplus
}
#endif

#endif //#ifndef _HAP_H_
