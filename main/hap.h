#ifndef _HAP_H_
#define _HAP_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#define HAP_ID_LENGTH       17
#define HAP_PINCODE_LENGTH  10

#include "hap_types.h"

struct hap_webserver_ops {
    void* (*bind)(int port, void* user_data);
    void (*unbind)(void* instance);
};

typedef struct {
    void* dummy;
} hap_accessory_callback_t;

void* hap_accessory_add(char* name, char* id, char* pincode, char* vendor, enum hap_accessory_category category,
                        int port, uint32_t config_number, void* callback_arg, hap_accessory_callback_t* callback);


void hap_init(void);

#ifdef __cplusplus
}
#endif

#endif //#ifndef _HAP_H_
