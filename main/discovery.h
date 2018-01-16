#ifndef _DISCOVERY_H_
#define _DISCOVERY_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "hap.h"

int discovery_init(const char* host, const int port, const char* model_name,
        const char* id, const uint32_t config_number, const enum hap_accessory_category category);

#ifdef __cplusplus
}
#endif

#endif //#ifndef _DISCOVERY_H_
