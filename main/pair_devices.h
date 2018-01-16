#ifndef _PAIR_DEVICES_H_
#define _PAIR_DEVICES_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "pairing_types.h"

int pair_device_del(void* pd, uint8_t* id, uint8_t* ltpk);
int pair_devices_add(void* pd, uint8_t* id, uint8_t* ltpk);
void* pair_devices_init(struct pairing_db_ops* ops);


#ifdef __cplusplus
}
#endif

#endif //#ifndef _PAIR_DEVICES_H_
