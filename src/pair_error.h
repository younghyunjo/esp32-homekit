#include "hap.h"
#ifndef _PAIR_ERROR_H_
#define _PAIR_ERROR_H_

#ifdef __cplusplus
extern "C" {
#endif

int pair_error(enum hap_tlv_error_codes error_codes, 
        uint8_t** acc_msg, int* acc_msg_length);
void pair_error_free(uint8_t* error_msg);

#ifdef __cplusplus
}
#endif

#endif //#ifndef _PAIR_ERROR_H_
