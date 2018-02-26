#ifndef _CONCAT_H_
#define _CONCAT_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

uint8_t* concat3(uint8_t* m1, int m1_len, 
        uint8_t* m2, int m2_len, 
        uint8_t* m3, int m3_len, int* concateated_len);
void concat_free(uint8_t* concatenated);

#ifdef __cplusplus
}
#endif

#endif //#ifndef _CONCAT_H_
