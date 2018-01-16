#ifndef _NVS_H_
#define _NVS_H_

#ifdef __cplusplus
extern "C" {
#endif

int nvs_get(char* key, uint8_t* value, int len);
int nvs_set(char* key, uint8_t* value, int len);
int nvs_erase(char* key);

#ifdef __cplusplus
}
#endif

#endif //#ifndef _NVS_H_
