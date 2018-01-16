#ifndef _PAIRING_TYPES_H_
#define _PAIRING_TYPES_H_

#ifdef __cplusplus
extern "C" {
#endif

struct pairing_db_ops {
    int (*get)(char* key, uint8_t* value, int len);
    int (*set)(char* key, uint8_t* value, int len);
    int (*erase)(char* key);
};

#ifdef __cplusplus
}
#endif

#endif //#ifndef _PAIRING_TYPES_H_
