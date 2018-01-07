#ifndef _PAIRING_H_
#define _PAIRING_H_

#ifdef __cplusplus
extern "C" {
#endif

struct pair_db_ops {
    int (*get)(char* key, uint8_t* value, int len);
    int (*set)(char* key, uint8_t* value, int len);
    int (*erase)(char* key);
};

int pairing_setup(char* req_body, int req_body_len,
        char** res_header, char** res_body, int* body_len);
void pairing_setup_free(char* res_header, char* res_body);

void pairing_init(char* accessory_id, char* setup_code);

#ifdef __cplusplus
}
#endif

#endif //#ifndef _PAIRING_H_
