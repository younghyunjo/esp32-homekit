#ifndef _PAIR_H_
#define _PAIR_H_

#ifdef __cplusplus
extern "C" {
#endif

struct pair_db_ops {
    int (*get)(char* key, uint8_t* value, int len);
    int (*set)(char* key, uint8_t* value, int len);
    int (*erase)(char* key);
};

int pairing_over_ip(
        char* req_body, int req_body_length, 
        char** res_header, int* res_header_len, char** res_body, int* res_body_len);
void pairing_over_ip_free(char* res_header, char*res_body);

int pairing_init(char* setup_code, char* acc_id, struct pair_db_ops* ops);
void pairing_cleanup(void);

#ifdef __cplusplus
}
#endif

#endif //#ifndef _PAIR_H_
