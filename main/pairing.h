#ifndef _PAIR_H_
#define _PAIR_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "pairing_types.h"

int pairing_over_ip_pairings(
        char* req_body, int req_body_length, 
        char** res_header, int* res_header_len, char** res_body, int* res_body_len);

int pairing_over_ip_verify(
        char* req_body, int req_body_length, 
        char** res_header, int* res_header_len, char** res_body, int* res_body_len);

int pairing_over_ip_setup(
        char* req_body, int req_body_length, 
        char** res_header, int* res_header_len, char** res_body, int* res_body_len);

void pairing_over_ip_free(char* res_header, char*res_body);

int pairing_init(char* setup_code, char* acc_id, struct pairing_db_ops* ops);
void pairing_cleanup(void);

void paired_msg(int len, char* msg);
void pairing_test(void);
#ifdef __cplusplus
}
#endif

#endif //#ifndef _PAIR_H_
