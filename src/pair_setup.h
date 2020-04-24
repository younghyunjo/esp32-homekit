#ifndef _PAIR_SETUP_H_
#define _PAIR_SETUP_H_

#ifdef __cplusplus
extern "C" {
#endif

int pair_setup_do(void* _ps, char* req_body, int req_body_len, char** res_body, int* res_body_len);

void* pair_setup_init(char* acc_id, char* setup_code, void* iosdevices, uint8_t* public_key, uint8_t* private_key);
void pair_setup_cleanup(void* _ps);;

#ifdef __cplusplus
}
#endif

#endif //#ifndef _PAIR_SETUP_H_

