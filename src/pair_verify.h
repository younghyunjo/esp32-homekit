#ifndef _PAIR_VERIFY_H_
#define _PAIR_VERIFY_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>

/**
 *
 * @param pair_verify
 * @param req_body
 * @param req_body_len
 * @param res_body
 * @param res_body_len
 * @param session_key
 * @return <0 if did not verify
 */
int pair_verify_do(void* pair_verify, const char* req_body, int req_body_len,
        char** res_body, int* res_body_len,
        char* session_key);

void* pair_verify_init(char* acc_id, void* iosdevices, uint8_t* public_key, uint8_t* private_key);

void pair_verify_cleanup(void* _pv);

#ifdef __cplusplus
}
#endif

#endif //#ifndef _PAIR_VERIFY_H_

