#ifndef _PAIRING_H_
#define _PAIRING_H_

#ifdef __cplusplus
extern "C" {
#endif

int pairing_setup(char* req_body, int req_body_len,
        char** res_header, char** res_body, int* body_len);
void pairing_setup_free(char* res_header, char* res_body);

#ifdef __cplusplus
}
#endif

#endif //#ifndef _PAIRING_H_
