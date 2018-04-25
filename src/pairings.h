
#ifndef _PAIRINGS_H_
#define _PAIRINGS_H_

#ifdef __cplusplus
extern "C" {
#endif

int pairings_do(void* iosdevices, char* req_body, int req_body_len, 
        char** res_header, int* res_header_len, char** res_body, int* res_body_len);
void pairings_do_free(char* res_header, char*res_body);

#ifdef __cplusplus
}
#endif

#endif //#ifndef _PAIRINGS_H_

