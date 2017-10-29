#ifndef _HTTPD_H_
#define _HTTPD_H_

#ifdef __cplusplus
extern "C" {
#endif

struct httpd_restapi {
    char* uri;
    char* method;

    int (*ops)(char* req_body, int req_body_len, 
            char** res_header, char** res_body, int* body_len);

    void (*post_response)(char* res_header, char* res_body);
};

void httpd_start(int port, struct httpd_restapi* api, int nr_restapi);

#ifdef __cplusplus
}
#endif

#endif //#ifndef _HTTPD_H_
