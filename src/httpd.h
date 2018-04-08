#ifndef _HTTPD_H_
#define _HTTPD_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "mongoose.h"

struct httpd_ops {
    void (*accept)(void* user_data, struct mg_connection* nc);
    void (*close)(void* user_data, struct mg_connection* nc);
    void (*recv)(void* user_data, struct mg_connection* nc, char* msg, int length);
};

void* httpd_bind(int port, void* user_data);
void httpd_init(struct httpd_ops* ops);

#ifdef __cplusplus
}
#endif

#endif  //#ifndef _HTTPD_H_
