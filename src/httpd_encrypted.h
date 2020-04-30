#pragma once

#include <esp_err.h>
#include <esp_http_server.h>
#include "hap_internal.h"

#define MAX_RX_LENGTH 2048


void httpd_encrypted_init(int port);

esp_err_t httpd_encrypted_start(httpd_handle_t *server);

void httpd_encrypted_stop(httpd_handle_t server);

void httpd_encrypted_terminate(httpd_handle_t s_server);

struct hap_connection *httpd_encrypted_get_connection(int sock_fd);

int httpd_encrypted_recv_body(httpd_req_t *req, size_t len, char *buf, size_t max_len);

esp_err_t httpd_encrypted_send(httpd_req_t* req, const char *buf, size_t len);

esp_err_t httpd_encrypted_send_err(httpd_req_t *req, httpd_err_code_t error, const char *usr_msg);

int httpd_encrypted_broadcast_event(httpd_handle_t s_server, const char *buf, size_t len);

int httpd_encrypted_get_port();
