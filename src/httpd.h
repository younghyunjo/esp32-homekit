#pragma once

#include <esp_err.h>

esp_err_t httpd_init(int port);
void httpd_terminate();
