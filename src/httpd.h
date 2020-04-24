#pragma once

#include <esp_err.h>
#include "hap_internal.h"

esp_err_t httpd_init(struct hap_accessory* accessory);

void httpd_terminate();
