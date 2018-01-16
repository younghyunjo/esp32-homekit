#include <esp_log.h>
#include <esp_wifi.h>
#include <mdns.h>

#include "discovery.h"

#define ARRAY_SIZE(array) (sizeof(array) / sizeof(array[0]))

#define HAP_SERVICE "_hap"
#define HAP_PROTO "_tcp"

#define TAG "DISCOVERY"

static mdns_server_t* _mdns = NULL;

int discovery_init(const char* host, const int port, const char* model_name,
        const char* id, const uint32_t config_number, const enum hap_accessory_category category) {
#define SERVICE_TXT_LEN 64

    if (_mdns != NULL) {
        ESP_LOGW(TAG, "discovery is already intialized\n");
        return 0;
    }

    char service_txt_c_sharp[SERVICE_TXT_LEN] = {0,};
    sprintf(service_txt_c_sharp, "c#=%u", config_number);

    char service_txt_id[SERVICE_TXT_LEN] = {0,};
    sprintf(service_txt_id, "id=%s", id);

    char service_txt_md[SERVICE_TXT_LEN] = {0,};
    sprintf(service_txt_md, "md=%s", model_name);

    char service_txt_ci[SERVICE_TXT_LEN] = {0,};
    sprintf(service_txt_ci, "ci=%d", category);

    const char* hap_service_txt[] = {
        service_txt_c_sharp,
        "ff=0",
        service_txt_id,
        service_txt_md,
        "s#=1",
        "sf=1",
        service_txt_ci,
    };

    ESP_ERROR_CHECK(mdns_init(TCPIP_ADAPTER_IF_STA, &_mdns));
    ESP_ERROR_CHECK(mdns_set_hostname(_mdns, host));
    ESP_ERROR_CHECK(mdns_set_instance(_mdns, model_name));
    ESP_ERROR_CHECK(mdns_service_add(_mdns, HAP_SERVICE, HAP_PROTO, port));
    ESP_ERROR_CHECK(mdns_service_txt_set(_mdns, HAP_SERVICE, HAP_PROTO, ARRAY_SIZE(hap_service_txt), hap_service_txt));

    return 0;
}
