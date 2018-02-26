#include <string.h>
#include <esp_log.h>
#include <esp_wifi.h>
#include <mdns.h>

#include "discovery.h"

#define ARRAY_SIZE(array) (sizeof(array) / sizeof(array[0]))

#define HAP_SERVICE "_hap"
#define HAP_PROTO "_tcp"

#define TAG "DISCOVERY"

static mdns_server_t* _mdns = NULL;

struct discovery_desc {
    uint32_t config_number;
    char* id;
    char* model_name;
    enum hap_accessory_category category;
    bool paired;
};
static struct discovery_desc* _dd;

static void _service_txt_set(struct discovery_desc* dd)
{
}

int discovery_init(const char* host, const int port, const char* model_name,
        const char* id, const uint32_t config_number, const enum hap_accessory_category category) {

    if (_mdns != NULL) {
        ESP_LOGW(TAG, "discovery is already intialized\n");
        return 0;
    }


    ESP_ERROR_CHECK(mdns_init(TCPIP_ADAPTER_IF_STA, &_mdns));
    ESP_ERROR_CHECK(mdns_set_hostname(_mdns, host));
    ESP_ERROR_CHECK(mdns_set_instance(_mdns, model_name));
    ESP_ERROR_CHECK(mdns_service_add(_mdns, HAP_SERVICE, HAP_PROTO, port));

    _dd = malloc(sizeof(struct discovery_desc));
    _dd->config_number = config_number;
    _dd->id = strdup(id);
    _dd->model_name = strdup(model_name);
    _dd->category = category;
    _dd->paired = false;
    _service_txt_set(_dd);

    return 0;
}

void discovery_paired(void)
{
    _dd->paired = true;
    _service_txt_set(_dd);
}
