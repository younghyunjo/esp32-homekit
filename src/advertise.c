#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include <mdns.h>

#include "advertise.h"

#define HAP_SERVICE "_hap"
#define HAP_PROTO "_tcp"
#define SERVICE_TXT_LEN 4

struct advertiser {
    char* name;
    char* id;
    int port;
    enum hap_accessory_category category;
    enum advertise_accessory_state state;
    uint32_t config_number;
    char service_txt_c_sharp[SERVICE_TXT_LEN];
    char service_txt_sf[SERVICE_TXT_LEN];
    char service_txt_ci[SERVICE_TXT_LEN];
    //mdns_server_t* mdns;
};

static void _service_txt_set(struct advertiser* adv) {
#define ARRAY_SIZE(array) (sizeof(array) / sizeof(array[0]))

    memset(adv->service_txt_c_sharp, 0, sizeof(adv->service_txt_c_sharp));
    sprintf(adv->service_txt_c_sharp, "%d", adv->config_number);
    memset(adv->service_txt_sf, 0, sizeof(adv->service_txt_sf));
    sprintf(adv->service_txt_sf, "%d", adv->state == ADVERTISE_ACCESSORY_STATE_NOT_PAIRED ? 1 : 0);
    memset(adv->service_txt_ci, 0, sizeof(adv->service_txt_ci));
    sprintf(adv->service_txt_ci, "%d", adv->category);

    mdns_txt_item_t hap_service_txt[] = {
        {"c#", adv->service_txt_c_sharp},
        {"ff", "0"},
        {"pv", "1.0"},
        {"id", adv->id},
        {"md", adv->name},
        {"s#", "1"},
        {"sf", adv->service_txt_sf},
        {"ci", adv->service_txt_ci},
    };

#if 0
    const char* hap_service_txt[] = {
        service_txt_c_sharp,
        "ff=0",
        "pv=1.0",
        service_txt_id,
        service_txt_md,
        "s#=1",
        service_txt_sf,
        service_txt_ci
    };
#endif
    mdns_service_txt_set(HAP_SERVICE, HAP_PROTO, hap_service_txt, ARRAY_SIZE(hap_service_txt));
}

void advertise_accessory_state_set(void* adv_instance, enum advertise_accessory_state state) {
    if (adv_instance == NULL) {
        printf("[ERR] Invalid arg\n");
        return;
    }

    struct advertiser* adv = adv_instance;
    if (adv->state == state)
        return;

    adv->state = state;
    _service_txt_set(adv);
}

void* advertise_accessory_add(char* name, char* id, char* host, int port, uint32_t config_number,
                              enum hap_accessory_category category, enum advertise_accessory_state state)
{

    if (name == NULL || id == NULL || host == NULL) {
        printf("[ERR] Invalid arg\n");
        return NULL;
    }
    struct advertiser* adv = calloc(1, sizeof(struct advertiser));
    if (adv == NULL) {
        printf("[ERR] calloc failed\n");
        return NULL;
    }

    adv->name = name;
    adv->id = id;
    adv->port = port;
    adv->config_number = config_number;
    adv->category = category;
    adv->state = state;

    mdns_init();
    mdns_hostname_set(host);
    mdns_instance_name_set(name);
    mdns_service_add(name, HAP_SERVICE, HAP_PROTO, port, NULL, 0);
    _service_txt_set(adv);

    return adv;
}

void advertise_accessory_remove(void* adv_instance) {
    if (adv_instance == NULL)
        return;

    struct advertiser* adv = adv_instance;
    free(adv);
}
