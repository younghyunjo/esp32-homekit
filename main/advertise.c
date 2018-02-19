#include <stdio.h>
#include <stdint.h>

#include <mdns.h>

#include "advertise.h"
#include "hap_types.h"

#define HAP_SERVICE "_hap"
#define HAP_PROTO "_tcp"

struct advertiser {
    char* name;
    char* id;
    int port;
    enum hap_accessory_category category;
    enum advertise_accessory_state state;
    uint32_t config_number;
    mdns_server_t* mdns;
};

static void _service_txt_set(struct advertiser* adv) {
#define ARRAY_SIZE(array) (sizeof(array) / sizeof(array[0]))
#define SERVICE_TXT_LEN 64

    char service_txt_c_sharp[SERVICE_TXT_LEN] = {0,};
    sprintf(service_txt_c_sharp, "c#=%u", adv->config_number);

    char service_txt_id[SERVICE_TXT_LEN] = {0,};
    sprintf(service_txt_id, "id=%s", adv->id);

    char service_txt_md[SERVICE_TXT_LEN] = {0,};
    sprintf(service_txt_md, "md=%s", adv->name);

    char service_txt_ci[SERVICE_TXT_LEN] = {0,};
    sprintf(service_txt_ci, "ci=%d", adv->category);

    char service_txt_sf[SERVICE_TXT_LEN] = {0,};
    sprintf(service_txt_sf, "sf=%d", adv->state == ADVERTISE_ACCESSORY_STATE_NOT_PAIRED ? 1 : 0);

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
    mdns_service_txt_set(adv->mdns, HAP_SERVICE, HAP_PROTO, ARRAY_SIZE(hap_service_txt), hap_service_txt);
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

    mdns_init(TCPIP_ADAPTER_IF_STA, &adv->mdns);
    mdns_set_hostname(adv->mdns, host);
    mdns_set_instance(adv->mdns, name);
    mdns_service_add(adv->mdns, HAP_SERVICE, HAP_PROTO, port);
    _service_txt_set(adv);

    return 0;
}

void advertise_accessory_remove(void* adv_instance) {
    if (adv_instance == NULL)
        return;

    struct advertiser* adv = adv_instance;
    mdns_free(adv->mdns);
    free(adv);
}
