#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "esp_event_loop.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "mdns.h"
#include "Arduino.h"
#include "hap.h"
#include "srp.h"
#include "pairing.h"
#include "nvs.h"
#include "advertise.h"
#include "httpd.h"

#include <WiFi.h>

#define ARRAY_SIZE(array) (sizeof(array) / sizeof(array[0]))

#if 0
#define EXAMPLE_WIFI_SSID "YOUNGHYUN"
#define EXAMPLE_WIFI_PASS "coldplay"
#endif
#if 0
#define EXAMPLE_WIFI_SSID "unibj"
#define EXAMPLE_WIFI_PASS "12673063"
#endif
#if 1
#define EXAMPLE_WIFI_SSID "NO_RUN"
#define EXAMPLE_WIFI_PASS "1qaz2wsx"
#endif

/* FreeRTOS event group to signal when we are connected & ready to make a request */
static EventGroupHandle_t wifi_event_group;

/* The event group allows multiple bits for each event,
   but we only care about one event - are we connected
   to the AP with an IP? */
const int CONNECTED_BIT = BIT0;

/*
struct httpd_restapi restapi[] = {
    {.uri = (char*)"/pair-setup",
     .method = (char*)"POST",
     .ops = pairing_over_ip_setup,
     .post_response = pairing_over_ip_free,
    },
    {.uri = (char*)"/pair-verify",
     .method = (char*)"POST",
     .ops = pairing_over_ip_verify,
     .post_response = pairing_over_ip_free,
    },
};
*/

void WiFiEvent(WiFiEvent_t event)
{
    printf("[WiFi-event] event: %d\n", event);

    if (event == SYSTEM_EVENT_STA_GOT_IP) {
        printf("WiFi connected\n");
//        advertise_accessory_add("hello", "12:34:11:22:33:44", "vendor", 811, 1, HAP_ACCESSORY_CATEGORY_FAN, ADVERTISE_ACCESSORY_STATE_NOT_PAIRED);

        hap_init();

        hap_accessory_callback_t callback;
        hap_accessory_add("Neell", "10:34:11:22:33:44", "053-58-197", "vendor", HAP_ACCESSORY_CATEGORY_FAN, 811, 1, NULL, &callback);
        //httpd_start(661, restapi, ARRAY_SIZE(restapi));
    }
    else if (event == SYSTEM_EVENT_STA_DISCONNECTED) {
        Serial.println("WiFi lost connection");
    }

}

extern void pairing_test(void);
extern "C" void app_main()
{
    ESP_ERROR_CHECK( nvs_flash_init() );

    initArduino();

    WiFi.onEvent(WiFiEvent);
    WiFi.begin(EXAMPLE_WIFI_SSID, EXAMPLE_WIFI_PASS);

    uint8_t mac[6];
    esp_wifi_get_mac(ESP_IF_WIFI_STA, mac);
    char accessory_id[32] = {0,};
    sprintf(accessory_id, "%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    printf("|%s|\n", accessory_id);
    accessory_id[9] = 0x39;

#if 0
    struct pairing_db_ops ops = {
        .get = nvs_get,
        .set = nvs_set,
        .erase = nvs_erase,
    };
#endif



//    pairing_init("053-58-197", accessory_id, &ops);
//
//    pairing_test();
}
