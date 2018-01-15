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
#include "discovery.h"
#include "srp.h"
#include "pairing.h"
#include "httpd.h"

#include <WiFi.h>

#define ARRAY_SIZE(array) (sizeof(array) / sizeof(array[0]))

#define EXAMPLE_WIFI_SSID "YOUNGHYUN"
#define EXAMPLE_WIFI_PASS "coldplay"
//#define EXAMPLE_WIFI_SSID "unibj"
//#define EXAMPLE_WIFI_PASS "12673063"
//#define EXAMPLE_WIFI_SSID "NO_RUN"
//#define EXAMPLE_WIFI_PASS "1qaz2wsx"

/* FreeRTOS event group to signal when we are connected & ready to make a request */
static EventGroupHandle_t wifi_event_group;

/* The event group allows multiple bits for each event,
   but we only care about one event - are we connected
   to the AP with an IP? */
const int CONNECTED_BIT = BIT0;

struct httpd_restapi restapi[] = {
    {.uri = (char*)"/pair-setup",
     .method = (char*)"POST",
     .ops = pairing_over_ip,
     .post_response = pairing_over_ip_free,
    },
};

void WiFiEvent(WiFiEvent_t event)
{
    printf("[WiFi-event] event: %d\n", event);

    if (event == SYSTEM_EVENT_STA_GOT_IP) {
        printf("WiFi connected\n");
        httpd_start(3233, restapi, ARRAY_SIZE(restapi));
    }
    else if (event == SYSTEM_EVENT_STA_DISCONNECTED) {
        Serial.println("WiFi lost connection");
    }

}

extern "C" void app_main()
{
    ESP_ERROR_CHECK( nvs_flash_init() );

    initArduino();

    WiFi.onEvent(WiFiEvent);
    WiFi.begin(EXAMPLE_WIFI_SSID, EXAMPLE_WIFI_PASS);

    uint8_t mac[6];
    esp_wifi_get_mac(ESP_IF_WIFI_STA, mac);
    char accessory_id[38] = {0,};
    sprintf(accessory_id, "%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    accessory_id[8] = 0x3a;
    pairing_init("053-58-197", accessory_id, NULL);
    discovery_init("ESP32", 3233, "AD", 6, HAP_ACCESSORY_CATEGORY_OTHER);
}
