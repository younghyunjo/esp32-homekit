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
#include "httpd.h"
#include "hap_srp.h"
#include "pairing.h"

#include <WiFi.h>

#define ARRAY_SIZE(array) (sizeof(array) / sizeof(array[0]))

//#define EXAMPLE_WIFI_SSID "YOUNGHYUN1"
//#define EXAMPLE_WIFI_PASS "coldplay"
//#define EXAMPLE_WIFI_SSID "unibj"
//#define EXAMPLE_WIFI_PASS "12673063"
#define EXAMPLE_WIFI_SSID "NO_RUN"
#define EXAMPLE_WIFI_PASS "1qaz2wsx"

/* FreeRTOS event group to signal when we are connected & ready to make a request */
static EventGroupHandle_t wifi_event_group;

/* The event group allows multiple bits for each event,
   but we only care about one event - are we connected
   to the AP with an IP? */
const int CONNECTED_BIT = BIT0;

struct httpd_restapi restapi[] {
    {.uri = "/pair-setup",
     .method = "POST",
     .ops = pairing_setup,
     .post_response = pairing_setup_free,
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

    hsrp_init("053-58-197");
    discovery_init("ESP32", 3233, "A", 1, HAP_ACCESSORY_CATEGORY_SENSOR);
}
