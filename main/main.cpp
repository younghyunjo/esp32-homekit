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
static void* a;
static void* _ev_handle;
static int led = 0;

void* led_read(void* arg)
{
    printf("LED\n");
    if (led)
        return (void*)true;
    else
        return (void*)false;
}

void led_write(void* arg, void* value, int len)
{
    printf("LED WRITE. %d\n", (int)value);

    led = (int)value;
    if (value) {
        led = true;
        //TODO TURN ON LED
    }
    else {
        led = false;
        //TODO TURN OFF LED
    }

    /*
    if (_ev_handle)
        hap_notification_response(a, ev_handle, (void*)led);
    */

    return;
}

void led_notify(void* arg, void* ev_handle, bool enable)
{
    if (enable) {
        _ev_handle = ev_handle;
    }
    else {
        _ev_handle = NULL;
    }
}

void hap_object_init(void* arg)
{
    void* attr_a = hap_attr_accessory_add(a);
    struct hap_characteristic cs[] = {
        {HAP_CHARACTER_IDENTIFY, (void*)true, NULL, NULL, NULL, NULL},
        {HAP_CHARACTER_MANUFACTURER, (void*)"Hack", NULL, NULL, NULL, NULL},
        {HAP_CHARACTER_MODEL, (void*)"A1234", NULL, NULL, NULL, NULL},
        {HAP_CHARACTER_NAME, (void*)"Neell", NULL, NULL, NULL, NULL},
        {HAP_CHARACTER_SERIAL_NUMBER, (void*)"0123", NULL, NULL, NULL, NULL},
        {HAP_CHARACTER_FIRMWARE_REVISION, (void*)"100.1.1", NULL, NULL, NULL, NULL},
    };

    hap_attr_service_and_characteristics_add(a, attr_a, HAP_SERVICE_ACCESSORY_INFORMATION, cs, 5);

    struct hap_characteristic cc[] = {
        {HAP_CHARACTER_NAME, (void*)"led", NULL, NULL, NULL, NULL},
        {HAP_CHARACTER_ON, (void*)1, NULL, led_read, led_write, led_notify},
    };

    hap_attr_service_and_characteristics_add(a, attr_a, HAP_SERVICE_SWITCHS, cc, 2);
}

void WiFiEvent(WiFiEvent_t event)
{
    printf("[WiFi-event] event: %d\n", event);

    if (event == SYSTEM_EVENT_STA_GOT_IP) {
        printf("WiFi connected\n");

        hap_init();

        uint8_t mac[6];
        esp_wifi_get_mac(ESP_IF_WIFI_STA, mac);
        char accessory_id[32] = {0,};
        sprintf(accessory_id, "%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        hap_accessory_callback_t callback;
        callback.hap_object_init = hap_object_init;
        a = hap_accessory_register("Neell", accessory_id, "053-58-197", "Hack", HAP_ACCESSORY_CATEGORY_OTHER, 811, 2, NULL, &callback);
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
}
