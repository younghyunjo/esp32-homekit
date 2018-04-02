#include <string.h>
#include "driver/gpio.h"
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
#if 1
#define EXAMPLE_WIFI_SSID "unibj"
#define EXAMPLE_WIFI_PASS "12673063"
#endif
#if 0
#define EXAMPLE_WIFI_SSID "NO_RUN"
#define EXAMPLE_WIFI_PASS "1qaz2wsx"
#endif

static gpio_num_t LED_PORT = GPIO_NUM_2;

/* FreeRTOS event group to signal when we are connected & ready to make a request */
static EventGroupHandle_t wifi_event_group;

/* The event group allows multiple bits for each event,
   but we only care about one event - are we connected
   to the AP with an IP? */
const int CONNECTED_BIT = BIT0;
static void* a;
static void* _ev_handle;
static int led = false;

void* led_read(void* arg)
{
    printf("[MAIN] LED READ\n");
    return (void*)led;
}

void led_write(void* arg, void* value, int len)
{
    printf("[MAIN] LED WRITE. %d\n", (int)value);

    led = (int)value;
    if (value) {
        led = true;
        gpio_set_level(LED_PORT, 1);
    }
    else {
        led = false;
        gpio_set_level(LED_PORT, 0);
    }

    if (_ev_handle)
        hap_event_response(a, _ev_handle, (void*)led);

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

static bool _identifed = false;
void* identify_read(void* arg)
{
    return (void*)true;
}

void hap_object_init(void* arg)
{
    void* accessory_object = hap_accessory_add(a);
    struct hap_characteristic cs[] = {
        {HAP_CHARACTER_IDENTIFY, (void*)true, NULL, identify_read, NULL, NULL},
        {HAP_CHARACTER_MANUFACTURER, (void*)"Hack", NULL, NULL, NULL, NULL},
        {HAP_CHARACTER_MODEL, (void*)"A1234", NULL, NULL, NULL, NULL},
        {HAP_CHARACTER_NAME, (void*)"Neell", NULL, NULL, NULL, NULL},
        {HAP_CHARACTER_SERIAL_NUMBER, (void*)"0123", NULL, NULL, NULL, NULL},
        {HAP_CHARACTER_FIRMWARE_REVISION, (void*)"1.0", NULL, NULL, NULL, NULL},
    };

    hap_service_and_characteristics_add(a, accessory_object, HAP_SERVICE_ACCESSORY_INFORMATION, cs, 6);

#if 1
    struct hap_characteristic cc[] = {
        {HAP_CHARACTER_ON, (void*)led, NULL, led_read, led_write, led_notify},
        //{HAP_CHARACTER_CONTACT_SENSOR_STATE, 0, NULL, led_read, NULL, led_notify},
    };

    //hap_service_and_characteristics_add(a, accessory_object, HAP_SERVICE_CONTACT_SENSOR, cc, 1);
    hap_service_and_characteristics_add(a, accessory_object, HAP_SERVICE_SWITCHS, cc, 1);
#endif
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
        a = hap_accessory_register((char*)"Neell", accessory_id, (char*)"053-58-197", (char*)"Hack", HAP_ACCESSORY_CATEGORY_OTHER, 811, 1, NULL, &callback);
    }
    else if (event == SYSTEM_EVENT_STA_DISCONNECTED) {
        Serial.println("WiFi lost connection");
    }
}

extern "C" void app_main()
{
    ESP_ERROR_CHECK( nvs_flash_init() );

    initArduino();

    gpio_pad_select_gpio(LED_PORT);
    gpio_set_direction(LED_PORT, GPIO_MODE_OUTPUT);

    WiFi.onEvent(WiFiEvent);
    WiFi.begin(EXAMPLE_WIFI_SSID, EXAMPLE_WIFI_PASS);
}
