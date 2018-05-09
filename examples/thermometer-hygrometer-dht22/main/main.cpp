#include <string.h>
#include "driver/gpio.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "esp_event_loop.h"
#include "esp_log.h"
#include "lwip/err.h"
#include "lwip/sys.h"
#include "nvs_flash.h"

#include "hap.h"

#include "rom/ets_sys.h"
#include "driver/gpio.h"
#include "dht22.h"

#define TAG "SWITCH"

#define ACCESSORY_NAME  "TEMP/HUMI"
#define MANUFACTURER_NAME   "YOUNGHYUN"
#define MODEL_NAME  "ESP32_ACC"
#define ARRAY_SIZE(array) (sizeof(array) / sizeof(array[0]))

#if 1
#define EXAMPLE_ESP_WIFI_SSID "unibj"
#define EXAMPLE_ESP_WIFI_PASS "12673063"
#endif
#if 0
#define EXAMPLE_ESP_WIFI_SSID "NO_RUN"
#define EXAMPLE_ESP_WIFI_PASS "1qaz2wsx"
#endif

/* FIXME */
static gpio_num_t DHT22_GPIO = GPIO_NUM_22;

static EventGroupHandle_t wifi_event_group;
const int WIFI_CONNECTED_BIT = BIT0;

static void* acc;
static SemaphoreHandle_t ev_mutex;
static int temperature = 0;
static int humidity = 0;
static void* _temperature_ev_handle = NULL;
static void* _humidity_ev_handle =  NULL;

void temperature_humidity_monitoring_task(void* arm)
{
    float temperature_float = 0;
    float humidity_float = 0;
    while (1) {
        ESP_LOGI("MAIN", "RAM LEFT %d", esp_get_free_heap_size());
        ESP_LOGI("MAIN", "TASK STACK : %d", uxTaskGetStackHighWaterMark(NULL));

        if (dht22_read(DHT22_GPIO, &temperature_float, &humidity_float) < 0) {
            vTaskDelay( 3000 / portTICK_RATE_MS );
            taskYIELD();
            continue;
        }

        temperature = temperature_float * 100;
        humidity = humidity_float * 100;

        //xSemaphoreTake(ev_mutex, 0);

#if 1
        if (_humidity_ev_handle)
            hap_event_response(acc, _humidity_ev_handle, (void*)humidity);

        if (_temperature_ev_handle)
            hap_event_response(acc, _temperature_ev_handle, (void*)temperature);

#endif
        //xSemaphoreGive(ev_mutex);

        printf("%d %d\n", temperature, humidity);
        vTaskDelay( 3000 / portTICK_RATE_MS );
    }
}

static void* _temperature_read(void* arg)
{
    ESP_LOGI("MAIN", "_temperature_read");
    return (void*)temperature;
}

void _temperature_notify(void* arg, void* ev_handle, bool enable)
{
    ESP_LOGI("MAIN", "_temperature_notify");
    //xSemaphoreTake(ev_mutex, 0);

    if (enable) 
        _temperature_ev_handle = ev_handle;
    else 
        _temperature_ev_handle = NULL;

    //xSemaphoreGive(ev_mutex);
}

static void* _humidity_read(void* arg)
{
    ESP_LOGI("MAIN", "_humidity_read");
    return (void*)humidity;
}

void _humidity_notify(void* arg, void* ev_handle, bool enable)
{
    ESP_LOGI("MAIN", "_humidity_notify");
    //xSemaphoreTake(ev_mutex, 0);

    if (enable) 
        _humidity_ev_handle = ev_handle;
    else 
        _humidity_ev_handle = NULL;

    //xSemaphoreGive(ev_mutex);
}

static bool _identifed = false;
void* identify_read(void* arg)
{
    return (void*)true;
}

void hap_object_init(void* arg)
{
    void* accessory_object = hap_accessory_add(acc);
    struct hap_characteristic cs[] = {
        {HAP_CHARACTER_IDENTIFY, (void*)true, NULL, identify_read, NULL, NULL},
        {HAP_CHARACTER_MANUFACTURER, (void*)MANUFACTURER_NAME, NULL, NULL, NULL, NULL},
        {HAP_CHARACTER_MODEL, (void*)MODEL_NAME, NULL, NULL, NULL, NULL},
        {HAP_CHARACTER_NAME, (void*)ACCESSORY_NAME, NULL, NULL, NULL, NULL},
        {HAP_CHARACTER_SERIAL_NUMBER, (void*)"0123456789", NULL, NULL, NULL, NULL},
        {HAP_CHARACTER_FIRMWARE_REVISION, (void*)"1.0", NULL, NULL, NULL, NULL},
    };
    hap_service_and_characteristics_add(acc, accessory_object, HAP_SERVICE_ACCESSORY_INFORMATION, cs, ARRAY_SIZE(cs));

    struct hap_characteristic humidity_sensor[] = {
        {HAP_CHARACTER_CURRENT_RELATIVE_HUMIDITY, (void*)humidity, NULL, _humidity_read, NULL, _humidity_notify},
        {HAP_CHARACTER_NAME, (void*)"HYGROMETER" , NULL, NULL, NULL, NULL},
    };
    hap_service_and_characteristics_add(acc, accessory_object, HAP_SERVICE_HUMIDITY_SENSOR, humidity_sensor, ARRAY_SIZE(humidity_sensor));

    struct hap_characteristic temperature_sensor[] = {
        {HAP_CHARACTER_CURRENT_TEMPERATURE, (void*)temperature, NULL, _temperature_read, NULL, _temperature_notify},
        {HAP_CHARACTER_NAME, (void*)"THERMOMETER" , NULL, NULL, NULL, NULL},
    };
    hap_service_and_characteristics_add(acc, accessory_object, HAP_SERVICE_TEMPERATURE_SENSOR, temperature_sensor, ARRAY_SIZE(temperature_sensor));

}


static esp_err_t event_handler(void *ctx, system_event_t *event)
{
    switch(event->event_id) {
    case SYSTEM_EVENT_STA_START:
        esp_wifi_connect();
        break;
    case SYSTEM_EVENT_STA_GOT_IP:
        ESP_LOGI(TAG, "got ip:%s",
                 ip4addr_ntoa(&event->event_info.got_ip.ip_info.ip));
        xEventGroupSetBits(wifi_event_group, WIFI_CONNECTED_BIT);
        {
            hap_init();

            uint8_t mac[6];
            esp_wifi_get_mac(ESP_IF_WIFI_STA, mac);
            char accessory_id[32] = {0,};
            sprintf(accessory_id, "%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
            hap_accessory_callback_t callback;
            callback.hap_object_init = hap_object_init;
            acc = hap_accessory_register((char*)ACCESSORY_NAME, accessory_id, (char*)"053-58-197", (char*)MANUFACTURER_NAME, HAP_ACCESSORY_CATEGORY_OTHER, 811, 1, NULL, &callback);
        }
        break;
    case SYSTEM_EVENT_STA_DISCONNECTED:
        esp_wifi_connect();
        xEventGroupClearBits(wifi_event_group, WIFI_CONNECTED_BIT);
        break;
    default:
        break;
    }
    return ESP_OK;
}

void wifi_init_sta()
{
    wifi_event_group = xEventGroupCreate();

    tcpip_adapter_init();
    ESP_ERROR_CHECK(esp_event_loop_init(event_handler, NULL) );

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    wifi_config_t wifi_config;
    memset(&wifi_config, 0, sizeof(wifi_config));
    memcpy(wifi_config.sta.ssid, EXAMPLE_ESP_WIFI_SSID, strlen(EXAMPLE_ESP_WIFI_SSID));
    memcpy(wifi_config.sta.password, EXAMPLE_ESP_WIFI_PASS, strlen(EXAMPLE_ESP_WIFI_PASS));

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA) );
    ESP_ERROR_CHECK(esp_wifi_set_config(ESP_IF_WIFI_STA, &wifi_config) );
    ESP_ERROR_CHECK(esp_wifi_start() );

    ESP_LOGI(TAG, "wifi_init_sta finished.");
    ESP_LOGI(TAG, "connect to ap SSID:%s password:%s",
             EXAMPLE_ESP_WIFI_SSID, EXAMPLE_ESP_WIFI_PASS);
}


extern "C" void app_main()
{
    ESP_ERROR_CHECK(nvs_flash_init());
    vSemaphoreCreateBinary(ev_mutex);

    xTaskCreate( &temperature_humidity_monitoring_task, "dht22", 4096, NULL, 5, NULL );

    wifi_init_sta();
}
