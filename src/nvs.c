#include <esp_log.h>
#include <stdio.h>

#include "nvs_flash.h"
#include "nvs.h"

#define TAG "nvs"
#define STORAGE_NAMESPACE "storage"

static int _value_length_get(nvs_handle handle, char* key) {
    size_t value_length = 0;
    esp_err_t err = nvs_get_blob (handle, key, NULL, &value_length);
    if (err != ESP_OK && err != ESP_ERR_NVS_NOT_FOUND) {
        ESP_LOGE(TAG, "nvs_get_blob failed. err:%d\n", err);
        nvs_close(handle);
        return 0;
    }

    return (int)value_length;
}

int nvs_get(char* key, uint8_t* value, int len)
{
    if (!key || !value || len == 0) {
        ESP_LOGE(TAG, "Invalid arguments\n");
        return -1;
    }

    nvs_handle handle;
    esp_err_t err = nvs_open(STORAGE_NAMESPACE, NVS_READWRITE, &handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nvs_open failed. namespace:%s err:%d\n", 
                STORAGE_NAMESPACE, err);
        return 0;
    }

    int value_length = _value_length_get(handle, key);
    if (value_length == 0) {
        ESP_LOGE(TAG, "nothing saved. key:%s\n", key);
        nvs_close(handle);
        return 0;
    }

    if (value_length > len) {
        ESP_LOGE(TAG, "value buffer is short\n");
        nvs_close(handle);
        return len - value_length;
    }

    err = nvs_get_blob(handle, key, value, (size_t*)&value_length);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nvs_get_blob failed. key:%s err:%d\n", key, err);
        nvs_close(handle);
        return 0;
    }

    nvs_close(handle);
    return value_length;
}

int nvs_set(char* key, uint8_t* value, int len)
{
    nvs_handle handle;
    esp_err_t err = nvs_open(STORAGE_NAMESPACE, NVS_READWRITE, &handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nvs_open failed. err:%d\n", err);
        return -1;
    }

    err = nvs_set_blob(handle, key, value, len);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nvs_set_blob failed. key:%s err:%d\n", key, err);
        nvs_close(handle);
        return -1;
    }

    err = nvs_commit(handle);
    if (err != ESP_OK)  {
        ESP_LOGE(TAG, "nvs_commit failed. err:%d\n", err);
        nvs_close(handle);
        return -1;
    }

    nvs_close(handle);
    return 0;
}

int nvs_erase(char* key)
{
    nvs_handle handle;
    esp_err_t err = nvs_open(STORAGE_NAMESPACE, NVS_READWRITE, &handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nvs_open failed. err:%d\n", err);
        return -1;
    }

    err = nvs_erase_key(handle, key);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nvs_erase_key failed. key:%s err:%d\n", key, err);
        nvs_close(handle);
        return -1;
    }

    err = nvs_commit(handle);
    if (err != ESP_OK)  {
        ESP_LOGE(TAG, "nvs_commit failed. err:%d\n", err);
        nvs_close(handle);
        return -1;
    }

    nvs_close(handle);
    return 0;
}

