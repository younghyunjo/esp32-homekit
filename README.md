# esp32-homekit

# Demo
[![ESP32 HOMEKIT](https://img.youtube.com/vi/OTBtEQNa-1E/0.jpg)](https://www.youtube.com/watch?v=OTBtEQNa-1E "ESP32 HOMEKIT")

# Build
- Before build the project, YOU MUST INSTALL ESP_IDF
  - https://github.com/espressif/esp-idf
  
```
$ git clone  https://github.com/younghyunjo/esp32-homekit.git
$ cd esp32-homekit
$ git submodule update --init --recursive
$ cd examples/switch
$ make
$ make flash
```

# WiFi Setting
1. Open examples/switch/main/main.c
2. Change EXAMPLE_ESP_WIFI_SSID, and EXAMPLE_ESP_WIFI_PASS
```
#define EXAMPLE_ESP_WIFI_SSID "unibj"  
#define EXAMPLE_ESP_WIFI_PASS "12345678"  
```

# Setup Code
"053-58-197"
