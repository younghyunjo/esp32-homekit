# esp32-homekit

This project is impemented Apple Homekit Accessory Protocol(HAP) to ESP32.\
You can make your own Homekit accessory with ESP32 with this project.




# Demo
[![ESP32 HOMEKIT](https://img.youtube.com/vi/OTBtEQNa-1E/0.jpg)](https://www.youtube.com/watch?v=OTBtEQNa-1E "ESP32 HOMEKIT")

# Resource
- [Apple Homekit Accessory Protocol](https://developer.apple.com/support/homekit-accessory-protocol/)
- [Mongoose](https://github.com/cesanta/mongoose)

# Prerequisite
The `esp32-homekit` is using esp-idf libraries and build.\
Please install ESP-IDF
- ESP-IDF Setup Guide
  * [Windows Setup Guide](https://docs.espressif.com/projects/esp-idf/en/latest/get-started/windows-setup.html)
  * [Mac OS Setup Guide](https://docs.espressif.com/projects/esp-idf/en/latest/get-started/macos-setup.html)
  * [Linux Setup Guide](https://docs.espressif.com/projects/esp-idf/en/latest/get-started/linux-setup.html)

# Download


```
$ git clone  https://github.com/younghyunjo/esp32-homekit.git
$ cd esp32-homekit
$ git submodule update --init --recursive
```

# Configuration
## WiFi
esp32-homekit uses WiFi as tranmission layer.\
To connection WiFi, you MUST config WiFi ssid and password.

1. Open examples/switch/main/main.c
2. Change EXAMPLE_ESP_WIFI_SSID, and EXAMPLE_ESP_WIFI_PASS

```
#define EXAMPLE_ESP_WIFI_SSID "unibj"
#define EXAMPLE_ESP_WIFI_SSID "12345678"  
```

# Build

```
$ cd examples/switch
$ make
$ make flash
```

# Setup Code
While pairing accessory and iOS devices, You must enter Setup Code at HOME App.
The default setupt code is 
## **`053-58-917`**


