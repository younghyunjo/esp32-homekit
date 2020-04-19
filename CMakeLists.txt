cmake_minimum_required(VERSION 3.5)

set(COMPONENT_SRCDIRS "src")

set(COMPONENT_REQUIRES
        nvs_flash
        mdns
        lwip
        json
        wpa_supplicant
        esp32-wolfssl
        )

set(COMPONENT_ADD_INCLUDEDIRS
        "src"
        "include"
        )

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-unused-variable")

register_component()
