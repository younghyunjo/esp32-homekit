# Automatically generated build file. Do not edit.
COMPONENT_INCLUDES += $(PROJECT_PATH)/main/include
COMPONENT_LDFLAGS += -L$(BUILD_DIR_BASE)/main -lmain -L $(PROJECT_PATH)/main -T esp32.bootloader.ld -T esp32.bootloader.rom.ld -T $(IDF_PATH)/components/esp_rom/esp32/ld/esp32.rom.ld -T $(IDF_PATH)/components/esp_rom/esp32/ld/esp32.rom.newlib-funcs.ld -T $(IDF_PATH)/components/esp32/ld/esp32.peripherals.ld
COMPONENT_LINKER_DEPS += $(PROJECT_PATH)/main/esp32.bootloader.ld $(PROJECT_PATH)/main/esp32.bootloader.rom.ld $(IDF_PATH)/components/esp_rom/esp32/ld/esp32.rom.ld $(IDF_PATH)/components/esp_rom/esp32/ld/esp32.rom.newlib-funcs.ld $(IDF_PATH)/components/esp32/ld/esp32.peripherals.ld
COMPONENT_SUBMODULES += 
COMPONENT_LIBRARIES += main
COMPONENT_LDFRAGMENTS += 
component-main-build: 
