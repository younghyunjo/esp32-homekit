
#ifndef LIGHT_H
#define LIGHT_H

#include <stdbool.h>

extern volatile bool state;
extern volatile int brightness;
extern volatile int hue;
extern volatile int saturation;

void led_init();

void* led_state_read(void* arg);
void led_state_write(void* arg, void* value, int len);
void led_state_notify(void* arg, void* ev_handle, bool enable);

void* led_brightness_read(void* arg);
void led_brightness_write(void* arg, void* value, int len);
void led_brightness_notify(void* arg, void* ev_handle, bool enable);

void* led_hue_read(void* arg);
void led_hue_write(void* arg, void* value, int len);
void led_hue_notify(void* arg, void* ev_handle, bool enable);

void* led_saturation_read(void* arg);
void led_saturation_write(void* arg, void* value, int len);
void led_saturation_notify(void* arg, void* ev_handle, bool enable);

#endif
