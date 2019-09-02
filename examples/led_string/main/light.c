
#include "light.h"

#include <math.h>

#include "driver/gpio.h"
#include "driver/rmt.h"

#include "hap.h"
#include "digital_led/esp32_digital_led_lib.h"

static gpio_num_t LED_PORT = GPIO_NUM_25;

#define LED_STRIP_LENGTH (32 * 8 * 1)
#define LED_STRIP_RMT_INTR_NUM 19U
#define LED_RGB_SCALE 255 

static void hsi2rgb(float h, float s, float i, pixelColor_t* rgb);

#define NUM_STRANDS 1

strand_t STRANDS[NUM_STRANDS] = { // Avoid using any of the strapping pins on the ESP32
  { .rmtChannel = RMT_CHANNEL_1, .gpioNum = GPIO_NUM_15, .ledType = LED_WS2812B_V3, .brightLimit = 32, .numPixels =  LED_STRIP_LENGTH, .pixels = NULL, ._stateVars = NULL },
};

extern void* a;

// LED state variables
volatile bool state;
volatile int brightness = 0;
volatile int hue = 0;
volatile int saturation = 0;

// LED notifier handles
void* _state_handle;
void* _brightness_handle;
void* _hue_handle;
void* _saturation_handle;

void led_update() {
    strand_t * strands [NUM_STRANDS];
    for (int i = 0; i < NUM_STRANDS; i++) {
        strands[i] = &STRANDS[i];
    }

    // Disable if state is off
    if (state == false) {
        digitalLeds_resetPixels(strands, NUM_STRANDS);
        return;
    }

    // Calculate RGB value
    pixelColor_t rgb;
    hsi2rgb((float)hue, (float)saturation, (float)brightness, &rgb);

    printf("H: %d S: %d I: %d\n", hue, saturation, brightness);
    printf("R: %d G: %d B: %d\n", rgb.r, rgb.g, rgb.b);

    // Write pixel values
    for (int i = 0; i < NUM_STRANDS; i++) {
        for (int p=0; p<LED_STRIP_LENGTH; p++) {
            strands[i]->pixels[p] = rgb;
        }     
    }

    // Display output
    digitalLeds_drawPixels(strands, NUM_STRANDS);
}

void led_init() {
    state = false;

    printf("[LED] initialising\n");

    digitalLeds_initDriver();

    for (int i = 0; i < NUM_STRANDS; i++) {
        gpioSetup(STRANDS[i].gpioNum, GPIO_MODE_OUTPUT, 0);
    }

    strand_t *strands [NUM_STRANDS];
    for (int i = 0; i < NUM_STRANDS; i++) {
        strands[i] = &STRANDS[i];
    }

    if (digitalLeds_addStrands(strands, NUM_STRANDS) == true) {
        printf("[LED] init failed\n");
        return;
    }
    
    printf("[LED] init success\n");

    led_update();
}

void* led_state_read(void* arg)
{
    printf("[MAIN] LED READ\n");
    return (void*)state;
}

void led_state_write(void* arg, void* value, int len)
{
    printf("[MAIN] LED WRITE. %d\n", (int)value);

    if (value != 0) {
        state = true;
        gpio_set_level(LED_PORT, 1);
    }
    else {
        state = false;
        gpio_set_level(LED_PORT, 0);
    }

    led_update();

    if (_state_handle)
        hap_event_response(a, _state_handle, (void*)state);

    return;
}

void led_state_notify(void* arg, void* state_handle, bool enable)
{
    if (enable) {
        _state_handle = state_handle;
    }
    else {
        _state_handle = NULL;
    }
}


void* led_brightness_read(void* arg) {
    printf("[MAIN] LED BRIGHTNESS READ\n");
    return (void*)brightness;
}

void led_brightness_write(void* arg, void* value, int len) {
    printf("[MAIN] LED BRIGHTNESS WRITE. %d\n", (int)value);

    brightness = (int)value;

    led_update();

    if (_brightness_handle)
        hap_event_response(a, _brightness_handle, (void*)brightness);
}

void led_brightness_notify(void* arg, void* brightness_handle, bool enable) {
    if (enable) {
        _brightness_handle = brightness_handle;
    }
    else {
        _brightness_handle = NULL;
    }
}

void* led_saturation_read(void* arg) {
    printf("[MAIN] LED SATURATION READ\n");
    return (void*)saturation;
}

void led_saturation_write(void* arg, void* value, int len) {
    printf("[MAIN] LED SATURATION WRITE. %d\n", (int)value);

    saturation = (int)value;

    led_update();

    if (_saturation_handle)
        hap_event_response(a, _saturation_handle, (void*)saturation);
}

void led_saturation_notify(void* arg, void* saturation_handle, bool enable) {
    if (enable) {
        _saturation_handle = saturation_handle;
    }
    else {
        _saturation_handle = NULL;
    }
}

void* led_hue_read(void* arg) {
    printf("[MAIN] LED HUE READ\n");
    return (void*)hue;
}

void led_hue_write(void* arg, void* value, int len) {
    printf("[MAIN] LED HUE WRITE. %d\n", (int)value);

    hue = (int)value;

    led_update();

    if (_hue_handle)
        hap_event_response(a, _hue_handle, (void*)hue);
}

void led_hue_notify(void* arg, void* hue_handle, bool enable) {
    if (enable) {
        _hue_handle = hue_handle;
    }
    else {
        _hue_handle = NULL;
    }
}



//http://blog.saikoled.com/post/44677718712/how-to-convert-from-hsi-to-rgb-white
static void hsi2rgb(float h, float s, float i, pixelColor_t* rgb) {
    int r, g, b;

    //h = h * 360 / 255;                  // convert to degrees
    //s = s * 100 / 255;
    //i = i * 100 / 255;

    i = i / 2;

    while (h < 0) { h += 360.0F; };     // cycle h around to 0-360 degrees
    while (h >= 360) { h -= 360.0F; };
    h = 3.14159F * h / 180.0F;          // convert to radians.
    s /= 100.0F;                        // from percentage to ratio
    i /= 100.0F;                        // from percentage to ratio
    s = s > 0 ? (s < 1 ? s : 1) : 0;    // clamp s and i to interval [0,1]
    i = i > 0 ? (i < 1 ? i : 1) : 0;    // clamp s and i to interval [0,1]
    i = i * sqrt(i);                    // shape intensity to have finer granularity near 0

    if (h < 2.09439) {
        r = LED_RGB_SCALE * i / 3 * (1 + s * cos(h) / cos(1.047196667 - h));
        g = LED_RGB_SCALE * i / 3 * (1 + s * (1 - cos(h) / cos(1.047196667 - h)));
        b = LED_RGB_SCALE * i / 3 * (1 - s);
    }
    else if (h < 4.188787) {
        h = h - 2.09439;
        g = LED_RGB_SCALE * i / 3 * (1 + s * cos(h) / cos(1.047196667 - h));
        b = LED_RGB_SCALE * i / 3 * (1 + s * (1 - cos(h) / cos(1.047196667 - h)));
        r = LED_RGB_SCALE * i / 3 * (1 - s);
    }
    else {
        h = h - 4.188787;
        b = LED_RGB_SCALE * i / 3 * (1 + s * cos(h) / cos(1.047196667 - h));
        r = LED_RGB_SCALE * i / 3 * (1 + s * (1 - cos(h) / cos(1.047196667 - h)));
        g = LED_RGB_SCALE * i / 3 * (1 - s);
    }

    rgb->r = (uint8_t) r;
    rgb->g = (uint8_t) g;
    rgb->b = (uint8_t) b;
}
