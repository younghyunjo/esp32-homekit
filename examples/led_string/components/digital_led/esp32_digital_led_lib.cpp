/* 
 * Library for driving digital RGB(W) LEDs using the ESP32's RMT peripheral
 *
 * Modifications Copyright (c) 2017-2019 Martin F. Falatic
 * 
 * Portions modified using FastLED's ClocklessController as a reference
 *   Copyright (c) 2018 Samuel Z. Guyer
 *   Copyright (c) 2017 Thomas Basler
 *
 * Based on public domain code created 19 Nov 2016 by Chris Osborn <fozztexx@fozztexx.com>
 * http://insentricity.com
 *
 */

/* 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "esp32_digital_led_lib.h"


#ifdef __cplusplus
extern "C" {
#endif

#if defined(ARDUINO)
  #include "esp32-hal.h"
  #include "esp_intr.h"
  #include "driver/gpio.h"
  #include "driver/rmt.h"
  #include "driver/periph_ctrl.h"
  #include "freertos/semphr.h"
  #include "soc/rmt_struct.h"
#elif defined(ESP_PLATFORM)
  #include <esp_intr.h>
  #include <driver/gpio.h>
  #include <driver/rmt.h>
  #include <freertos/FreeRTOS.h>
  #include <freertos/semphr.h>
  #include <soc/dport_reg.h>
  #include <soc/gpio_sig_map.h>
  #include <soc/rmt_struct.h>
  #include <stdio.h>
  #include <string.h>  // memset, memcpy, etc. live here!
#endif

#ifdef __cplusplus
}
#endif

#define COUNT_OF(x) ((sizeof(x)/sizeof(0[x])) / ((size_t)(!(sizeof(x) % sizeof(0[x])))))

#if DEBUG_ESP32_DIGITAL_LED_LIB
extern char * digitalLeds_debugBuffer;
extern int digitalLeds_debugBufferSz;
#endif

static DRAM_ATTR const uint16_t MAX_PULSES = 32;  // A channel has a 64 "pulse" buffer - we use half per pass
static DRAM_ATTR const uint16_t DIVIDER    =  4;  // 8 still seems to work, but timings become marginal
static DRAM_ATTR const double   RMT_DURATION_NS = 12.5;  // Minimum time of a single RMT duration based on clock ns


// Considering the RMT_INT_RAW_REG (raw int status) and RMT_INT_ST_REG (masked int status) registers (each 32-bit):
//   Where op = {raw, st, ena, clr} and n = {0..7}
//   Every three bits = RMT.int_<op>.ch<n>_tx_end, RMT.int_<op>.ch<n>_rx_end, RMT.int_<op>.ch<n>_err
//   The final 8 bits are RMT.int_<op>.ch<n>_tx_thr_event

// LUT for mapping bits in RMT.int_<op>.ch<n>_tx_thr_event
static DRAM_ATTR const uint32_t tx_thr_event_offsets [] = {
  static_cast<uint32_t>(1) << (24 + 0),
  static_cast<uint32_t>(1) << (24 + 1),
  static_cast<uint32_t>(1) << (24 + 2),
  static_cast<uint32_t>(1) << (24 + 3),
  static_cast<uint32_t>(1) << (24 + 4),
  static_cast<uint32_t>(1) << (24 + 5),
  static_cast<uint32_t>(1) << (24 + 6),
  static_cast<uint32_t>(1) << (24 + 7),
};

// LUT for mapping bits in RMT.int_<op>.ch<n>_tx_end
static DRAM_ATTR const uint32_t tx_end_offsets [] = {
  static_cast<uint32_t>(1) << (0 + 0) * 3,
  static_cast<uint32_t>(1) << (0 + 1) * 3,
  static_cast<uint32_t>(1) << (0 + 2) * 3,
  static_cast<uint32_t>(1) << (0 + 3) * 3,
  static_cast<uint32_t>(1) << (0 + 4) * 3,
  static_cast<uint32_t>(1) << (0 + 5) * 3,
  static_cast<uint32_t>(1) << (0 + 6) * 3,
  static_cast<uint32_t>(1) << (0 + 7) * 3,
};

typedef union {
  struct {
    uint32_t duration0:15;
    uint32_t level0:1;
    uint32_t duration1:15;
    uint32_t level1:1;
  };
  uint32_t val;
} rmtPulsePair;

typedef struct {
  uint8_t * buf_data;
  uint16_t buf_pos, buf_len, buf_half, buf_isDirty;
  rmtPulsePair pulsePairMap[2];
  bool isProcessing;
} digitalLeds_stateData;

double randDouble()
{
  return double(esp_random()>>16) / (UINT16_MAX + 1);
}

pixelColor_t adjustByUniformFactor(pixelColor_t * color, double adjFactor) {
  color->r = uint8_t(color->r * (1.0 - adjFactor));
  color->g = uint8_t(color->g * (1.0 - adjFactor));
  color->b = uint8_t(color->b * (1.0 - adjFactor));
  color->w = uint8_t(color->w * (1.0 - adjFactor));
  return *color;
}


const static int MAX_RMT_CHANNELS = 8;
static strand_t * strandDataPtrs[MAX_RMT_CHANNELS] = {nullptr};  // Indexed by RMT channel

// Forward declarations of local functions
static void copyHalfBlockToRmt(strand_t * pStrand);
static void rmtInterruptHandler(void *arg);


static xSemaphoreHandle gRmtSem = nullptr;
static intr_handle_t gRmtIntrHandle = nullptr;

static int gToProcess = 0;


#if defined(ARDUINO) && ARDUINO >= 100
  void espPinMode(int pinNum, int pinDir) {
    // Enable GPIO32 or 33 as output. Device-dependent
    // (only works if these aren't used for external XTAL).
    // https://esp32.com/viewtopic.php?t=9151#p38282
    if (pinNum == 32 || pinNum == 33) {
      uint64_t gpioBitMask = (pinNum == 32) ? 1ULL<<GPIO_NUM_32 : 1ULL<<GPIO_NUM_33;
      gpio_mode_t gpioMode = (pinDir == OUTPUT) ? GPIO_MODE_OUTPUT : GPIO_MODE_INPUT;
      gpio_config_t io_conf;
      io_conf.intr_type = GPIO_INTR_DISABLE;
      io_conf.mode = gpioMode;
      io_conf.pin_bit_mask = gpioBitMask;
      io_conf.pull_down_en = GPIO_PULLDOWN_DISABLE;
      io_conf.pull_up_en = GPIO_PULLUP_DISABLE;
      gpio_config(&io_conf);
    }
    else {
      pinMode(pinNum, pinDir);
    }
  }
#endif


void gpioSetup(int gpioNum, int gpioMode, int gpioVal) {
  #if defined(ARDUINO) && ARDUINO >= 100
    espPinMode(gpioNum, gpioMode);
    digitalWrite (gpioNum, gpioVal);
  #elif defined(ESP_PLATFORM)
    gpio_num_t gpioNumNative = static_cast<gpio_num_t>(gpioNum);
    gpio_mode_t gpioModeNative = static_cast<gpio_mode_t>(gpioMode);
    gpio_pad_select_gpio(gpioNumNative);
    gpio_set_direction(gpioNumNative, gpioModeNative);
    gpio_set_level(gpioNumNative, gpioVal);
  #endif
}


int digitalLeds_initDriver()
{
  #if DEBUG_ESP32_DIGITAL_LED_LIB
    snprintf(digitalLeds_debugBuffer, digitalLeds_debugBufferSz, "digitalLeds_initDriver\n");
  #endif

  esp_err_t rc = ESP_OK;

  if (gRmtIntrHandle == nullptr) {  // Only on first run
    // Sem is created here
    gRmtSem = xSemaphoreCreateBinary();
    xSemaphoreGive(gRmtSem);
    rc = esp_intr_alloc(ETS_RMT_INTR_SOURCE, 0, rmtInterruptHandler, nullptr, &gRmtIntrHandle);
  }

  return rc;  
}


int digitalLeds_addStrands(strand_t * strands [], int numStrands)
{
  for (int i = 0; i < numStrands; i++) {
    int rmtChannel = strands[i]->rmtChannel;
    strand_t * pStrand = strands[i];
    strandDataPtrs[rmtChannel] = pStrand;

    ledParams_t ledParams = ledParamsAll[pStrand->ledType];

    pStrand->pixels = static_cast<pixelColor_t*>(malloc(pStrand->numPixels * sizeof(pixelColor_t)));
    if (pStrand->pixels == nullptr) {
      return -1;
    }

    pStrand->_stateVars = static_cast<digitalLeds_stateData*>(malloc(sizeof(digitalLeds_stateData)));
    if (pStrand->_stateVars == nullptr) {
      return -2;
    }
    digitalLeds_stateData * pState = static_cast<digitalLeds_stateData*>(pStrand->_stateVars);

    pState->buf_len = (pStrand->numPixels * ledParams.bytesPerPixel);
    pState->buf_data = static_cast<uint8_t*>(malloc(pState->buf_len));
    if (pState->buf_data == nullptr) {
      return -3;
    }

    // RMT configuration for transmission
    rmt_config_t rmt_tx;
    rmt_tx.channel = static_cast<rmt_channel_t>(rmtChannel);
    rmt_tx.gpio_num = static_cast<gpio_num_t>(pStrand->gpioNum);
    rmt_tx.rmt_mode = RMT_MODE_TX;
    rmt_tx.mem_block_num = 1;
    rmt_tx.clk_div = DIVIDER;
    rmt_tx.tx_config.loop_en = false;
    rmt_tx.tx_config.carrier_level = RMT_CARRIER_LEVEL_LOW;
    rmt_tx.tx_config.carrier_en = false;
    rmt_tx.tx_config.idle_level = RMT_IDLE_LEVEL_LOW;
    rmt_tx.tx_config.idle_output_en = true;
    rmt_config(&rmt_tx);

    // RMT config for transmitting a '0' bit val to this LED strand
    pState->pulsePairMap[0].level0 = 1;
    pState->pulsePairMap[0].level1 = 0;
    pState->pulsePairMap[0].duration0 = ledParams.T0H / (RMT_DURATION_NS * DIVIDER);
    pState->pulsePairMap[0].duration1 = ledParams.T0L / (RMT_DURATION_NS * DIVIDER);

    // RMT config for transmitting a '0' bit val to this LED strand
    pState->pulsePairMap[1].level0 = 1;
    pState->pulsePairMap[1].level1 = 0;
    pState->pulsePairMap[1].duration0 = ledParams.T1H / (RMT_DURATION_NS * DIVIDER);
    pState->pulsePairMap[1].duration1 = ledParams.T1L / (RMT_DURATION_NS * DIVIDER);

    pState->isProcessing = false;

    // Set interrupts
    rmt_set_tx_thr_intr_en(static_cast<rmt_channel_t>(rmtChannel), true, MAX_PULSES);  // sets rmt_set_tx_wrap_en and RMT.tx_lim_ch<n>.limit
  }

  digitalLeds_resetPixels(strands, numStrands);

  return 0;
}


int digitalLeds_removeStrands(strand_t * strands [], int numStrands)
{
  digitalLeds_resetPixels(strands, numStrands);

  for (int i = 0; i < numStrands; i++) {
    int rmtChannel = strands[i]->rmtChannel;
    strand_t * pStrand = strandDataPtrs[rmtChannel];
    if (pStrand) {
      strandDataPtrs[rmtChannel] = nullptr;
    }
  }

  return 0;
}


int digitalLeds_resetPixels(strand_t * strands [], int numStrands)
{
  // TODO: The input is strands for convenience - the point is to get indicies of strands to draw
  // Could just pass the channel numbers, but would it be slower to construct that list?

  for (int i = 0; i < numStrands; i++) {
    int rmtChannel = strands[i]->rmtChannel;
    strand_t * pStrand = strandDataPtrs[rmtChannel];
    memset(pStrand->pixels, 0, pStrand->numPixels * sizeof(pixelColor_t));
  }

  digitalLeds_drawPixels(strands, numStrands);

  return 0;
}


int IRAM_ATTR digitalLeds_drawPixels(strand_t * strands [], int numStrands)
{
  // TODO: The input is strands for convenience - the point is to get indicies of strands to draw
  // Could just pass the channel numbers, but would it be slower to construct that list?

  if (numStrands == 0) {
    return 0;
  }

  gToProcess = numStrands;

  xSemaphoreTake(gRmtSem, portMAX_DELAY);

  for (int i = 0; i < numStrands; i++) {
    int rmtChannel = strands[i]->rmtChannel;
    strand_t * pStrand = strandDataPtrs[rmtChannel];

    digitalLeds_stateData * pState = static_cast<digitalLeds_stateData*>(pStrand->_stateVars);
    ledParams_t ledParams = ledParamsAll[pStrand->ledType];

    pState->isProcessing = true;

    // Pack pixels into transmission buffer
    if (ledParams.bytesPerPixel == 3) {
      for (uint16_t i = 0; i < pStrand->numPixels; i++) {
        // Color order is translated from RGB to GRB
        pState->buf_data[0 + i * 3] = pStrand->pixels[i].g;
        pState->buf_data[1 + i * 3] = pStrand->pixels[i].r;
        pState->buf_data[2 + i * 3] = pStrand->pixels[i].b;
      }
    }
    else if (ledParams.bytesPerPixel == 4) {
      for (uint16_t i = 0; i < pStrand->numPixels; i++) {
        // Color order is translated from RGBW to GRBW
        pState->buf_data[0 + i * 4] = pStrand->pixels[i].g;
        pState->buf_data[1 + i * 4] = pStrand->pixels[i].r;
        pState->buf_data[2 + i * 4] = pStrand->pixels[i].b;
        pState->buf_data[3 + i * 4] = pStrand->pixels[i].w;
      }    
    }
    else {
      return -1;
    }
  
    pState->buf_pos = 0;
    pState->buf_half = 0;
  
    rmt_set_tx_intr_en(static_cast<rmt_channel_t>(rmtChannel), true);

    copyHalfBlockToRmt(pStrand);  
    if (pState->buf_pos < pState->buf_len) {  // Fill the other half of the buffer block
      copyHalfBlockToRmt(pStrand);
    }

    // Starts RMT, which will end up giving us the semaphore back
    // Immediately starts transmitting
    rmt_set_tx_intr_en(static_cast<rmt_channel_t>(rmtChannel), true);
    rmt_tx_start(static_cast<rmt_channel_t>(rmtChannel), true);
  }

  // Give back semaphore after drawing is done
  xSemaphoreTake(gRmtSem, portMAX_DELAY);
  xSemaphoreGive(gRmtSem);

  return 0;
}


static IRAM_ATTR void copyHalfBlockToRmt(strand_t * pStrand)
{
  // This fills half an RMT block
  // When wraparound is happening, we want to keep the inactive half of the RMT block filled
  digitalLeds_stateData * pState = static_cast<digitalLeds_stateData*>(pStrand->_stateVars);
  ledParams_t ledParams = ledParamsAll[pStrand->ledType];

  uint16_t i, j, offset, len, byteval;

  offset = pState->buf_half * MAX_PULSES;
  pState->buf_half = !pState->buf_half;

  len = pState->buf_len - pState->buf_pos;
  if (len > (MAX_PULSES / 8))
    len = (MAX_PULSES / 8);

  if (!len) {
    if (!pState->buf_isDirty) {
      return;
    }
    // Clear the channel's data block and return
    for (i = 0; i < MAX_PULSES; i++) {
      RMTMEM.chan[pStrand->rmtChannel].data32[i + offset].val = 0;
    }
    pState->buf_isDirty = 0;
    return;
  }
  pState->buf_isDirty = 1;

  for (i = 0; i < len; i++) {
    byteval = pState->buf_data[i + pState->buf_pos];

    // Shift bits out, MSB first, setting RMTMEM.chan[n].data32[x] to
    // the rmtPulsePair value corresponding to the buffered bit value
    for (j = 0; j < 8; j++, byteval <<= 1) {
      int bitval = (byteval >> 7) & 0x01;
      int data32_idx = i * 8 + offset + j;
      RMTMEM.chan[pStrand->rmtChannel].data32[data32_idx].val = pState->pulsePairMap[bitval].val;
    }

    // Handle the reset bit by stretching duration1 for the final bit in the stream
    if (i + pState->buf_pos == pState->buf_len - 1) {
      RMTMEM.chan[pStrand->rmtChannel].data32[i * 8 + offset + 7].duration1 =
        ledParams.TRS / (RMT_DURATION_NS * DIVIDER);
    }
  }

  // Clear the remainder of the channel's data not set above
  for (i *= 8; i < MAX_PULSES; i++) {
    RMTMEM.chan[pStrand->rmtChannel].data32[i + offset].val = 0;
  }
  
  pState->buf_pos += len;

  return;
}


static IRAM_ATTR void rmtInterruptHandler(void *arg)
{
  portBASE_TYPE xHigherPriorityTaskWoken = pdFALSE;

  for (int rmtChannel = 0; rmtChannel < MAX_RMT_CHANNELS; rmtChannel++) {
    strand_t * pStrand = strandDataPtrs[rmtChannel];
    if (pStrand == nullptr) {
      continue;
    }

    digitalLeds_stateData * pState = static_cast<digitalLeds_stateData*>(pStrand->_stateVars);
    if (!pState->isProcessing) {
      continue;
    }

    if (RMT.int_st.val & tx_thr_event_offsets[rmtChannel]) {
      // We got an RMT.int_st.ch<n>_tx_thr_event interrupt because RMT.tx_lim_ch<n>.limit was crossed
      RMT.int_clr.val |= tx_thr_event_offsets[rmtChannel];  // set RMT.int_clr.ch<n>_tx_thr_event (reset interrupt bit)
      copyHalfBlockToRmt(pStrand);
    }
    else if (RMT.int_st.val & tx_end_offsets[rmtChannel]) {
      // We got an RMT.int_st.ch<n>_tx_end interrupt with a zero-length entry which means we're done
      RMT.int_clr.val |= tx_end_offsets[rmtChannel];  // set RMT.int_clr.ch<n>_tx_end (reset interrupt bit)
      //gpio_matrix_out(static_cast<gpio_num_t>(pStrand->gpioNum), 0x100, 0, 0);  // only useful if rmt_config keeps getting called
      pState->isProcessing = false;
      gToProcess--;
      if (gToProcess == 0) {
        xSemaphoreGiveFromISR(gRmtSem, &xHigherPriorityTaskWoken);
        if (xHigherPriorityTaskWoken == pdTRUE) { // Perform cleanup if we're all done
          portYIELD_FROM_ISR();
        }
      }
    }

  }

  return;
}


//**************************************************************************//
