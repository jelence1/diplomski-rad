#pragma once

#include "driver/adc.h"
#include "esp_adc_cal.h"

static const adc_bits_width_t ADC_WIDTH = ADC_WIDTH_BIT_12;
static const adc_atten_t ADC_ATTEN = ADC_ATTEN_DB_12;

void adc_init(void);