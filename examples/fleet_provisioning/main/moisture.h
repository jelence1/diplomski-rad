#pragma once

#include "adc.h"

#define WET_SOIL	4095
#define DRY_SOIL	500

static const adc_channel_t MOISTURE_CHANNEL = ADC_CHANNEL_2;

void moisture_init(void);

float read_moisture(void);