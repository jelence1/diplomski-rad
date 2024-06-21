#include "adc.h"
#include "moisture.h"

/**
 * Setup moisture ADC settings.
 */
void moisture_init() {
    adc1_config_channel_atten(MOISTURE_CHANNEL, ADC_ATTEN);
}

/**
 * Reads moisture from dedicated GPIO pin.
 * Returns moisture percentage.
 */
float read_moisture(void) {

    int adc_value = adc1_get_raw(MOISTURE_CHANNEL);
    float moisture = 0;
    
	if (adc_value >= WET_SOIL) {
		moisture = 100.0;
	} else if (adc_value <= DRY_SOIL) {
		moisture = 0.0;
	} else {
		moisture = ((100.0)/((double) DRY_SOIL - (double) WET_SOIL))*((double) (adc_value) - (double) WET_SOIL);
	}

    return moisture;
	//return adc_value;
}