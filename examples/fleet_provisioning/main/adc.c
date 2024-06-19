#include "adc.h"

/**
 * Setup global ADC settings. 
 */
void adc_init(void) {
    adc1_config_width(ADC_WIDTH);
}