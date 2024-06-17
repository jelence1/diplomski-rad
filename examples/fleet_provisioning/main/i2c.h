#pragma once

#include <stdint.h>
#include "driver/i2c.h"

#define SDA_PIN GPIO_NUM_7
#define SCL_PIN GPIO_NUM_6

void i2c_init(i2c_port_t i2c_num, gpio_num_t sda_pin, gpio_num_t scl_pin);

void i2c_write_register(uint8_t i2c_addr, uint8_t reg, uint8_t *data, size_t len);

void i2c_read_register(uint8_t i2c_addr, uint8_t reg, uint8_t *data, size_t len);