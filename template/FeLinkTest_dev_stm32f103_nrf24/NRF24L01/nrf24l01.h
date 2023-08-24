#ifndef __NRF24L01_H
#define __NRF24L01_H

#include "main.h"
#include "nrf24.h"

#define NRF24_PAYLOAD_WIDTH 32

extern uint8_t nrf24l01_buf[NRF24_PAYLOAD_WIDTH];
extern volatile uint8_t nrf24l01_data_count;
extern volatile uint8_t nrf24l01_data_en_rx;
extern volatile uint8_t nrf24l01_status;

int nrf24l01_config(void);
void nrf24l01_set_felink_data_addr(uint32_t salt);
uint32_t nrf24l01_rx_felink_package(uint8_t *buf, uint16_t buf_len);
int nrf24l01_tx_felink_package(const uint8_t *buf, uint16_t len);
void nrf24l01_irq_handler(void);

#endif
