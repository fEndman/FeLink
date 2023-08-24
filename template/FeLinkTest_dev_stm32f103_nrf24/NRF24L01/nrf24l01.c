#include "nrf24l01.h"

static const uint8_t nrf24l01_cmd_addr[] = {0x66, 0x6C, 0x63, 0x6D, 0x64};  //"FLCMD"

uint8_t nrf24l01_buf[NRF24_PAYLOAD_WIDTH];
nRF24_RXResult nrf24l01_rx_pipe;
volatile uint8_t nrf24l01_data_count;
volatile uint8_t nrf24l01_data_en_rx = 0;
volatile uint8_t nrf24l01_status = 0;

int nrf24l01_config(void)
{
  int res;

  nRF24_CE_L();

  nRF24_Init();

  res = nRF24_Check();
  if (!res)
    return 1;

  nRF24_SetRFChannel(113);
  nRF24_SetDataRate(nRF24_DR_2Mbps);
  nRF24_SetCRCScheme(nRF24_CRC_2byte);
  nRF24_SetTXPower(nRF24_TXPWR_0dBm);
  nRF24_SetAddrWidth(5);
	
  nRF24_SetAddr(nRF24_PIPE0, nrf24l01_cmd_addr);
  nRF24_SetRXPipe(nRF24_PIPE0, nRF24_AA_ON, NRF24_PAYLOAD_WIDTH);
  nRF24_SetAddr(nRF24_PIPETX, nrf24l01_cmd_addr);
	nRF24_SetAutoRetr(nRF24_ARD_1000us, 15);
	
	nRF24_SetDynamicPayloadLength(nRF24_DPL_OFF);
	
  nRF24_SetPowerMode(nRF24_PWR_UP);

  nRF24_SetOperationalMode(nRF24_MODE_RX);
  nRF24_CE_H();

  return 0;
}

void nrf24l01_set_felink_data_addr(uint32_t salt)
{
  uint8_t nrf24l01_data_addr[] = {0x66, 0x6C, (uint8_t)(salt >> 16), (uint8_t)(salt >> 8), (uint8_t)(salt >> 0)}; //"FL..."

  nRF24_CE_L();
  nRF24_SetAddr(nRF24_PIPE1, nrf24l01_data_addr);
  nRF24_SetRXPipe(nRF24_PIPE1, nRF24_AA_ON, NRF24_PAYLOAD_WIDTH);
  nRF24_CE_H();
}

static void nrf24l01_memcpy(void *dst, const void *src, int count)
{
  uint8_t *d = (uint8_t *)dst;
  const uint8_t *s = (const uint8_t *)src;
  if (count)
  {
    do
    {
      *d++ = *s++;
    } while (--count);
  }
}

#define NRF24_MIN(a, b) ((a) < (b) ? (a) : (b))
#define NRF24_FELINK_BLOCK_SIZE (NRF24_PAYLOAD_WIDTH - 1)
uint32_t nrf24l01_rx_felink_package(uint8_t *buf, uint16_t buf_len)
{
  uint8_t buf_max_block_index = buf_len / NRF24_FELINK_BLOCK_SIZE;
  uint8_t max_block_index = 0;
  uint8_t block_index;

  while (1)
  {
    nrf24l01_data_count = 0;
    nrf24l01_data_en_rx = 1;
    while (nrf24l01_data_count == 0);
    nrf24l01_data_en_rx = 0;
    
    block_index = nrf24l01_buf[0];
    if (block_index > buf_max_block_index)
      continue;
    else
      nrf24l01_memcpy(
        &buf[block_index * NRF24_FELINK_BLOCK_SIZE],
        &nrf24l01_buf[1],
        block_index == buf_max_block_index ? buf_len - block_index * NRF24_FELINK_BLOCK_SIZE : NRF24_FELINK_BLOCK_SIZE);

    if (block_index > max_block_index)
      max_block_index = block_index;

    if (block_index == 0)
      return NRF24_MIN((max_block_index + 1) * NRF24_FELINK_BLOCK_SIZE, buf_len);
  }
}

int nrf24l01_send_payload(uint8_t *buf, uint16_t len)
{
  nRF24_CE_L();
  nRF24_FlushTX();
  nRF24_WritePayload(buf, len);
  nrf24l01_status &= ~(nRF24_FLAG_TX_DS | nRF24_FLAG_MAX_RT);
  nRF24_CE_H();
  while ((nrf24l01_status & (nRF24_FLAG_TX_DS | nRF24_FLAG_MAX_RT)) == 0);
	if (nrf24l01_status & nRF24_FLAG_MAX_RT)
	{
		nRF24_FlushTX();
		return 1;
	}
  return 0;
}

int nrf24l01_tx_felink_package(const uint8_t *buf, uint16_t len)
{
  uint8_t tx_buf[NRF24_PAYLOAD_WIDTH] = {0};
  uint8_t block_index = len / NRF24_FELINK_BLOCK_SIZE;
  const uint8_t *ptr = buf + len - len % NRF24_FELINK_BLOCK_SIZE;
  int ret = 0;
  
	nRF24_CE_L();
  nRF24_SetOperationalMode(nRF24_MODE_TX);

  tx_buf[0] = block_index;
  nrf24l01_memcpy(&tx_buf[1], ptr, len % NRF24_FELINK_BLOCK_SIZE);
  ret = nrf24l01_send_payload(tx_buf, NRF24_PAYLOAD_WIDTH);
  if (ret)
    goto tx_send_exit;
  ptr -= NRF24_FELINK_BLOCK_SIZE;
  while (block_index--)
  {
    tx_buf[0] = block_index;
    nrf24l01_memcpy(&tx_buf[1], ptr, NRF24_FELINK_BLOCK_SIZE);
    ret = nrf24l01_send_payload(tx_buf, NRF24_PAYLOAD_WIDTH);
    if (ret)
      goto tx_send_exit;
    ptr -= NRF24_FELINK_BLOCK_SIZE;
  }

tx_send_exit:
	nRF24_CE_L();
  nRF24_SetOperationalMode(nRF24_MODE_RX);
	nRF24_CE_H();
  return ret;
}

void nrf24l01_irq_handler(void)
{
  nrf24l01_status = nRF24_GetStatus();
  while (nrf24l01_data_en_rx && nRF24_GetStatus_RXFIFO() != nRF24_STATUS_RXFIFO_EMPTY)
    nrf24l01_rx_pipe = nRF24_ReadPayload(nrf24l01_buf, (uint8_t *)&nrf24l01_data_count);
  nRF24_ClearIRQFlags();
}
