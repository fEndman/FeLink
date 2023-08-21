//
// Created by ilia.motornyi on 13-Dec-18.
//

#ifndef __SUPPORT_H
#define __SUPPORT_H

#include "main.h"
#include "spi.h"

sbit nRF_CE_Pin = P1^6;
sbit nRF_CSN_Pin = P1^7;

#define nRF24_CE_L() nRF_CE_Pin = 0

#define nRF24_CE_H() nRF_CE_Pin = 1

#define nRF24_CSN_L() nRF_CSN_Pin = 0

#define nRF24_CSN_H() nRF_CSN_Pin = 1

#define nRF24_LL_RW(d) SPI_WriteRead_Byte_Poll(d)

#define Delay_ms(ms) delay_ms(ms)

#endif //__SUPPORT_H
