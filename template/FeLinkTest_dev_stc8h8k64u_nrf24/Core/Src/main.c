#include "main.h"

#include "gpio.h"
#include "adc.h"
#include "uart.h"
#include "spi.h"
#include "exti.h"
#include "timer.h"
#include "delay.h"

#include "nrf24l01.h"
#include "felink.h"

#define FELINK_PACKAGE_BUF_SIZE FELINK_RECOMMENDED_USER_RX_BUF_SIZE

struct fldev fldev0;
flu8 fl_package_buf[FELINK_PACKAGE_BUF_SIZE];

static flu16 my_rd16(const flu8 *p)
{
    flu16 rv;
    rv = p[1];
    rv = rv << 8 | p[0];
    return rv;
}

void my_memcpy(void* dst, const void* src, int count)
{
	flu8 *d = (flu8*)dst;
	const flu8 *s = (const flu8*)src;
	if (count) {
		do {
			*d++ = *s++;
		} while (--count);
	}
}

char my_strncmp(char* c1, char* c2, int count)
{
	while(count--)
		if(*c1++ != *c2++)
			return 1;
	return 0;
}

void led_init(void)
{
	GPIO_InitTypeDef	GPIO_InitStructure;
	
	GPIO_InitStructure.Pin  = GPIO_Pin_0;
	GPIO_InitStructure.Mode = GPIO_OUT_PP;
	GPIO_Inilize(GPIO_P2,&GPIO_InitStructure);
}

void random_init(void)
{
	GPIO_InitTypeDef	GPIO_InitStructure;
	ADC_InitTypeDef		ADC_InitStructure;
	
	GPIO_InitStructure.Pin  = GPIO_Pin_6;
	GPIO_InitStructure.Mode = GPIO_HighZ;
	GPIO_Inilize(GPIO_P0,&GPIO_InitStructure);

	ADC_InitStructure.ADC_SMPduty   = 10;
	ADC_InitStructure.ADC_CsSetup   = 0;
	ADC_InitStructure.ADC_CsHold    = 1;
	ADC_InitStructure.ADC_Speed     = ADC_SPEED_2X16T;
	ADC_InitStructure.ADC_Power     = DISABLE;
	ADC_InitStructure.ADC_AdjResult = ADC_RIGHT_JUSTIFIED;
	ADC_InitStructure.ADC_Priority    = Priority_0;
	ADC_InitStructure.ADC_Interrupt = DISABLE;
	ADC_Inilize(&ADC_InitStructure);
	
	ADC_PowerControl(ENABLE);
}

void uart_config(void)
{
	GPIO_InitTypeDef	GPIO_InitStructure;
	COMx_InitDefine		COMx_InitStructure;
		
	GPIO_InitStructure.Pin  = GPIO_Pin_6 | GPIO_Pin_7;
	GPIO_InitStructure.Mode = GPIO_PullUp;
	GPIO_Inilize(GPIO_P3,&GPIO_InitStructure);

	COMx_InitStructure.UART_Mode      = UART_8bit_BRTx;
	COMx_InitStructure.UART_BRT_Use   = BRT_Timer2;
	COMx_InitStructure.UART_BaudRate  = 115200ul;
	COMx_InitStructure.UART_RxEnable  = ENABLE;
	COMx_InitStructure.BaudRateDouble = DISABLE;
	COMx_InitStructure.UART_Interrupt = ENABLE;
	COMx_InitStructure.UART_Priority  = Priority_1;
	COMx_InitStructure.UART_P_SW      = UART1_SW_P36_P37;
	UART_Configuration(UART1, &COMx_InitStructure);
}

void key_init()
{
	GPIO_InitTypeDef	GPIO_InitStructure;
	EXTI_InitTypeDef	EXTI_InitStructure;
	
	GPIO_InitStructure.Pin  = GPIO_Pin_2;
	GPIO_InitStructure.Mode = GPIO_HighZ;
	GPIO_Inilize(GPIO_P3,&GPIO_InitStructure);
	
	EXTI_InitStructure.EXTI_Mode = EXT_MODE_Fall;
	EXTI_InitStructure.EXTI_Priority = Priority_0;
	EXTI_InitStructure.EXTI_Interrupt = ENABLE;
	Ext_Inilize(EXT_INT0, &EXTI_InitStructure);
}

extern u32 sys_tick_ms;
void sys_tick_init(u32 freq)
{
	TIM_InitTypeDef	TIM_InitStructure;
	
	TIM_InitStructure.TIM_Mode = TIM_16BitAutoReload;
	TIM_InitStructure.TIM_Priority = Priority_3;
	TIM_InitStructure.TIM_Interrupt = ENABLE;
	TIM_InitStructure.TIM_ClkSource = TIM_CLOCK_1T;
	TIM_InitStructure.TIM_ClkOut = DISABLE;
	TIM_InitStructure.TIM_Value = (u16)(0x10000 - MAIN_Fosc / 1 / freq);
	TIM_InitStructure.TIM_Run = ENABLE;
	Timer_Inilize(Timer0, &TIM_InitStructure);
	
	sys_tick_ms = 0;
}

void nrf24l01_hardware_init(void)
{
	GPIO_InitTypeDef	GPIO_InitStructure;
	SPI_InitTypeDef		SPI_InitStructure;
	EXTI_InitTypeDef	EXTI_InitStructure;
	
	GPIO_InitStructure.Pin  = GPIO_Pin_6 | GPIO_Pin_7;
	GPIO_InitStructure.Mode = GPIO_OUT_PP;
	GPIO_Inilize(GPIO_P1,&GPIO_InitStructure);
	
	GPIO_InitStructure.Pin  = GPIO_Pin_3 | GPIO_Pin_4 | GPIO_Pin_5;
	GPIO_InitStructure.Mode = GPIO_PullUp;
	GPIO_Inilize(GPIO_P1,&GPIO_InitStructure);

	SPI_InitStructure.SPI_Module    = ENABLE;
	SPI_InitStructure.SPI_SSIG      = DISABLE;
	SPI_InitStructure.SPI_FirstBit  = SPI_MSB;
	SPI_InitStructure.SPI_Mode      = SPI_Mode_Master;
	SPI_InitStructure.SPI_CPOL      = SPI_CPOL_Low;
	SPI_InitStructure.SPI_CPHA      = SPI_CPHA_1Edge;
	SPI_InitStructure.SPI_Interrupt = DISABLE;
	SPI_InitStructure.SPI_Speed     = SPI_Speed_64;
	SPI_InitStructure.SPI_IoUse     = SPI_P12_P13_P14_P15;
	SPI_Init(&SPI_InitStructure);
	
	GPIO_InitStructure.Pin  = GPIO_Pin_3;
	GPIO_InitStructure.Mode = GPIO_PullUp;
	GPIO_Inilize(GPIO_P3,&GPIO_InitStructure);
	
	EXTI_InitStructure.EXTI_Mode = EXT_MODE_Fall;
	EXTI_InitStructure.EXTI_Priority = Priority_2;
	EXTI_InitStructure.EXTI_Interrupt = ENABLE;
	Ext_Inilize(EXT_INT1, &EXTI_InitStructure);
}

void main(void)
{
	fluint len;
	flresult flres;
	int res;

	led_init();
	random_init();
	uart_config();
	key_init();
	sys_tick_init(1000);
	nrf24l01_hardware_init();
	
	EA = 1;

	res = nrf24l01_config();
	flres = fl_init(&fldev0);
	while (res || flres)
	{
		P20 = ~P20;
		delay_ms(250);
	}
	P20 = 0;

	while(1)
	{
		len = nrf24l01_rx_felink_package(fl_package_buf, sizeof(fl_package_buf));
		flres = fl_receive_handler(&fldev0, fl_package_buf, len);
		if(flres == RES_DATA_AVAILABLE)
		{
			if(my_strncmp((char*)fldev0.buf, "on", 2) == 0)
				P20 = 0;
			else if(my_strncmp((char*)fldev0.buf, "off", 3) == 0)
				P20 = 1;
		}
		else if (flres == RES_CONNECTED)
		{
			nrf24l01_set_felink_data_addr(fldev0.salt);
		}
		else if (flres < 0)
		{
			P20 = ~P20;
		}
	}
}
