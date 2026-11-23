/* Stand-in for the FreeRTOS header included by client-tls.h.
 * The sample task calls vTaskDelete at the end; the test supplies that. */
#ifndef FREERTOS_FREERTOS_H_
#define FREERTOS_FREERTOS_H_
typedef void *TaskHandle_t;
typedef void *xTaskHandle;
#endif
