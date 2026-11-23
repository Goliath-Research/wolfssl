#ifndef FREERTOS_TASK_H_
#define FREERTOS_TASK_H_
#include "FreeRTOS.h"
#define pdPASS 1
void vTaskDelete(void *task);
int xTaskCreate(void (*fn)(void *), const char *name, unsigned stack,
                void *arg, int prio, TaskHandle_t *out);
#endif
