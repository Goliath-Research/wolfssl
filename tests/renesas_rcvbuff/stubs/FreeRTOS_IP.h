#ifndef FREERTOS_IP_STUB_H
#define FREERTOS_IP_STUB_H

#include <stdint.h>
#include <stdlib.h>

typedef int BaseType_t;
typedef unsigned int UBaseType_t;

#define pdPASS 1
#define pdTRUE 1
#define pdFALSE 0

#ifndef configASSERT
#define configASSERT(x) do { if (!(x)) abort(); } while (0)
#endif

BaseType_t FreeRTOS_IPInit(const uint8_t *ip, const uint8_t *mask,
    const uint8_t *gw, const uint8_t *dns, const uint8_t *mac);

#endif
