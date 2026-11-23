#ifndef CLIENT_TLS_LOG_WALK_H_
#define CLIENT_TLS_LOG_WALK_H_

#include <stddef.h>
#include <stdint.h>

/* Filled when the sample logs "Server response:" through ESP_LOGI %s. */
extern int g_server_response_logged;
extern size_t g_server_response_strlen;
extern unsigned char g_server_response_bytes[256];

void log_walk_reset(void);

#endif
