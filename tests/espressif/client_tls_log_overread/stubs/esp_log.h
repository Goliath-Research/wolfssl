/* ESP-IDF v5.2.3 components/log/include/esp_log.h, the path this example
 * documents (IDE/Espressif/ESP-IDF/README.md: v5.2, v5.3, and master).
 *
 * ESP_LOGI expands to esp_log_write() with LOG_FORMAT, and esp_log_writev()
 * passes that format to vprintf (components/log/log.c). newlib 4.3.0
 * vfprintf case 's' with no precision calls strlen() on the argument
 * (espressif/newlib-esp32 esp-4.3.0 newlib/libc/stdio/vfprintf.c).
 *
 * CONFIG_LOG_COLORS defaults on, CONFIG_LOG_TIMESTAMP_SOURCE_RTOS is the
 * default, and CONFIG_LOG_MASTER_LEVEL defaults off. LOG_MAXIMUM_LEVEL
 * tracks LOG_DEFAULT_LEVEL, which keeps ESP_LOGI compiled in.
 */
#ifndef ESP_LOG_H_STUB_
#define ESP_LOG_H_STUB_

#include <stdint.h>
#include <inttypes.h>

typedef enum {
    ESP_LOG_NONE,
    ESP_LOG_ERROR,
    ESP_LOG_WARN,
    ESP_LOG_INFO,
    ESP_LOG_DEBUG,
    ESP_LOG_VERBOSE
} esp_log_level_t;

#ifndef LOG_LOCAL_LEVEL
#define LOG_LOCAL_LEVEL ESP_LOG_INFO
#endif

#define LOG_COLOR_E ""
#define LOG_COLOR_W ""
#define LOG_COLOR_I ""
#define LOG_COLOR_D ""
#define LOG_COLOR_V ""
#define LOG_RESET_COLOR ""
#define LOG_FORMAT(letter, format) \
    LOG_COLOR_ ## letter #letter " (%" PRIu32 ") %s: " format LOG_RESET_COLOR "\n"

uint32_t esp_log_timestamp(void);
void esp_log_write(esp_log_level_t level, const char *tag, const char *format, ...)
    __attribute__((format(printf, 3, 4)));

#define ESP_LOG_LEVEL(level, tag, format, ...) do { \
        if ((level) == ESP_LOG_ERROR) { \
            esp_log_write(ESP_LOG_ERROR, tag, LOG_FORMAT(E, format), \
                          esp_log_timestamp(), tag, ##__VA_ARGS__); \
        } else if ((level) == ESP_LOG_WARN) { \
            esp_log_write(ESP_LOG_WARN, tag, LOG_FORMAT(W, format), \
                          esp_log_timestamp(), tag, ##__VA_ARGS__); \
        } else { \
            esp_log_write(ESP_LOG_INFO, tag, LOG_FORMAT(I, format), \
                          esp_log_timestamp(), tag, ##__VA_ARGS__); \
        } \
    } while (0)

#define ESP_LOG_LEVEL_LOCAL(level, tag, format, ...) do { \
        if (LOG_LOCAL_LEVEL >= (level)) { \
            ESP_LOG_LEVEL(level, tag, format, ##__VA_ARGS__); \
        } \
    } while (0)

#define ESP_LOGE(tag, format, ...) \
    ESP_LOG_LEVEL_LOCAL(ESP_LOG_ERROR, tag, format, ##__VA_ARGS__)
#define ESP_LOGW(tag, format, ...) \
    ESP_LOG_LEVEL_LOCAL(ESP_LOG_WARN, tag, format, ##__VA_ARGS__)
#define ESP_LOGI(tag, format, ...) \
    ESP_LOG_LEVEL_LOCAL(ESP_LOG_INFO, tag, format, ##__VA_ARGS__)
#define ESP_LOGD(tag, format, ...) \
    ESP_LOG_LEVEL_LOCAL(ESP_LOG_DEBUG, tag, format, ##__VA_ARGS__)
#define ESP_LOGV(tag, format, ...) \
    ESP_LOG_LEVEL_LOCAL(ESP_LOG_VERBOSE, tag, format, ##__VA_ARGS__)

#endif
