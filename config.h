#ifndef CONFIG_H
#define CONFIG_H
#include <stdint.h>
#include "telegram.h"

typedef struct
{
  uint16_t pin_code;
  telegram_int_t user_id;
  char *bot_token;
}config_t;

config_t *config_load(const char *config_file);
void config_free(config_t *obj);

#endif // CONFIG_H
