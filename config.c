#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <cJSON.h>
#include <syslog.h>
#include <errno.h>
#include "starline.h"
#include "config.h"

static uint8_t convHexChar(char in_byte)
{
  uint8_t i;
  char ar[] = {'0','1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

  for (i = 0; i < sizeof(ar) / sizeof(ar[0]); i++)
  {
     if (ar[i] == in_byte)
     {
        return i;
     }
  }
  return 0xff;
}

static int parse_pincode(char *pin_in, uint16_t *pin_out)
{
  uint32_t i;
  uint8_t digit;

  *pin_out = 0;
  if (pin_in == NULL)
  {
    return -1;
  }

  for (i = 0; i < STARLINE_PINCODE_LEN; i++)
  {
    digit = convHexChar(pin_in[i]);
    if (digit == 0xff)
    {
      return -1;
    }
    *pin_out |= digit << (4 * (STARLINE_PINCODE_LEN - i - 1));
  }

  return 0;
}

static config_t *config_get_from_json_obj(cJSON *cobj)
{
  int fret = 0;
  config_t *ret = NULL;
  cJSON *tmp = NULL;

  if (cobj == NULL)
  {
    return NULL;
  }

  tmp = cJSON_GetObjectItem(cobj, "pin_code");
  if (tmp == NULL)
  {
    syslog(LOG_ERR, "Config: No starline pin code provided");
    return NULL;
  }

  ret = calloc(sizeof(config_t), 1);
  if (ret == NULL)
  {
    syslog(LOG_ERR, "Config: No mem(2)");
    return NULL;
  }

  fret = parse_pincode(tmp->valuestring, &ret->pin_code);
  if (fret < 0)
  {
    syslog(LOG_ERR, "Config: incorrect pin code format");
    config_free(ret);
    return NULL;
  }

  tmp = cJSON_GetObjectItem(cobj, "telegram_bot_token");
  if ((tmp == NULL) || (tmp->valuestring == NULL))
  {
    syslog(LOG_ERR, "Config: No telegram bot token");
    config_free(ret);
    return NULL;
  }

  ret->bot_token = strdup(tmp->valuestring);
  tmp = cJSON_GetObjectItem(cobj, "telegram_user_id");
  if (tmp != NULL)
  {
    ret->user_id = tmp->valuedouble;
  } else {
    syslog(LOG_WARNING, "No telegram used id provided");
  }

  return ret;
}

static config_t *config_parse(uint8_t *buffer, long buffer_size)
{
  cJSON *json = NULL;
  cJSON *config_obj = NULL;
  config_t *ret = NULL;

  if ((buffer == NULL) || (0 == buffer_size))
  {
    syslog(LOG_ERR, "Config: Internal error! Incorrect params!");
    return NULL;
  }

  json = cJSON_Parse((char *)buffer);
  if (json == NULL)
  {
    syslog(LOG_ERR, "Config: Failed to parse JSON: %s", cJSON_GetErrorPtr());
    return NULL;
  }

  config_obj = cJSON_GetObjectItem(json, "config");
  if (config_obj == NULL)
  {
    syslog(LOG_ERR, "Config: Failed to parse JSON: no config object");
  } else {
    ret = config_get_from_json_obj(config_obj);
  }

  cJSON_Delete(json);
  return ret;
}

config_t *config_load(const char *config_file_path)
{
  uint8_t *file_buff = NULL;
  long file_len = 0;
  long ret_len = 0;
  config_t *ret = NULL;
  FILE *pFile = fopen(config_file_path, "rb");

  if (pFile == NULL)
  {
    syslog(LOG_ERR, "Failed to open config file: %d", errno);
    return NULL;
  }

  // Obtain file size
  fseek(pFile, 0L, SEEK_END);
  file_len = ftell(pFile);
  rewind(pFile);

  if (file_len == 0)
  {
    syslog(LOG_ERR, "Config file is empty");
    fclose(pFile);
    return NULL;
  }

  file_buff = calloc(file_len, 1);
  if (file_buff == NULL)
  {
    syslog(LOG_ERR, "No mem for config file");
    fclose(pFile);
    return NULL;
  }

  ret_len = fread(file_buff, 1, file_len, pFile);
  if (ret_len != file_len)
  {
    syslog(LOG_ERR, "Failed to read config file Fread return: %ld", ret_len);
   } else {
    ret = config_parse(file_buff, ret_len);
  }

  free(file_buff);
  fclose(pFile);
  return ret;
}

void config_free(config_t *obj)
{
  if (obj == NULL)
  {
     return;
  }

  free(obj->bot_token);
  free(obj);
}

