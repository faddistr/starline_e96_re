#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <libusb-1.0/libusb.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <semaphore.h>
#include <syslog.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "starline.h"
#include "config.h"
#include "telegram.h"

#define STARLINE_VID 0x2803U
#define STARLINE_PID 0x0015U


#define ENDPOINT_INT_OUT 0x01U
#define ENDPOINT_INT_IN 0x81U
#define TIMEOUT 5000U

static  void *telegramHandle;
static bool should_stop = false;
static config_t *config = NULL;
static sem_t dev_mutex;
static libusb_context *usb_ctx = NULL;
static libusb_device_handle *dev = NULL;
static startline_hnd_t hnd = {0};
static starline_status_packet_t last_packet;


#define MAX_CMD_TEXT 16
typedef void (*cmdptr_t)(libusb_device_handle *, void *, telegram_update_t *);
typedef struct
{
  char text[MAX_CMD_TEXT + 1];
  cmdptr_t func;
} cmd_t;

static void send_stat_telegram(void *teleCtx, telegram_int_t chat_id, const char *header, starline_status_packet_t *status);

int32_t starline_io_int_sync(libusb_device_handle *dev, uint8_t *out_buffer, uint8_t *in_buffer)
{
    int len;
    int res;

    sem_wait(&dev_mutex);
    if (out_buffer != NULL)
    {
        res = libusb_interrupt_transfer(dev, ENDPOINT_INT_OUT, out_buffer, STARLINE_PACKET_SIZE, &len, TIMEOUT);
        if (res < 0)
        {
            syslog(LOG_ERR, "(OUT) Interrupt transfer error: %d\n", res);
            return res;
        }
        syslog(LOG_DEBUG, "Sent: %d bytes\n", len);
    }

    if (in_buffer != NULL)
    {
        //todo -> parse_answer
        res = libusb_interrupt_transfer(dev, ENDPOINT_INT_IN, in_buffer, STARLINE_PACKET_SIZE, &len, TIMEOUT);
        if (res < 0)
        {
           syslog(LOG_ERR, "(IN) Interrupt transfer error: %d\n", res);
           return res;
        }
    }

    sem_post(&dev_mutex);
    return 0;
}

int32_t starline_init_async_read_transfer(libusb_device_handle *dev, struct libusb_transfer **irq_transfer, uint8_t *in_buffer, libusb_transfer_cb_fn cb)
{
    int res;
    *irq_transfer = libusb_alloc_transfer(0);
    if (*irq_transfer == NULL)
    {
        syslog(LOG_ERR, "No mem for async transfer\n");
        return -1;
    }

    libusb_fill_iso_transfer(*irq_transfer, dev, ENDPOINT_INT_IN, in_buffer, STARLINE_PACKET_SIZE, 1, cb, in_buffer, TIMEOUT);
    res = libusb_submit_transfer(*irq_transfer);

    if (res)
    {

        syslog(LOG_ERR, "Failed to submit iso transfer %d", res);
        libusb_free_transfer(*irq_transfer);
        *irq_transfer = NULL;
    }

    return  res;
}

void starline_on_error(void *hnd, starline_packet_t *packet, starline_errors_t error)
{
    (void)hnd;
    (void)packet;
    syslog(LOG_ERR, "Starline error: %d\r\n", error);
}
#define COLUMNS 8
void starline_on_data(void *hnd, starline_status_packet_t *packet)
{
    (void)hnd;
    static uint8_t alarm_status_saved;
#if 0
    int i, j;
    uint16_t line = 0;

    syslog(LOG_DEBUG, "\nStarline data in payload: %d\r\n", packet->hdr.payload_size);
    syslog(LOG_DEBUG, " # ");
    for (i = 0; i < COLUMNS; i++)
    {
        syslog(LOG_DEBUG, "%4d ",i);
    }

    syslog(LOG_DEBUG, "\r\n");

    for (i = 0; i < packet->hdr.payload_size; i+= COLUMNS)
    {
        syslog(LOG_DEBUG, "%2d ", line++);
        for (j = 0; j < COLUMNS; j++)
        {
          if ((i + j) >= packet->hdr.payload_size)
          {
              break;
          }

          syslog(LOG_DEBUG, "0x%02X ", packet->payload[i + j]);
        }
        syslog(LOG_DEBUG, "\r\n");
    }


    syslog(LOG_DEBUG, "Alarm status: %03d 0x%02X\r\n", packet->status.alarm_status, packet->status.alarm_status);
    syslog(LOG_DEBUG, "RPM: %08d 0x%04X\r\n", packet->status.rpm, packet->status.rpm);
    syslog(LOG_DEBUG, "Temp engine: %03d 0x%02X\r\n", packet->status.temp_engine, packet->status.temp_engine);
    syslog(LOG_DEBUG, "Temp int: %03d 0x%02X\r\n", packet->status.temp_int, packet->status.temp_int);
    syslog(LOG_DEBUG, "Ign status: %03d 0x%02X\r\n", packet->status.ign, packet->status.ign);

    syslog(LOG_DEBUG, "Temp engine p: %03d 0x%02X\r\n", packet->status.temp_engine_prime, packet->status.temp_engine_prime);
    syslog(LOG_DEBUG, "Temp int p: %03d 0x%02X\r\n", packet->status.temp_int_prime, packet->status.temp_int_prime);
    syslog(LOG_DEBUG, "Voltage accum: %2.2fV\r\n", ((float)packet->status.accum_mV/1000));
    syslog(LOG_DEBUG, "Status unk: %d\r\n", packet->status.status_unk);

    syslog(LOG_DEBUG, "Reg id prime: %04X\r\n", packet->status.regid_prime);
    syslog(LOG_DEBUG, "Reg id sec: %04X\r\n", packet->status.regid_sec);
    syslog(LOG_DEBUG, "Diag flags: %02X\r\n", packet->status.diag_flags);
    syslog(LOG_DEBUG, "Timestamp since 2012 #: %u %0X\r\n", packet->status.timestamp, packet->status.timestamp);

    time_t time_starline = packet->status.timestamp + STARLINE_EPOCH_START_OFFSET;
    syslog(LOG_DEBUG, "%s", ctime(&time_starline));
    syslog(LOG_DEBUG, "%d %x\r\n", packet->status.unk_data, packet->status.unk_data);
#endif
    memcpy(&last_packet, packet, sizeof(last_packet));
    if (alarm_status_saved != packet->status.alarm_status)
    {
      alarm_status_saved = packet->status.alarm_status;
      if ((packet->status.alarm_status  & STARLINE_ALARM_STATUS_ON_MASK)
          && (packet->status.alarm_status & STARLINE_ALARM_MASK)
          && (packet->status.rpm == 0))
      {
        send_stat_telegram(telegramHandle, config->user_id, "Alarm:", packet);
      }
   }
}

uint8_t convHexChar(char in_byte)
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

int parse_pincode(char *pin_in, uint16_t *pin_out)
{
  uint32_t i;
  uint8_t digit;

  *pin_out = 0;
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

static void print_buffer(uint8_t *buffer, uint32_t size)
{
    uint32_t i;
    for (i = 0; i < size; i++)
    {
        syslog(LOG_DEBUG, "%X ", buffer[i]);
    }
    syslog(LOG_DEBUG, "\r\n");
}


static int32_t starline_debug_mode(libusb_device_handle *dev)
{
  int32_t res;
  uint8_t out_buffer[STARLINE_PACKET_SIZE];
  uint8_t in_buffer[STARLINE_PACKET_SIZE];
  starline_cmd_t *answ = (starline_cmd_t *)in_buffer;


  memset(out_buffer, 0x00, sizeof(out_buffer));
  starline_send_eof_cmd_gen((starline_cmd_t *)out_buffer);
  res = starline_io_int_sync(dev, out_buffer, in_buffer);
  if (res < 0)
  {
      syslog(LOG_ERR, "LIBUSB error %d\r\n", res);
      return res;
  }

  if (answ->hdr.function_id == STARLINE_FAILED)
  {
    syslog(LOG_ERR, "Failed to send EOF\r\n");
    print_buffer(in_buffer, sizeof(in_buffer));
    return -1;
  }

  memset(out_buffer, 0x00, sizeof(out_buffer));
  starline_send_unlock_cmd_gen((starline_cmd_t *)out_buffer);
  res = starline_io_int_sync(dev, out_buffer, in_buffer);
  if (res < 0)
  {
      syslog(LOG_ERR, "LIBUSB error %d\r\n", res);
      return res;
  }

  if (answ->hdr.function_id == STARLINE_FAILED)
  {
    syslog(LOG_ERR, "Failed to send UNLOCK\r\n");
    print_buffer(in_buffer, sizeof(in_buffer));
    return -1;
  }

  return 0;
}

static int32_t starline_auth(libusb_device_handle *dev, uint16_t pin_code)
{
  int32_t res;
  uint8_t out_buffer[STARLINE_PACKET_SIZE];
  uint8_t in_buffer[STARLINE_PACKET_SIZE];
  starline_cmd_t *answ = (starline_cmd_t *)in_buffer;

  memset(out_buffer, 0x00, sizeof(out_buffer));
  starline_send_pin_cmd_gen((starline_cmd_t *)out_buffer, pin_code);
  res = starline_io_int_sync(dev, out_buffer, in_buffer);
  if (res < 0)
  {
      return -1;
  }

  if (answ->hdr.function_id == STARLINE_FAILED)
  {
    syslog(LOG_ERR, "Failed to send pin code\r\n");
    print_buffer(in_buffer, sizeof(in_buffer));
    return -1;
  }

  res = starline_debug_mode(dev);
  if (res < 0)
  {
    syslog(LOG_ERR, "Failed to init debug mode!\r\n");
    return res;
  }

  return 0;
}

static telegram_kbrd_inline_btn_t row0[] = {{.text = "Arm", .callback_data = "cmd_arm"}, {.text = "Disarm", .callback_data = "cmd_disarm"}, {NULL}};
static telegram_kbrd_inline_btn_t row1[] = {{.text = "Engine start", .callback_data = "cmd_eng_start"}, {.text = "Engine stop", .callback_data = "cmd_eng_stop"}, {NULL}};
static telegram_kbrd_inline_btn_t row2[] = {{.text = "Stat", .callback_data = "cmd_stat"}, {NULL}};
static telegram_kbrd_inline_row_t kbrd_btns[] =
{
    { row0, },
    { row1, },
    { row2, },
    { NULL },
};

static telegram_kbrd_t keyboard =
{
    .type = TELEGRAM_KBRD_INLINE,
    .kbrd = {
        .inl.rows = kbrd_btns,
    },
};


static void send_stat_telegram(void *teleCtx, telegram_int_t chat_id, const char *header, starline_status_packet_t *status)
{
  telegram_send_text(teleCtx, chat_id, &keyboard, "%s\r\n"
                                          "Temperature[0]: %d C\r\n"
                                          "Temperature[1]: %d C\r\n"
                                          "RPM: %d\r\n"
                                          "Battery: %2.2f V\r\n"
                                          "Alarm: %s\r\n"
                                          "Full status: %x\r\n",
                     header,
                     status->status.temp_engine,
                     status->status.temp_int,
                     status->status.rpm,
                     ((float)status->status.accum_mV) / 1000,
                     (status->status.alarm_status & STARLINE_ALARM_STATUS_ON_MASK)?"on":"off",
                     status->status.alarm_status);
}

static void cmd_stat_cb(libusb_device_handle *dev, void *teleCtx, telegram_update_t *info)
{
  (void)dev;
  telegram_int_t chat = telegram_get_chat_id(info->callback_query->message);
  send_stat_telegram(teleCtx, chat, "Status:", &last_packet);
  telegram_answer_cb_query(teleCtx, info->callback_query->id, "OK", false, NULL, 0);
}

static void cmd_eng_start_cb(libusb_device_handle *dev, void *teleCtx, telegram_update_t *info)
{
  int32_t res;
  uint8_t out_buffer[STARLINE_PACKET_SIZE];
  uint8_t in_buffer[STARLINE_PACKET_SIZE];


  memset(out_buffer, 0x00, sizeof(out_buffer));
  starline_start_engine_cmd_gen((starline_cmd_t *)out_buffer);
  res = starline_io_int_sync(dev, out_buffer, in_buffer);
  if (res < 0)
  {
      telegram_answer_cb_query(teleCtx, info->callback_query->id, "Fail", false, NULL, 0);
      return;
  }
  telegram_answer_cb_query(teleCtx, info->callback_query->id, "OK", false, NULL, 0);
}

static void cmd_eng_stop_cb(libusb_device_handle *dev, void *teleCtx, telegram_update_t *info)
{
  int32_t res;
  uint8_t out_buffer[STARLINE_PACKET_SIZE];
  uint8_t in_buffer[STARLINE_PACKET_SIZE];
  res = starline_auth(dev, config->pin_code);
  if (res < 0)
  {
      telegram_answer_cb_query(teleCtx, info->callback_query->id, "Fail auth", false, NULL, 0);
      return;   
  }

  memset(out_buffer, 0x00, sizeof(out_buffer));
  starline_stop_engine_cmd_gen((starline_cmd_t *)out_buffer);
  res = starline_io_int_sync(dev, out_buffer, in_buffer);
  if (res < 0)
  {
      telegram_answer_cb_query(teleCtx, info->callback_query->id, "Fail", false, NULL, 0);
      return;
  }
  telegram_answer_cb_query(teleCtx, info->callback_query->id, "OK", false, NULL, 0);
}


static void cmd_arm_cb(libusb_device_handle *dev, void *teleCtx, telegram_update_t *info)
{
  int32_t res;
  uint8_t out_buffer[STARLINE_PACKET_SIZE];
  uint8_t in_buffer[STARLINE_PACKET_SIZE];
  res = starline_auth(dev, config->pin_code);
  if (res < 0)
  {
      telegram_answer_cb_query(teleCtx, info->callback_query->id, "Fail auth", false, NULL, 0);
      return;
  }

  memset(out_buffer, 0x00, sizeof(out_buffer));
  starline_arm_cmd_gen((starline_cmd_t *)out_buffer);
  res = starline_io_int_sync(dev, out_buffer, in_buffer);
  if (res < 0)
  {
      telegram_answer_cb_query(teleCtx, info->callback_query->id, "Fail", false, NULL, 0);
      return;
  }
  telegram_answer_cb_query(teleCtx, info->callback_query->id, "OK", false, NULL, 0);
}


static void cmd_disarm_cb(libusb_device_handle *dev, void *teleCtx, telegram_update_t *info)
{
  int32_t res;
  uint8_t out_buffer[STARLINE_PACKET_SIZE];
  uint8_t in_buffer[STARLINE_PACKET_SIZE];

  res = starline_auth(dev, config->pin_code);
  if (res < 0)
  {
      telegram_answer_cb_query(teleCtx, info->callback_query->id, "Fail auth", false, NULL, 0);
      return;
  }

  memset(out_buffer, 0x00, sizeof(out_buffer));
  starline_disarm_cmd_gen((starline_cmd_t *)out_buffer);
  res = starline_io_int_sync(dev, out_buffer, in_buffer);
  if (res < 0)
  {
      telegram_answer_cb_query(teleCtx, info->callback_query->id, "Fail", false, NULL, 0);
      return;
  }
  telegram_answer_cb_query(teleCtx, info->callback_query->id, "OK", false, NULL, 0);
}


static void telegram_process_cbquery(void *teleCtx, telegram_update_t *info)
{
  uint32_t i;
  cmd_t cmd[] = {
     {.text = "cmd_stat", .func = cmd_stat_cb},
     {.text = "cmd_eng_start", .func = cmd_eng_start_cb},
     {.text = "cmd_eng_stop", .func = cmd_eng_stop_cb},
     {.text = "cmd_arm", .func = cmd_arm_cb},
     {.text = "cmd_disarm", .func = cmd_disarm_cb}
  };
  if (info->callback_query == NULL)
  {
    return;
  }

  if (info->callback_query->from->id != config->user_id)
  {
    return;
  }

  for(i = 0; i < (sizeof(cmd) / sizeof(cmd[0])); i++)
  {
    if (!strncmp(cmd[i].text, info->callback_query->data, MAX_CMD_TEXT))
    {
        cmd[i].func(dev, teleCtx, info);
        starline_reset(&hnd);
        return;
    }
  }
}

static void telegram_process_message(void *teleCtx, telegram_update_t *info)
{
  telegram_chat_message_t *msg = telegram_get_message(info);
  telegram_int_t chat = telegram_get_chat_id(msg);;
  telegram_int_t user_id = telegram_get_user_id(msg);


  if ((user_id != -1) && (config->user_id == 0))
  {
    telegram_send_text(teleCtx, chat, NULL, "Your user id is %f", user_id);
    return;
  }

  if (user_id!= config->user_id)
  {
    syslog(LOG_DEBUG, "Ignored %f\r\n", user_id);
    return;
  }

  telegram_kbrd(teleCtx, chat, "Select command", &keyboard);
}

static void telegramOnMsg(void *teleCtx, telegram_update_t *info)
{
  telegram_process_cbquery(teleCtx, info);
  telegram_process_message(teleCtx, info);
}

static void cleanup(void)
{
  sem_destroy(&dev_mutex);
  libusb_close(dev);
  libusb_exit(usb_ctx);
  closelog();
  config_free(config);
}

#define PATH_TO_CONFIG "/etc/starline.json"

static void sig_handler(int signo)
{
  if (signo == SIGINT)
  {
    syslog(LOG_INFO, "Stopping daemon...");
    should_stop = true;
  }
}

static void daemonize(void)
{
  pid_t pid;

    /* Fork off the parent process */
    pid = fork();

    /* An error occurred */
    if (pid < 0)
    {
      exit(EXIT_FAILURE);
    }

    /* Success: Let the parent terminate */
    if (pid > 0)
    {
      exit(EXIT_SUCCESS);
    }

    /* On success: The child process becomes session leader */
    if (setsid() < 0)
    {
      exit(EXIT_FAILURE);
    }

    /* Catch, ignore and handle signals */
    signal(SIGCHLD, SIG_IGN);
    signal(SIGHUP, SIG_IGN);

    /* Fork off for the second time*/
    pid = fork();

    /* An error occurred */
    if (pid < 0)
    {
      exit(EXIT_FAILURE);
    }

    /* Success: Let the parent terminate */
    if (pid > 0)
    {
      exit(EXIT_SUCCESS);
    }

    /* Set new file permissions */
    umask(0);

    /* Change the working directory to the root directory */
    /* or another appropriated directory */
    chdir("/");
    if (signal(SIGINT, sig_handler) == SIG_ERR)
    {
      fprintf(stderr, "Failed to initialize sig handler\r\n");
      exit(EXIT_FAILURE);
    }

    /* Close all open file descriptors */
    int x;
    for (x = sysconf(_SC_OPEN_MAX); x>=0; x--)
    {
        close(x);
    }

}

int main()
{
    int32_t res;
    startline_cb_t cbs = {
        .on_error = starline_on_error,
        .on_status_packet = starline_on_data,
    };
    uint8_t in_buffer_i[STARLINE_PACKET_SIZE];

    //daemonize();
    openlog("starline", LOG_PID, LOG_DAEMON);
    starline_set_cb(&hnd, &cbs);

    res = libusb_init(&usb_ctx);
    if (res)
    {
        syslog(LOG_ERR, "Failed to open libusb %d\n", res);
        closelog();
        return -1;
    }

    dev = libusb_open_device_with_vid_pid(usb_ctx, STARLINE_VID, STARLINE_PID);
    if (dev == NULL)
    {
        libusb_exit(usb_ctx);
        syslog(LOG_ERR, "Device not found\n");
        closelog();
        return -1;
    }
    (void)libusb_detach_kernel_driver(dev, 0);
    res = libusb_claim_interface(dev, 0);
    if (res < 0)
    {
        syslog(LOG_ERR, "Claim device failed %d\n", res);
        libusb_close(dev);
        libusb_exit(usb_ctx);
        closelog();
        return -1;
    }

    config = config_load(PATH_TO_CONFIG);
    if (config == NULL)
    {
      cleanup();
      return -1;
    }

    sem_init(&dev_mutex, 0, 1);
    res = starline_auth(dev, config->pin_code);
    if (res < 0)
    {
        cleanup();
        return -1;
    }

    telegramHandle = telegram_init(config->bot_token, 10, telegramOnMsg);
    if (telegramHandle == NULL)
    {
      syslog(LOG_ERR, "Failed to init telegram\r\n");
      cleanup();
      return -1;
    }

    while(!should_stop)
    {
        res = starline_io_int_sync(dev, NULL, in_buffer_i);
        if (res < 0)
        {
            telegram_stop(telegramHandle);
            cleanup();
            return -1;
        }

        starline_proccess_next_packet(&hnd, in_buffer_i, STARLINE_PACKET_SIZE);
    }

    telegram_stop(telegramHandle);
    cleanup();
    return 0;
}

