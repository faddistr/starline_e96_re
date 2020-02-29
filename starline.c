#include <stdio.h>
#include <string.h>
#include "starline.h"



uint16_t starline_gencrc(uint16_t initial, void *pData, size_t len, uint16_t bitsCount)
{
    size_t i, j;
    uint16_t crc = initial;
    uint8_t *data = (uint8_t *)pData;
    uint8_t mask = 0x80;
    uint16_t flag = 0;
    uint16_t poli = (1<<(bitsCount - 1));


    for (i = 0; i < len; i++) {
        mask = 0x80;
        for (j = 0; j < 8; j++)
        {
            if (mask & data[i])
            {
                crc ^= poli;
            }

            mask = mask >> 1;
            flag = 0;
            if (poli & crc)
            {
                flag = (bitsCount == 16)?0x1021U:7U;
            }

            crc = flag ^ (crc << 1);
        }
    }

    return crc;
}

void starline_form_hdr_request(starline_cmd_hdr_t *dst, uint32_t function_id, uint8_t payload_size)
{
    dst->magic_aa = STARLINE_HEADER_MAGIC;
    dst->type = STARLINE_TYPE_REQUEST;
    dst->function_id = function_id;
    dst->payload_size = payload_size;
    dst->hdr_crc = (uint8_t)starline_gencrc(0xff, dst, sizeof(*dst) - sizeof(dst->hdr_crc), 8);
}

static void starline_write_region_gen(starline_cmd_t *cmd, uint8_t mask)
{
    starline_form_hdr_request(&cmd->hdr, STARLINE_WRITE_MEMORY_REGION_ID, sizeof(starline_cmd_write_reg_payload_t) - sizeof(cmd->write_reg.payload_crc));
    cmd->write_reg.regId = STARLINE_WRITE_MAGIC_NUMBER;
    cmd->write_reg.addr = STARLINE_WRITE_MEMORY_ADDR;
    cmd->write_reg.value = mask;
    cmd->write_reg.payload_crc = starline_gencrc(0xFFFF,&cmd->write_reg, sizeof(starline_cmd_write_reg_payload_t) - sizeof(cmd->write_reg.payload_crc), 16);
}

static void starline_send_unlock_gen(starline_cmd_t *cmd, uint8_t regId)
{
    starline_form_hdr_request(&cmd->hdr, STARLINE_UNLOCK_ID, sizeof(starline_cmd_unlock_payload_t) - sizeof(cmd->unlock.payload_crc));
    cmd->unlock.regId = regId;
    cmd->unlock.payload_crc = starline_gencrc(0xFFFF,&cmd->unlock, sizeof(starline_cmd_unlock_payload_t) - sizeof(cmd->unlock.payload_crc), 16);
}

static void starline_send_eof_gen(starline_cmd_t *cmd, uint8_t regId)
{
    starline_form_hdr_request(&cmd->hdr, STARLINE_SEND_EOF_ID, sizeof(starline_cmd_unlock_payload_t) - sizeof(cmd->unlock.payload_crc));
    cmd->unlock.regId = regId;
    cmd->unlock.payload_crc = starline_gencrc(0xFFFF,&cmd->unlock, sizeof(starline_cmd_unlock_payload_t) - sizeof(cmd->unlock.payload_crc), 16);
}

static void starline_enter_pin_gen(starline_cmd_t *cmd, uint16_t pin)
{
    starline_form_hdr_request(&cmd->hdr, STARLINE_ENTER_PIN_ID, sizeof(starline_cmd_pin_payload_t) - sizeof(cmd->pin.payload_crc));
    cmd->pin.pin = pin;
    cmd->pin.payload_crc = starline_gencrc(0xFFFF,&cmd->pin, sizeof(starline_cmd_pin_payload_t) - sizeof(cmd->pin.payload_crc), 16);
}


int32_t starline_send_unlock_cmd_gen(starline_cmd_t *cmd)
{
    if (cmd == NULL)
    {
        return -1;
    }

    starline_send_unlock_gen(cmd, STARLINE_WRITE_MAGIC_NUMBER);
    return (sizeof(cmd->hdr) + sizeof(cmd->unlock));
}

int32_t starline_send_eof_cmd_gen(starline_cmd_t *cmd)
{
    if (cmd == NULL)
    {
        return -1;
    }

    starline_send_eof_gen(cmd, STARLINE_WRITE_MAGIC_NUMBER);
    return (sizeof(cmd->hdr) + sizeof(cmd->unlock));
}


int32_t starline_arm_cmd_gen(starline_cmd_t *cmd)
{
    if (cmd == NULL)
    {
        return -1;
    }

    starline_write_region_gen(cmd, STARLINE_ARM_CMD);
    return (sizeof(cmd->hdr) + sizeof(cmd->write_reg));
}

int32_t starline_disarm_cmd_gen(starline_cmd_t *cmd)
{
    if (cmd == NULL)
    {
        return -1;
    }

    starline_write_region_gen(cmd, STARLINE_DISARM_CMD);
    return (sizeof(cmd->hdr) + sizeof(cmd->write_reg));
}

int32_t starline_start_engine_cmd_gen(starline_cmd_t *cmd)
{
    if (cmd == NULL)
    {
        return -1;
    }

    starline_write_region_gen(cmd, STARLINE_ENGINE_START_CMD);
    return (sizeof(cmd->hdr) + sizeof(cmd->write_reg));
}

int32_t starline_stop_engine_cmd_gen(starline_cmd_t *cmd)
{
    if (cmd == NULL)
    {
        return -1;
    }

    starline_write_region_gen(cmd, STARLINE_ENGINE_STOP_CMD);
    return (sizeof(cmd->hdr) + sizeof(cmd->write_reg));
}

int32_t starline_send_pin_cmd_gen(starline_cmd_t *cmd, uint16_t pin)
{
    if (cmd == NULL)
    {
        return -1;
    }

    starline_enter_pin_gen(cmd, pin);
    return (sizeof(cmd->hdr) + sizeof(cmd->pin));
}

static starline_errors_t starline_check_answ_hdr(starline_cmd_hdr_t *answ_hdr)
{
    uint8_t crc8;
    if (answ_hdr->magic_aa != STARLINE_HEADER_MAGIC)
    {
        return STARLINE_BAD_HDR;
    }

    if (answ_hdr->type != STARLINE_TYPE_ANSWER)
    {
       return STARLINE_BAD_HDR;
    }

    crc8 = (uint8_t)starline_gencrc(0xff, answ_hdr, sizeof(*answ_hdr) - sizeof(answ_hdr->hdr_crc), 8);
    if (crc8 != answ_hdr->hdr_crc)
    {
        return STARLINE_BAD_HDR_CRC;
    }

    return STARLINE_OK;
}

static starline_process_packet_state_t starline_wait_full_hdr(startline_hnd_t *ihnd, uint8_t byte)
{
    starline_errors_t res;
    uint8_t *ptr8 = (uint8_t *)&ihnd->packet.hdr;

    ptr8[ihnd->counter] = byte;
    ihnd->counter++;
    if (ihnd->counter != sizeof(starline_cmd_hdr_t))
    {
        return STARLINE_WAIT_FULL_HEADER;
    }

    res = starline_check_answ_hdr(&ihnd->packet.hdr);
    if (res != STARLINE_OK)
    {
        if (ihnd->cb.on_error != NULL)
        {
            ihnd->cb.on_error(ihnd, &ihnd->packet, res);
        }
        return STARLINE_WAIT_NEW_PACKET;
    }

    if (ihnd->packet.hdr.payload_size == 0)
    {
        if (ihnd->cb.on_data_packet != NULL)
        {
            ihnd->cb.on_data_packet(ihnd, &ihnd->packet);
        }

        return STARLINE_WAIT_NEW_PACKET;
    }

    ihnd->counter = 0;
    return STARLINE_WAIT_PAYLOAD;
}

static starline_read_region_result_t starline_process_status_packet(startline_hnd_t *ihnd, starline_packet_t *packet)
{
    switch(ihnd->status_packet_state)
    {
        case STARLINE_WAIT_FOR_REGION_06:
            memcpy(&ihnd->status_packet.hdr, &packet->hdr, sizeof(packet->hdr));
            memcpy(&ihnd->status_packet.payload, packet->payload, packet->hdr.payload_size);
            return STARLINE_WAIT_FOR_REGION_01;

        case STARLINE_WAIT_FOR_REGION_01:
            memcpy(&ihnd->status_packet.payload[ihnd->status_packet.hdr.payload_size], packet->payload, packet->hdr.payload_size);
            ihnd->status_packet.hdr.payload_size += packet->hdr.payload_size;
            if (ihnd->cb.on_status_packet != NULL)
            {
                ihnd->cb.on_status_packet(ihnd, &ihnd->status_packet);
            }
            break;

        default:
            break;

    }

    return  STARLINE_WAIT_FOR_REGION_06;
}

static starline_process_packet_state_t starline_wait_payload(startline_hnd_t *ihnd, uint8_t byte)
{
    uint16_t *crc16 = (uint16_t *)&ihnd->packet.payload[ihnd->packet.hdr.payload_size];

    ihnd->packet.payload[ihnd->counter] = byte;
    ihnd->counter++;
    if (ihnd->counter != ihnd->packet.hdr.payload_size + sizeof(*crc16))
    {
       return STARLINE_WAIT_PAYLOAD;
    }

    if (1)//(*crc16 == starline_gencrc(0xFFFF, ihnd->packet.payload, ihnd->packet.hdr.payload_size, 16))
    {
        if (ihnd->packet.hdr.function_id == STARLINE_READ_MEMORY_REGION_ANSW_ID)
        {
            ihnd->status_packet_state = starline_process_status_packet(ihnd, &ihnd->packet);
            return STARLINE_WAIT_NEW_PACKET;
        }


        if (ihnd->cb.on_data_packet != NULL)
        {
            ihnd->cb.on_data_packet(ihnd, &ihnd->packet);
        }
    } else
    {
        if (ihnd->cb.on_error != NULL)
        {
            ihnd->cb.on_error(ihnd, &ihnd->packet, STARLINE_BAD_PAYLOAD_CRC);
        }
    }

    return STARLINE_WAIT_NEW_PACKET;
}


static void starline_process_byte(startline_hnd_t *ihnd, uint8_t byte)
{
    switch (ihnd->packet_state)
    {
        case STARLINE_WAIT_NEW_PACKET:
            if (byte == STARLINE_HEADER_MAGIC)
            {
                memset(&ihnd->packet, 0x00, sizeof(ihnd->packet));
                ihnd->counter = 0;
                ihnd->packet_state = starline_wait_full_hdr(ihnd, byte);
            }
            break;

        case STARLINE_WAIT_FULL_HEADER:
            ihnd->packet_state = starline_wait_full_hdr(ihnd, byte);
            break;

        case STARLINE_WAIT_PAYLOAD:
            ihnd->packet_state = starline_wait_payload(ihnd, byte);
            break;

        default:
            ihnd->packet_state = STARLINE_WAIT_NEW_PACKET;
            break;
    }
}

starline_errors_t starline_proccess_next_packet(startline_hnd_t *ihnd, void *data, uint8_t size)
{
    uint8_t *ptr8 = (uint8_t *)data;

    if ((ihnd == NULL) || (data == NULL) || (size == 0))
    {
        return STARLINE_INVALID_ARG;
    }

    while(size--)
    {
        starline_process_byte(ihnd, *ptr8++);
    }

    return STARLINE_OK;
}
starline_errors_t starline_reset(startline_hnd_t *ihnd)
{
  if (ihnd == NULL)
  {
      return STARLINE_INVALID_ARG;
  }

  ihnd->status_packet_state = STARLINE_WAIT_FOR_REGION_06;
  return STARLINE_OK;
}

starline_errors_t starline_set_cb(startline_hnd_t *ihnd, startline_cb_t *cbs)
{

    if ((ihnd == NULL) || (cbs == NULL))
    {
        return STARLINE_INVALID_ARG;
    }


    ihnd->cb = *cbs;
    return STARLINE_OK;
}
