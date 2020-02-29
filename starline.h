#ifndef STARLINE_H
#define STARLINE_H
#include <stdint.h>

#define STARLINE_PACKET_SIZE (64U)
#define STARLINE_PINCODE_LEN (4U)
#define STARLINE_MAX_PAYLOAD_SIZE (255U + sizeof(uint16_t)) //+crc16

#define STARLINE_EPOCH_START_OFFSET (1325376000UL) //01.01.2012 00:00

#define STARLINE_FAILED ((uint8_t)0xFF)


#define STARLINE_HEADER_MAGIC (uint8_t)(0xAAU)
#define STARLINE_TYPE_REQUEST (uint16_t)(0x1101U)
#define STARLINE_TYPE_ANSWER  (uint16_t)(0x0111U)

#define STARLINE_UNLOCK_ID                (uint8_t)(0x05U) //should be send before any commands, open region
#define STARLINE_SEND_EOF_ID              (uint8_t)(0x06U)
#define STARLINE_WRITE_MEMORY_REGION_ID   (uint8_t)(0x08U)
#define STARLINE_ENTER_PIN_ID             (uint8_t)(0x0DU)
#define STARLINE_READ_MEM_ID              (uint8_t)(0x09U)


#define STARLINE_READ_MEMORY_REGION_ANSW_ID   (uint8_t)(0x89U)
#define STARLINE_SUCCESS_MASK (uint8_t)(0x80U)

#define STARLINE_WRITE_MEMORY_ADDR (uint32_t)(0x00000200U)
#define STARLINE_WRITE_MAGIC_NUMBER (uint8_t)(0x4fU)

#define STARLINE_ARM_CMD           (uint8_t)(0x01U)
#define STARLINE_DISARM_CMD        (uint8_t)(0x02U)
#define STARLINE_ENGINE_START_CMD  (uint8_t)(0x03U)
#define STARLINE_ENGINE_STOP_CMD   (uint8_t)(0x04U)


typedef enum
{
    STARLINE_OK,
    STARLINE_INVALID_ARG,
    STARLINE_BAD_HDR,
    STARLINE_BAD_HDR_CRC,
    STARLINE_BAD_PAYLOAD_CRC,
} starline_errors_t;

#pragma pack(push, 1)

typedef struct
{
    uint8_t  magic_aa;
    uint16_t type;
    uint8_t  function_id; //function_id + magic number
    uint8_t  reserved0;    //unknown, always 0
    uint8_t  payload_size; //additional payload size if any
    uint8_t  reserved1;    //reserved for second byte of size, always 0
    uint8_t  hdr_crc;      //crc 8 bits of the header
}  __attribute__((packed)) starline_cmd_hdr_t;

typedef struct
{
    uint8_t            regId;
    uint32_t           addr;       //unknown member, always 0x00020000U, perhaps destination in RAM
    uint8_t            value;      //value to write
    uint16_t           payload_crc;//crc 16 bits of the payload
}  __attribute__((packed)) starline_cmd_write_reg_payload_t;

typedef struct
{
    uint8_t            regId;
    uint16_t           payload_crc;//crc 16 bits of the payload
}  __attribute__((packed)) starline_cmd_unlock_payload_t;

typedef struct
{
    uint16_t           pin; //yep, this is raw hex values :)
    uint16_t           payload_crc;//crc 16 bits of the payload
}  __attribute__((packed)) starline_cmd_pin_payload_t;

typedef struct
{
    starline_cmd_hdr_t  hdr;        //header
    union
    {
        starline_cmd_write_reg_payload_t write_reg;
        starline_cmd_unlock_payload_t    unlock; //write eof
        starline_cmd_pin_payload_t       pin;
    };
} __attribute__((packed)) starline_cmd_t;

typedef struct
{
    starline_cmd_hdr_t  hdr;        //header
    uint8_t             regid; //always 4F
    uint8_t             magic; //always 1
    uint8_t             res[3];
    uint16_t            data[23];
    uint16_t            rpm;
    uint16_t            payload_crc;//crc 16 bits of the payload
} __attribute__((packed)) starline_read_reg_answ_even_t;


typedef struct
{
    starline_cmd_hdr_t  hdr;        //header
    uint8_t             regid; //always 4F
    uint8_t             magic; //always 6
    uint8_t             res[3];
    uint8_t             data[75];
    uint16_t            payload_crc;//crc 16 bits of the payload
} __attribute__((packed)) starline_read_reg_answ_odd_t;

typedef struct
{
    starline_read_reg_answ_odd_t   odd;
    starline_read_reg_answ_even_t  even;
} __attribute__((packed)) starline_answer_read_full_t;

typedef struct
{
    starline_cmd_hdr_t  hdr;
    uint8_t payload[STARLINE_MAX_PAYLOAD_SIZE];
} __attribute__((packed)) starline_packet_t;

#define STARLINE_ALARM_STATUS_ON_MASK ((uint8_t)0x80)
#define STARLINE_ALARM_MASK ((uint8_t)0x73)
typedef struct
{
    uint8_t             regid_prime; //always 4F //0
    uint32_t            sub_regid_prime; // 1  //alway 6
    uint16_t            packet_counter_unk;  // 5
    uint16_t            unk_data;  // 5
    uint32_t            timestamp;//timestamp from 01/01/2012 00:00 (1325376000) //9
    uint8_t             data_prime_unk01[3]; // 12
    uint8_t             status_unk; // 15
    uint8_t             data_prime_unk02[3]; //16
    uint8_t             ign; // 19
    uint8_t             data_prime_unk03[4]; //20
    uint8_t             alarm_status; //24,
    uint8_t             data_prime_unk04[14]; //25
    int8_t              temp_engine_prime; // 39
    uint8_t             data_prime_unk05; // 40
    int8_t              temp_int_prime; // 41
    uint8_t             data_prime_unk06[4]; //42
    uint8_t             fuel_min_value;//46, not sure
    uint8_t             fuel_max_value;//47, not sure
    uint8_t             fuel_delta_value;//48, not sure
    uint8_t             data_prime_unk07; //49
    uint16_t            accum_mV; //50, milivolts
    uint8_t             step_unk;//52
    uint8_t             data_prime_unk09[8]; //53
    uint8_t             diag_flags; //61 //unk
    uint8_t             data_prime_unk10[15]; //62
    uint8_t             regid_sec; //always 4F
    uint32_t            subregid_sec; //always 1
    uint8_t             data_sec_unk00[33];
    int8_t              temp_engine;
    uint8_t             data_sec_unk01;
    int8_t              temp_int;
    uint8_t             data_sec_unk02[10];
    uint16_t            rpm;
} __attribute__((packed)) starline_status_t;

typedef struct
{
    starline_cmd_hdr_t  hdr;
    union
    {
        uint8_t payload[STARLINE_MAX_PAYLOAD_SIZE];
        starline_status_t status;
    };
} __attribute__((packed)) starline_status_packet_t;




#pragma pack(pop)


typedef enum
{
    STARLINE_WAIT_NEW_PACKET,
    STARLINE_WAIT_FULL_HEADER,
    STARLINE_WAIT_PAYLOAD,
} starline_process_packet_state_t;

typedef enum
{
    STARLINE_WAIT_FOR_REGION_06,
    STARLINE_WAIT_FOR_REGION_01,
} starline_read_region_result_t;




typedef struct
{
    void (*on_data_packet)(void *hnd, starline_packet_t *packet);
    void (*on_status_packet)(void *hnd, starline_status_packet_t *packet);
    void (*on_error)(void *hnd, starline_packet_t *packet, starline_errors_t error);
} startline_cb_t;

typedef struct
{
    starline_process_packet_state_t packet_state;
    starline_packet_t packet;
    starline_status_packet_t status_packet;
    starline_read_region_result_t status_packet_state;
    uint16_t counter;
    startline_cb_t cb;
} startline_hnd_t;



uint16_t starline_gencrc(uint16_t initial, void *pData, size_t len, uint16_t bitsCount);
int32_t starline_start_engine_cmd_gen(starline_cmd_t *cmd);
int32_t starline_stop_engine_cmd_gen(starline_cmd_t *cmd);
int32_t starline_arm_cmd_gen(starline_cmd_t *cmd);
int32_t starline_disarm_cmd_gen(starline_cmd_t *cmd);
int32_t starline_send_unlock_cmd_gen(starline_cmd_t *cmd);
int32_t starline_send_eof_cmd_gen(starline_cmd_t *cmd);
int32_t starline_send_pin_cmd_gen(starline_cmd_t *cmd, uint16_t pin);
void starline_form_hdr_request(starline_cmd_hdr_t *dst, uint32_t function_id, uint8_t payload_size);


starline_errors_t starline_proccess_next_packet(startline_hnd_t *ihnd, void *data, uint8_t size);
starline_errors_t starline_set_cb(startline_hnd_t *ihnd, startline_cb_t *cbs);
starline_errors_t starline_reset(startline_hnd_t *ihnd);

#endif // STARLINE_H
