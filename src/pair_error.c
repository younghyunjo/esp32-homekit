#include <stdint.h>
#include <stdlib.h>
#include <esp_log.h>

#include "hap.h"
#include "hap_internal.h"
#include "tlv.h"

#define TAG "PAIR_ERROR"

#define CHUNK_RESPONSE_DEFALT_META_LENGTH  16

int pair_error(enum hap_tlv_error_codes error_codes, 
        uint8_t** acc_msg, int* acc_msg_length)
{
    uint8_t error[] = {error_codes};
    *acc_msg_length =tlv_encode_length(sizeof(error));

    (*acc_msg) = malloc(*acc_msg_length);
    if (*acc_msg == NULL) {
        ESP_LOGE(TAG, "malloc failed. size:%d\n", *acc_msg_length);
        return -1;
    }

    uint8_t* tlv_encode_ptr = *acc_msg;
    tlv_encode_ptr += tlv_encode(HAP_TLV_TYPE_ERROR, sizeof(error), error, tlv_encode_ptr);

    return 0;
}

void pair_error_free(uint8_t* error_msg)
{
    if (error_msg)
        free(error_msg);
}
