#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <freertos/FreeRTOS.h>

#include "tlv.h"

#define TLV_TYPE_INDEX 0
#define TLV_LENGTH_INDEX 1
#define TLV_VALUE_INDEX 2
#define TLV_HEADER_LENGTH 2

#define TLV_MAX_FRAGMENTATION_SIZE   0xff

#define tlv_for_each(pos, start, bound) \
    for (pos = start; \
         pos <= bound; \
         pos += TLV_HEADER_LENGTH + pos[TLV_LENGTH_INDEX])

static uint8_t* _item_find(uint8_t* start, int length, uint8_t type) 
{
    uint8_t* pos;
    tlv_for_each(pos, start, start + length -1) {
        if (pos[TLV_TYPE_INDEX] == type) {
            return pos;
        }
    }

    return NULL;
}

static int _item_length(uint8_t* item, uint8_t* bound)
{
    int type = item[TLV_TYPE_INDEX];
    int tlv_length = TLV_HEADER_LENGTH;

    uint8_t* pos;
    tlv_for_each(pos, item, bound) {
        if (pos[TLV_TYPE_INDEX] == type)
            tlv_length += pos[TLV_LENGTH_INDEX];
        else
            break;
    }

    return tlv_length;
}

static struct tlv* _defragmentation(uint8_t* item, uint8_t* bound) 
{
    int tlv_item_length = _item_length(item, bound);
    //printf("[TLV] tlv_item_length:%d\n", tlv_item_length);
    struct tlv* tlv = malloc(sizeof(struct tlv) + tlv_item_length);
    if (tlv == NULL) {
        printf("[TLV] malloc failed. %d\n", sizeof(struct tlv) + tlv_item_length);
        return NULL;
    }

    tlv->type = item[TLV_TYPE_INDEX];
    tlv->length = tlv_item_length - TLV_HEADER_LENGTH;

    uint8_t* pos;
    uint8_t* tlv_value_ptr = (uint8_t*)&tlv->value;
    tlv_for_each(pos, item, bound) {
        if (pos[TLV_TYPE_INDEX] == tlv->type) {
            memcpy(tlv_value_ptr, &pos[TLV_VALUE_INDEX], pos[TLV_LENGTH_INDEX]);
            tlv_value_ptr += pos[TLV_LENGTH_INDEX];
        }
        else 
            break;
    }

    return tlv;
}

struct tlv* tlv_decode(uint8_t* msg, int msg_len, uint8_t type)
{
    uint8_t* item = _item_find(msg, msg_len, type);
    if (item == NULL) {
        return NULL;
    }

    return _defragmentation(item, msg + msg_len -1);
}

void tlv_decoded_item_free(struct tlv* tlv_item)
{
    if (!tlv_item)
        return;

    free(tlv_item);
}

int tlv_encode_length(int value_length)
{
    return value_length + TLV_HEADER_LENGTH + 
        (value_length / (TLV_MAX_FRAGMENTATION_SIZE+1)) * TLV_HEADER_LENGTH;
}

int tlv_encode(uint8_t type, int length, uint8_t* value, uint8_t* item)
{
    int nr_fragment = length / TLV_MAX_FRAGMENTATION_SIZE + 1;

    while (nr_fragment-- > 1) {
        item[TLV_TYPE_INDEX] = type;
        item[TLV_LENGTH_INDEX] = TLV_MAX_FRAGMENTATION_SIZE;
        memcpy(&item[TLV_VALUE_INDEX], value, TLV_MAX_FRAGMENTATION_SIZE);

        value += TLV_MAX_FRAGMENTATION_SIZE;
        item += TLV_MAX_FRAGMENTATION_SIZE + TLV_HEADER_LENGTH;
    }

    item[TLV_TYPE_INDEX] = type;
    item[TLV_LENGTH_INDEX] = length % TLV_MAX_FRAGMENTATION_SIZE;
    memcpy(&item[TLV_VALUE_INDEX], value, item[TLV_LENGTH_INDEX]);

    return tlv_encode_length(length);
}
