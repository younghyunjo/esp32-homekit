#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "tlv.h"

#define TLV_TYPE_INDEX 0
#define TLV_LENGTH_INDEX 1
#define TLV_VALUE_INDEX 2
#define TLV_HEADER_LENGTH 2

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
    int tlv_length = _item_length(item, bound);
    struct tlv* tlv = malloc(tlv_length);

    tlv->type = item[TLV_TYPE_INDEX];
    tlv->length = tlv_length - TLV_HEADER_LENGTH;

    uint8_t* pos;
    int value_index = 0;
    tlv_for_each(pos, item, bound) {
        if (pos[TLV_TYPE_INDEX] == tlv->type) {
            memcpy(&tlv->value + value_index, &pos[TLV_VALUE_INDEX],
                    pos[TLV_LENGTH_INDEX]);
            value_index += pos[TLV_LENGTH_INDEX];
        }
        else 
            break;
    }

    return tlv;
}

struct tlv* tlv_item_get(uint8_t* msg, int msg_len, uint8_t type)
{
    uint8_t* item = _item_find(msg, msg_len, type);
    if (item == NULL) {
        return NULL;
    }

    return _defragmentation(item, msg + msg_len -1);
}

void tlv_item_free(struct tlv* tlv_item)
{
    if (!tlv_item)
        return;

    free(tlv_item);
}
