#ifndef _TLV8_H_
#define _TLV8_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

struct tlv {
    uint8_t type;
    int length;
    uint8_t* value;
};

struct tlv* tlv_decode(uint8_t* msg, int msg_len, uint8_t type);
void tlv_decoded_item_free(struct tlv* tlv_item);

int tlv_encode_length(int value_length);
int tlv_encode(uint8_t type, int length, uint8_t* value, uint8_t* encoded);

#ifdef __cplusplus
}
#endif

#endif //#ifndef _TLV8_H_
