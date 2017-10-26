#ifndef _TLV8_H_
#define _TLV8_H_

#ifdef __cplusplus
extern "C" {
#endif

struct tlv {
    uint8_t type;
    uint8_t length;
    uint8_t* value;
};

struct tlv* tlv_item_get(uint8_t* msg, int msg_len, uint8_t type);
void tlv_item_free(struct tlv* tlv_item);

#ifdef __cplusplus
}
#endif

#endif //#ifndef _TLV8_H_
