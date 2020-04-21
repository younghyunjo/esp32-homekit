#ifndef _HAP_ACCESSORIES_H_
#define _HAP_ACCESSORIES_H_

#ifdef __cplusplus
extern "C" {
#endif

/**
 *
 * @param ev
 * @param value
 * @param res_header
 * @param res_header_len
 * @param res_body Must be freed upon making this call.
 * @param res_body_len Must be freed upon making this call.
 */
void hap_acc_event_response(struct hap_event* ev, void* value,
        char** res_header, int* res_header_len, char** res_body, int* res_body_len);

/**
 *
 * @param a
 * @param query
 * @param len
 * @param res_header
 * @param res_header_len
 * @param res_body Must be freed upon making this call.
 * @param res_body_len Must be freed upon making this call.
 * @return
 */
int hap_acc_characteristic_get(struct hap_accessory* a, char* query, int len,
        char** res_header, int* res_header_len, char** res_body, int* res_body_len);

/**
 *
 * @param a
 * @param ev_handle
 * @param req_body
 * @param req_body_len
 * @param res_header
 * @param res_header_len
 * @param res_body Must be freed upon making this call.
 * @param res_body_len Must be freed upon making this call.
 * @return
 */
int hap_acc_characteristic_put(struct hap_accessory* a, void* ev_handle, char* req_body,
        int req_body_len, char** res_header, int* res_header_len, char** res_body, int* res_body_len);

/**
 *
 * @param a
 * @param res_header
 * @param res_header_len
 * @param res_body Must be freed upon making this call.
 * @param res_body_len Must be freed upon making this call.
 * @return
 */
int hap_acc_accessories_do(struct hap_accessory* a, char** res_header,
        int* res_header_len, char** res_body, int* res_body_len);

void* hap_acc_accessory_add(void* acc_instance);

void* hap_acc_service_and_characteristics_add(
        void* _attr_a, enum hap_service_type type, struct hap_characteristic* cs, int nr_cs);

#ifdef __cplusplus
}
#endif

#endif //#ifndef _HAP_ACCESSORIES_H_
