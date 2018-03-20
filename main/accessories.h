#ifndef _HAP_ACCESSORIES_H_
#define _HAP_ACCESSORIES_H_

#ifdef __cplusplus
extern "C" {
#endif

int hap_acc_characteristic_get(struct hap_accessory* a, char* query, int len, char** res_header, int* res_header_len, char** res_body, char* res_body_len);
void hap_acc_characteristic_get_free(char* res_header, char* res_body);

int hap_acc_characteristic_put(struct hap_accessory* a, void* ev_handle, char* req_body, int req_body_len, char** res_header, int* res_header_len, char** res_body, char* res_body_len);
void hap_acc_characteristic_put_free(char* res_header, char* res_body);

int hap_acc_accessories_do(struct hap_accessory* a, char** res_header, int* res_header_len, char** res_body, int* res_body_len);
void hap_acc_accessories_do_free(char* res_header, char* res_body);

void* hap_acc_accessory_add(void* acc_instance);
void* hap_acc_service_and_characteristics_add(void* acc_instance, void* _attr_a,
        enum hap_service_type type, struct hap_attr_character* cs, int nr_cs); 

#ifdef __cplusplus
}
#endif

#endif //#ifndef _HAP_ACCESSORIES_H_
