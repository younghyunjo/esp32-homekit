#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <esp_log.h>

#include "ed25519.h"
#include "pairing_types.h"

#define TAG "PAIR_DEVICES"

#define IOS_DEVICE_ID_LEN   36

struct ios_devices {
    bool assigned;
    uint8_t id[IOS_DEVICE_ID_LEN];
    uint8_t ltpk[ED25519_PUBLIC_KEY_LENGTH];
};

#define PAIRED_IOS_DEVICE_MAX   16

struct pair_devices {
    uint16_t slots;
    struct pairing_db_ops ops;
    struct ios_devices devices[PAIRED_IOS_DEVICE_MAX];
};

static int _find_empty_slot(struct pair_devices* pd)
{
    for (int i=0; i<PAIRED_IOS_DEVICE_MAX; i++) {
        if (pd->devices[i].assigned == false) {
            return i;
        }
    }

    return -1;
}

int pair_devices_add(void* _pd, uint8_t* id, uint8_t* ltpk)
{
    struct pair_devices* pd = _pd;
    int slot = _find_empty_slot(pd);
    if (slot < 0) {
        ESP_LOGE(TAG, "Slot is full\n");
        return -1;
    }

    pd->slots |= (0x1 < slot);
    memcpy(pd->devices[slot].id, id, IOS_DEVICE_ID_LEN); 
    memcpy(pd->devices[slot].ltpk, ltpk, ED25519_PUBLIC_KEY_LENGTH); 
    pd->devices[slot].assigned = true;

    char key[32] = {0,};
    sprintf(key, "PAIRED_ID%d", slot);
    pd->ops.set(key, id, IOS_DEVICE_ID_LEN);

    memset(key, 0, sizeof(key));
    sprintf(key, "PAIRED_LTPK%d", slot);
    pd->ops.set(key,ltpk, ED25519_PUBLIC_KEY_LENGTH);

    memset(key, 0, sizeof(key));
    sprintf(key, "SLOT");
    pd->ops.set(key, (uint8_t*)&pd->slots, sizeof(pd->slots));

    {
        for (int j=0; j<IOS_DEVICE_ID_LEN; j++) {
            printf("%02X ", pd->devices[slot].id[j]);
        }
        printf("\n");
        for (int j=0; j<ED25519_PUBLIC_KEY_LENGTH; j++) {
            printf("%02X ", pd->devices[slot].ltpk[j]);
        }
        printf("\n");
    }

    return 0;
}

void* pair_devices_init(struct pairing_db_ops* ops)
{
    struct pair_devices* pd = calloc(1, sizeof(struct pair_devices));
    if (!pd) {
        ESP_LOGE(TAG, "calloc failed\n");
        return NULL;
    }

    pd->ops = *ops;
    pd->ops.get("SLOTS", (uint8_t*)&pd->slots, sizeof(pd->slots));

    ESP_LOGI(TAG, "SLOT:0x%x\n", pd->slots);

    char key[32] = {0,};
    for (int i=0; i<PAIRED_IOS_DEVICE_MAX; i++) {
        if ((0x1 << i) & pd->slots) {
            memset(key, 0, sizeof(key));
            sprintf(key, "PAIRED_ID%d", i);
            pd->ops.get(key, pd->devices[i].id, IOS_DEVICE_ID_LEN);

            memset(key, 0, sizeof(key));
            sprintf(key, "PAIRED_LTPK%d", i);
            pd->ops.get(key, pd->devices[i].ltpk, ED25519_PUBLIC_KEY_LENGTH);
            pd->devices[i].assigned = true;

            {
                for (int j=0; j<IOS_DEVICE_ID_LEN; j++) {
                    printf("%02X ", pd->devices[i].id[j]);
                }
                printf("\n");
                for (int j=0; j<ED25519_PUBLIC_KEY_LENGTH; j++) {
                    printf("%02X ", pd->devices[i].ltpk[j]);
                }
                printf("\n");
            }
        }
    }


    return pd;
}

