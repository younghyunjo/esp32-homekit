#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ed25519.h"
#include "iosdevice.h"
#include "nvs.h"

#define ACCESSORY_ID_COMPACT_LEN    12
struct iosdevice_pairings {
    char id[ACCESSORY_ID_COMPACT_LEN];
    int nr_iosdevices;
    struct {
        int slot;
        char id[IOSDEVICE_ID_LEN];
        char key[ED25519_PUBLIC_KEY_LENGTH];
    } iosdevices[IOSDEVICE_PER_ACCESSORY_MAX];
};

static int _pairing_match(void* handle, char id[], char key[])
{
    struct iosdevice_pairings *ipairings = (struct iosdevice_pairings*)handle;
    for (int i=0; i<IOSDEVICE_PER_ACCESSORY_MAX; i++) {
        if (ipairings->iosdevices[i].slot == -1)
            continue;
        if (memcmp(ipairings->iosdevices[i].id, id, IOSDEVICE_ID_LEN) != 0)
            continue;
        if (memcmp(ipairings->iosdevices[i].key, key, ED25519_PUBLIC_KEY_LENGTH) != 0)
            continue;

        return i;
        }

    return -1;
}

static int _pairing_match_with_id(void* handle, char id[])
{
    struct iosdevice_pairings *ipairings = (struct iosdevice_pairings*)handle;
    for (int i=0; i<IOSDEVICE_PER_ACCESSORY_MAX; i++) {
        if (ipairings->iosdevices[i].slot == -1)
            continue;
        if (memcmp(ipairings->iosdevices[i].id, id, IOSDEVICE_ID_LEN) != 0)
            continue;
        return i;
    }

    return -1;
}

int iosdevice_pairings(void* handle, struct iosdevice *idevice)
{
    struct iosdevice_pairings *ipairings = (struct iosdevice_pairings*)handle;
    int nr_paired_device = 0;

    for (int i=0; i<IOSDEVICE_PER_ACCESSORY_MAX; i++) {
        if (ipairings->iosdevices[i].slot == -1)
            continue;

        memcpy(idevice[nr_paired_device].id, ipairings->iosdevices[i].id, IOSDEVICE_ID_LEN);
        memcpy(idevice[nr_paired_device].key, ipairings->iosdevices[i].key, ED25519_PUBLIC_KEY_LENGTH);
        nr_paired_device++;
    }

    return nr_paired_device;
}

int iosdevice_pairings_remove(void* handle, char id[])
{
    int slot = _pairing_match_with_id(handle, id);
    if (slot < 0) {
        printf("[ERR] no iosdevice to be removed\n");
        return -1;
    }

    struct iosdevice_pairings *ipairings = (struct iosdevice_pairings*)handle;
    ipairings->iosdevices[slot].slot = -1;
    ipairings->nr_iosdevices--;

    char nvs_key[64] = {0,};
    sprintf(nvs_key, "%sD%d", ipairings->id, slot);
    nvs_erase(nvs_key);

    return 0;
}

int iosdevice_pairings_add(void* handle, char id[], char key[])
{
    if (iosdevice_pairing_match(handle, id, key))
        return 0;

    struct iosdevice_pairings *ipairings = (struct iosdevice_pairings*)handle;
    if (ipairings->nr_iosdevices == IOSDEVICE_PER_ACCESSORY_MAX) {
        printf("[ERR] pairings are full\n");
        return -1;
    }

    for (int i=0; i<IOSDEVICE_PER_ACCESSORY_MAX; i++) {
        if (ipairings->iosdevices[i].slot == -1) {
            ipairings->iosdevices[i].slot = i;
            memcpy(ipairings->iosdevices[i].id, id, IOSDEVICE_ID_LEN);
            memcpy(ipairings->iosdevices[i].key, key, ED25519_PUBLIC_KEY_LENGTH);

            char nvs_key[64] = {0,};
            sprintf(nvs_key, "%sD%d", ipairings->id, i);

            uint8_t value[128] = {0,};
            memcpy(value, id, IOSDEVICE_ID_LEN);
            memcpy(value+IOSDEVICE_ID_LEN, key, ED25519_PUBLIC_KEY_LENGTH);

            nvs_set(nvs_key, value, IOSDEVICE_ID_LEN+ED25519_PUBLIC_KEY_LENGTH);

            ipairings->nr_iosdevices++;
            break;
        }
    }
    return 0;
}

bool iosdevice_pairing_match(void* handle, char id[], char key[])
{
    if (_pairing_match(handle, id, key) < 0) {
        return false;
    }

    return true;
}

void* iosdevice_pairings_init(char accessory_id[])
{
    uint8_t value[128] = {0,};
    char nvs_key[64] = {0,};
    struct iosdevice_pairings *ipairings = calloc(1, sizeof(struct iosdevice_pairings));

    ipairings->id[0] = accessory_id[0];
    ipairings->id[1] = accessory_id[1];
    ipairings->id[2] = accessory_id[3];
    ipairings->id[3] = accessory_id[4];
    ipairings->id[4] = accessory_id[6];
    ipairings->id[5] = accessory_id[7];
    ipairings->id[6] = accessory_id[9];
    ipairings->id[7] = accessory_id[10];
    ipairings->id[8] = accessory_id[12];
    ipairings->id[9] = accessory_id[13];
    ipairings->id[10] = accessory_id[15];
    ipairings->id[11] = accessory_id[16];


    for (int i=0; i<IOSDEVICE_PER_ACCESSORY_MAX; i++) {
        memset(nvs_key, 0, sizeof(nvs_key));
        memset(value, 0, sizeof(value));
        sprintf(nvs_key, "%sD%d", ipairings->id, i);
        //nvs_erase(nvs_key);
        if (nvs_get(nvs_key, value, IOSDEVICE_ID_LEN + ED25519_PUBLIC_KEY_LENGTH) == 0) {
            ipairings->iosdevices[i].slot = -1;
            continue;
        }

        ipairings->nr_iosdevices++;
        ipairings->iosdevices[i].slot = i;

        memcpy(ipairings->iosdevices[i].id, value, IOSDEVICE_ID_LEN);
        printf("[IOSDEVICE] ID:%.*s\n", IOSDEVICE_ID_LEN, ipairings->iosdevices[i].id);
        memcpy(ipairings->iosdevices[i].key, value+IOSDEVICE_ID_LEN, ED25519_PUBLIC_KEY_LENGTH);
    }

    return ipairings;
}
