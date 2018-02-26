#include <esp_log.h>
#include <wolfssl/wolfcrypt/hmac.h>

#include "hkdf.h"

#define TAG "HKDF"

struct hkdf_salt_info {
    char* salt;
    char* info;
};

static struct hkdf_salt_info _hkdf_salt_info[] = {
    {   /* HKDF_KEY_TYPE_PAIR_SETUP_ENCRYPT */
        .salt = "Pair-Setup-Encrypt-Salt",
        .info = "Pair-Setup-Encrypt-Info",
    },
    {   /* HKDF_KEY_TYPE_PAIR_SETUP_CONTROLLER */
        .salt = "Pair-Setup-Controller-Sign-Salt",
        .info = "Pair-Setup-Controller-Sign-Info",
    },
    {   /* HKDF_KEY_TYPE_PAIR_SETUP_ACCESSORY */
        .salt = "Pair-Setup-Accessory-Sign-Salt",
        .info = "Pair-Setup-Accessory-Sign-Info",
    },
    {   /* HKDF_KEY_TYPE_PAIR_VERIFY_ENCRYPT */
        .salt = "Pair-Verify-Encrypt-Salt",
        .info = "Pair-Verify-Encrypt-Info",
    },
    {   /* HKDF_KEY_TYPE_CONTROL_READ */
        .salt = "Control-Salt",
        .info = "Control-Read-Encryption-Key",
    },
    {   /* HKDF_KEY_TYPE_CONTROL_WRITE */
        .salt = "Control-Salt",
        .info = "Control-Write-Encryption-Key",
    }
};

static struct hkdf_salt_info* _salt_info_get(enum hkdf_key_type type)
{
    return &_hkdf_salt_info[type];
}

int hkdf_key_get(enum hkdf_key_type type, uint8_t* inkey, int inkey_len, uint8_t* outkey)
{
    uint8_t key[CHACHA20_POLY1305_AEAD_KEYSIZE];
    struct hkdf_salt_info* salt_info = _salt_info_get(type);

    int err = wc_HKDF(SHA512, inkey, inkey_len, 
            (uint8_t*)salt_info->salt, strlen(salt_info->salt), 
            (uint8_t*)salt_info->info, strlen(salt_info->info),
            key, CHACHA20_POLY1305_AEAD_KEYSIZE);

    if (err < 0) {
        ESP_LOGE(TAG, "wc_HKDF failed. %d\n", err);
        return err;
    }

    memcpy(outkey, key, CHACHA20_POLY1305_AEAD_KEYSIZE);
    return 0;
}

