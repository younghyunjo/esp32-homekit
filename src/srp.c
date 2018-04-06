#include <os.h>
#include <esp_log.h>
#include <wolfssl/wolfcrypt/srp.h>
#include <wolfssl/wolfcrypt/sha512.h>

#include "srp.h"

//#define DEBUG

#define TAG "SRP"

#define VERIFIER_LENGTH     384
#define PRIVATE_KEY_LENGTH  32

struct srp_desc {
    Srp wolfcrypt;
    uint8_t salt[SRP_SALT_LENGTH];
    uint8_t b[PRIVATE_KEY_LENGTH];
    uint8_t B[SRP_PUBLIC_KEY_LENGTH];
};

static const uint8_t N[] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xc9, 0x0f, 0xda, 0xa2,
    0x21, 0x68, 0xc2, 0x34, 0xc4, 0xc6, 0x62, 0x8b, 0x80, 0xdc, 0x1c, 0xd1,
    0x29, 0x02, 0x4e, 0x08, 0x8a, 0x67, 0xcc, 0x74, 0x02, 0x0b, 0xbe, 0xa6,
    0x3b, 0x13, 0x9b, 0x22, 0x51, 0x4a, 0x08, 0x79, 0x8e, 0x34, 0x04, 0xdd,
    0xef, 0x95, 0x19, 0xb3, 0xcd, 0x3a, 0x43, 0x1b, 0x30, 0x2b, 0x0a, 0x6d,
    0xf2, 0x5f, 0x14, 0x37, 0x4f, 0xe1, 0x35, 0x6d, 0x6d, 0x51, 0xc2, 0x45,
    0xe4, 0x85, 0xb5, 0x76, 0x62, 0x5e, 0x7e, 0xc6, 0xf4, 0x4c, 0x42, 0xe9,
    0xa6, 0x37, 0xed, 0x6b, 0x0b, 0xff, 0x5c, 0xb6, 0xf4, 0x06, 0xb7, 0xed,
    0xee, 0x38, 0x6b, 0xfb, 0x5a, 0x89, 0x9f, 0xa5, 0xae, 0x9f, 0x24, 0x11,
    0x7c, 0x4b, 0x1f, 0xe6, 0x49, 0x28, 0x66, 0x51, 0xec, 0xe4, 0x5b, 0x3d,
    0xc2, 0x00, 0x7c, 0xb8, 0xa1, 0x63, 0xbf, 0x05, 0x98, 0xda, 0x48, 0x36,
    0x1c, 0x55, 0xd3, 0x9a, 0x69, 0x16, 0x3f, 0xa8, 0xfd, 0x24, 0xcf, 0x5f,
    0x83, 0x65, 0x5d, 0x23, 0xdc, 0xa3, 0xad, 0x96, 0x1c, 0x62, 0xf3, 0x56,
    0x20, 0x85, 0x52, 0xbb, 0x9e, 0xd5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6d,
    0x67, 0x0c, 0x35, 0x4e, 0x4a, 0xbc, 0x98, 0x04, 0xf1, 0x74, 0x6c, 0x08,
    0xca, 0x18, 0x21, 0x7c, 0x32, 0x90, 0x5e, 0x46, 0x2e, 0x36, 0xce, 0x3b,
    0xe3, 0x9e, 0x77, 0x2c, 0x18, 0x0e, 0x86, 0x03, 0x9b, 0x27, 0x83, 0xa2,
    0xec, 0x07, 0xa2, 0x8f, 0xb5, 0xc5, 0x5d, 0xf0, 0x6f, 0x4c, 0x52, 0xc9,
    0xde, 0x2b, 0xcb, 0xf6, 0x95, 0x58, 0x17, 0x18, 0x39, 0x95, 0x49, 0x7c,
    0xea, 0x95, 0x6a, 0xe5, 0x15, 0xd2, 0x26, 0x18, 0x98, 0xfa, 0x05, 0x10,
    0x15, 0x72, 0x8e, 0x5a, 0x8a, 0xaa, 0xc4, 0x2d, 0xad, 0x33, 0x17, 0x0d,
    0x04, 0x50, 0x7a, 0x33, 0xa8, 0x55, 0x21, 0xab, 0xdf, 0x1c, 0xba, 0x64,
    0xec, 0xfb, 0x85, 0x04, 0x58, 0xdb, 0xef, 0x0a, 0x8a, 0xea, 0x71, 0x57,
    0x5d, 0x06, 0x0c, 0x7d, 0xb3, 0x97, 0x0f, 0x85, 0xa6, 0xe1, 0xe4, 0xc7,
    0xab, 0xf5, 0xae, 0x8c, 0xdb, 0x09, 0x33, 0xd7, 0x1e, 0x8c, 0x94, 0xe0,
    0x4a, 0x25, 0x61, 0x9d, 0xce, 0xe3, 0xd2, 0x26, 0x1a, 0xd2, 0xee, 0x6b,
    0xf1, 0x2f, 0xfa, 0x06, 0xd9, 0x8a, 0x08, 0x64, 0xd8, 0x76, 0x02, 0x73,
    0x3e, 0xc8, 0x6a, 0x64, 0x52, 0x1f, 0x2b, 0x18, 0x17, 0x7b, 0x20, 0x0c,
    0xbb, 0xe1, 0x17, 0x57, 0x7a, 0x61, 0x5d, 0x6c, 0x77, 0x09, 0x88, 0xc0,
    0xba, 0xd9, 0x46, 0xe2, 0x08, 0xe2, 0x4f, 0xa0, 0x74, 0xe5, 0xab, 0x31,
    0x43, 0xdb, 0x5b, 0xfc, 0xe0, 0xfd, 0x10, 0x8e, 0x4b, 0x82, 0xd1, 0x20,
    0xa9, 0x3a, 0xd2, 0xca, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};
static const uint8_t g[] = {5};

static int _verifier_set(struct srp_desc* srp)
{
    uint8_t* verifier = malloc(VERIFIER_LENGTH);
    if (!verifier) {
        ESP_LOGE(TAG, "malloc failed. size:%d\n", VERIFIER_LENGTH);
        return -1;
    }

    uint32_t verifier_length = VERIFIER_LENGTH;
    if (wc_SrpGetVerifier(&srp->wolfcrypt, verifier, &verifier_length)  < 0) {
        ESP_LOGE(TAG, "wc_SrpGetVerifier failed\n");
        free(verifier);
        return -1;
    }

    srp->wolfcrypt.side=SRP_SERVER_SIDE; //switch to server mode
    if (wc_SrpSetVerifier(&srp->wolfcrypt, verifier, verifier_length) < 0) {
        ESP_LOGE(TAG, "wc_SrpSetVerifier failed\n");
        free(verifier);
        return -1;
    }

    free(verifier);
    return 0;
}

static int _session_key_generate(Srp* wolfcrypt, byte* secret, word32 size)
{
    SrpHash hash;
    int r = -1;

    wolfcrypt->key = (byte*)XMALLOC(SHA512_DIGEST_SIZE, NULL, DYNAMIC_TYPE_SRP);
    if (wolfcrypt->key == NULL)
        return -1;

    wolfcrypt->keySz = SHA512_DIGEST_SIZE;

    r = wc_InitSha512(&hash.data.sha512);
    if (!r) r = wc_Sha512Update(&hash.data.sha512, secret, size);
    if (!r) r = wc_Sha512Final(&hash.data.sha512, wolfcrypt->key);

    memset(&hash,0,sizeof(SrpHash));

    return r;
}

int srp_client_proof_verify(void* instance, uint8_t* proof)
{
    struct srp_desc* srp = instance;
    if (!srp) {
        ESP_LOGE(TAG, "Invalid instance\n");
        return -1;
    }

    int err = wc_SrpVerifyPeersProof(&srp->wolfcrypt, proof, SRP_PROOF_LENGTH);
    if (err < 0) {
        ESP_LOGE(TAG, "wc_SrpVerifyPeersProof failed. err:%d\n", err);
        return -1;
    }

    return 0;
}

int srp_host_proof_get(void* instance, uint8_t proof[])
{
    struct srp_desc* srp = instance;
    if (!srp) {
        ESP_LOGE(TAG, "Invalid instance\n");
        return -1;
    }

    uint32_t size = SRP_PROOF_LENGTH;
    int err = wc_SrpGetProof(&srp->wolfcrypt, proof, &size);
    if (err < 0) {
        ESP_LOGE(TAG, "wc_SrpGetProof failed. %d\n", err);
        return -1;
    }

    return 0;
}

int srp_client_key_set(void* instance, uint8_t* client_public_key)
{
    struct srp_desc* srp = instance;
    if (!srp) {
        ESP_LOGE(TAG, "Invalid instance\n");
        return -1;
    }

    int err = wc_SrpComputeKey(&srp->wolfcrypt, 
            client_public_key, SRP_PUBLIC_KEY_LENGTH, 
            srp->B, SRP_PUBLIC_KEY_LENGTH);
    if (err < 0) {
        ESP_LOGE(TAG, "wc_SrpComputeKey failed. err:%d\n", err);
        return -1;
    }

    return 0;
}

int srp_host_key_get(void* instance, uint8_t public_key[])
{
    struct srp_desc* srp = instance;
    if (!srp) {
        ESP_LOGE(TAG, "Invalid instance\n");
        return -1;
    }

    memcpy(public_key, srp->B, SRP_PUBLIC_KEY_LENGTH);

    return SRP_PUBLIC_KEY_LENGTH;
}

int srp_host_session_key(void* instance, uint8_t session_key[])
{
    struct srp_desc* srp = instance;
    if (!srp) {
        ESP_LOGE(TAG, "Invalid instance\n");
        return -1;
    }

    memcpy(session_key, srp->wolfcrypt.key, SRP_SESSION_KEY_LENGTH);
    return 0;
}

int srp_salt(void* instance, uint8_t salt[])
{
    struct srp_desc* srp = instance;
    if (!srp) {
        ESP_LOGE(TAG, "Invalid instance\n");
        return -1;
    }

    memcpy(salt, srp->wolfcrypt.salt, SRP_SALT_LENGTH);
    return SRP_SALT_LENGTH;
}

void* srp_init(const char* setup_code)
{
    if (!setup_code) {
        ESP_LOGE(TAG, "setup code is NULL\n");
        return NULL;
    }

    ESP_LOGI(TAG, "setup_code:%s\n", setup_code);

    struct srp_desc *srp = malloc(sizeof(struct srp_desc));
    if (!srp) {
        ESP_LOGE(TAG, "malloc failed. size:%d\n", sizeof(struct srp_desc));
        goto err_malloc;
    }

    if (wc_SrpInit(&srp->wolfcrypt, SRP_TYPE_SHA512, SRP_CLIENT_SIDE) < 0) {
        ESP_LOGE(TAG, "wc_SrpInit failed\n");
        goto err_wc_SrpInit;
    }
    srp->wolfcrypt.keyGenFunc_cb = _session_key_generate;

    const char* username = "Pair-Setup";
    if (wc_SrpSetUsername(&srp->wolfcrypt, (const byte*)username, strlen(username)) < 0) {
        ESP_LOGE(TAG, "wc_SrpSetUsername failed\n");
        goto err_wc_SrpSetUsername;
    }

    os_get_random(srp->salt, SRP_SALT_LENGTH);
    if (wc_SrpSetParams(&srp->wolfcrypt, N, sizeof(N), g, sizeof(g),
                srp->salt, sizeof(srp->salt)) < 0) {
        ESP_LOGE(TAG, "wc_SrpSetParams failed\n");
        goto err_wc_SrpSetParams;
    }

    if (wc_SrpSetPassword(&srp->wolfcrypt, (const byte*)setup_code, strlen(setup_code)) < 0) {
        ESP_LOGE(TAG, "wc_SrpSetPassword failed\n");
        goto err_wc_SrpSetPassword;
    }

    if (_verifier_set(srp) < 0) {
        ESP_LOGE(TAG, "_verifier_set failed\n");
        goto err_verifier_set;
    }

    os_get_random(srp->b, PRIVATE_KEY_LENGTH);
    if (wc_SrpSetPrivate(&srp->wolfcrypt, srp->b, PRIVATE_KEY_LENGTH) < 0) {
        ESP_LOGE(TAG, "wc_SrpSetPrivate failed\n");
        goto err_wc_SrpSetPrivate;
    }

    uint32_t B_len = SRP_PUBLIC_KEY_LENGTH;
    if (wc_SrpGetPublic(&srp->wolfcrypt, srp->B, &B_len) < 0) {
        ESP_LOGE(TAG, "err_wc_SrpGetPublic failed\n");
        goto err_wc_SrpGetPublic;
    }

    ESP_LOGI(TAG, "INITIALIZED\n");

    return srp;

err_wc_SrpGetPublic:
err_wc_SrpSetPrivate:
err_verifier_set:
err_wc_SrpSetPassword:
err_wc_SrpSetParams:
err_wc_SrpSetUsername:
    wc_SrpTerm(&srp->wolfcrypt);

err_wc_SrpInit:
    free(srp);

err_malloc:
    return NULL;
}

void srp_cleanup(void* instance)
{
    struct srp_desc* srp = instance;
    if (!srp)
        return;

    wc_SrpTerm(&srp->wolfcrypt);
    free(srp);
}
