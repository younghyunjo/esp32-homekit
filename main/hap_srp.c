#include <os.h>
#include <esp_log.h>
#include <srp.h>

#include "hap_srp.h"

//#define DEBUG
//#define SRP_TEST

#define TAG "HSRP"

struct hsrp_desc {
    SRP_HashAlgorithm alg;
    SRP_NGType ng_type;
    struct SRPVerifier* ver;

    char* username;
    char* password;

    const uint8_t* salt;
    int salt_len;

    const uint8_t* verifier;
    int verifier_len;

    const uint8_t* B;
    int B_len;

    const uint8_t* b;
    int b_len;

    const uint8_t* hamk;
};

static struct hsrp_desc _h;

int hsrp_init(const char* setup_code)
{
    struct hsrp_desc* h = &_h;

    h->alg = SRP_SHA512;
    h->ng_type = SRP_NG_3072;
    h->username = "Pair-Setup";
    h->password = strdup(setup_code);

    const char* n_hex = 0;
    const char* g_hex = 0;
    srp_create_salted_verification_key(h->alg, h->ng_type, h->username, 
            (const unsigned char*)h->password, strlen(h->password),
            &h->salt, &h->salt_len,
            &h->verifier, &h->verifier_len,
            n_hex, g_hex);

    srp_create_B(h->alg, h->ng_type,
            h->verifier, h->verifier_len,
            &h->B, &h->B_len,
            &h->b, &h->b_len,
            n_hex, g_hex);

    ESP_LOGI(TAG, "initialized\nj");

    return 0;
}

uint8_t* hsrp_salt(void)
{
    return _h.salt;
}

uint8_t* hsrp_B(void)
{
    return _h.B;
}

int hsrp_verify_A(uint8_t* bytes_A, int len_A)
{
    const char* n_hex = 0;
    const char* g_hex = 0;
    _h.ver = srp_verifier_new(_h.alg, _h.ng_type, _h.username,
            _h.salt, _h.salt_len,
            _h.verifier, _h.verifier_len,
            bytes_A, len_A,
            _h.B, _h.B_len,
            _h.b, _h.b_len, n_hex, g_hex);
    return 0;
}

int hsrp_verify_session( uint8_t * user_M )
{
    srp_verifier_verify_session( _h.ver, user_M, &_h.hamk);
    return srp_verifier_is_authenticated(_h.ver);
}

uint8_t* hsrp_hamk(void)
{
    //int key_length = 0;
    //return srp_verifier_get_session_key(_h.ver, &key_length);
    return _h.hamk;
}

int srp_test(void)
{
    const uint8_t* bytes_s;
    int len_s;
    const uint8_t* bytes_v;
    int len_v;

    const char* n_hex = 0;
    const char* g_hex = 0;

    SRP_HashAlgorithm alg = SRP_SHA512;
    SRP_NGType ngtype = SRP_NG_3072;

    const char* username = "alice";
    const char* password = "password123";

    srp_create_salted_verification_key(alg, ngtype, username, 
            (const unsigned char*)password, strlen(password),
            &bytes_s, &len_s,
            &bytes_v, &len_v,
            n_hex, g_hex);

    const uint8_t* bytes_B;
    int len_B;

    const uint8_t* bytes_b;
    int len_b;

    srp_create_B(alg, ngtype,
            bytes_v, len_v,
            &bytes_B, &len_B,
            &bytes_b, &len_b,
            n_hex, g_hex);

    struct SRPUser *usr;
    usr = srp_user_new(alg, ngtype, username,
            (const unsigned char*)password, strlen(password),
            n_hex, g_hex);

    const uint8_t* bytes_A;
    int len_A;
    const char* auth_username;
    srp_user_start_authentication(usr, &auth_username, &bytes_A, &len_A);

    printf("A %d\n", len_A);
    for (int i=0; i<len_A; i++)
        printf("%x ", bytes_A[i]);
    printf("\n");


    struct SRPVerifier* ver = srp_verifier_new(alg, ngtype, auth_username, 
            bytes_s, len_s, 
            bytes_v, len_v,
            bytes_A, len_A, 
            bytes_B, len_B, 
            bytes_b, len_b, 
            n_hex, g_hex);

    int len_K = 0;
    unsigned char* K = srp_verifier_get_session_key(ver, &len_K);
    /*
    printf("K %d\n", len_K);
    for (int i=0; i<len_K; i++)
        printf("%x ", K[i]);
    printf("\n");
    */


    /*
    const uint8_t* bytes_M;
    int len_M;
    srp_user_process_challenge(usr, bytes_s, len_s, bytes_B, len_B, &bytes_M, &len_M);
    printf("M %d\n", len_M);
    for (int i=0; i<len_M; i++)
        printf("%x ", bytes_M[i]);
    printf("\n");

    */

    return 0;
}
