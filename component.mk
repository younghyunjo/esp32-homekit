COMPONENT_SRCDIRS := src wolfssl/src wolfssl/wolfcrypt/src
COMPONENT_ADD_INCLUDEDIRS := include
COMPONENT_PRIV_INCLUDEDIRS := wolfssl src

HOMEKIT_OBJS := $(patsubst %.c,%.o,$(wildcard $(COMPONENT_PATH)/src/*.c))
HOMEKIT_OBJS := $(patsubst $(COMPONENT_PATH)/%,%,$(HOMEKIT_OBJS))

WOLFSSL_OBJS := \
    wolfssl/src/internal.o          \
    wolfssl/src/io.o                \
    wolfssl/src/keys.o              \
    wolfssl/src/ocsp.o              \
    wolfssl/src/ssl.o               \
    wolfssl/src/tls.o               \
    wolfssl/wolfcrypt/src/aes.o     \
    wolfssl/wolfcrypt/src/arc4.o    \
    wolfssl/wolfcrypt/src/asn.o     \
    wolfssl/wolfcrypt/src/chacha.o  \
    wolfssl/wolfcrypt/src/chacha20_poly1305.o  \
    wolfssl/wolfcrypt/src/coding.o  \
    wolfssl/wolfcrypt/src/curve25519.o  \
    wolfssl/wolfcrypt/src/dh.o      \
    wolfssl/wolfcrypt/src/ed25519.o \
    wolfssl/wolfcrypt/src/error.o   \
    wolfssl/wolfcrypt/src/fe_operations.o   \
    wolfssl/wolfcrypt/src/ge_operations.o   \
    wolfssl/wolfcrypt/src/hash.o    \
    wolfssl/wolfcrypt/src/hmac.o    \
    wolfssl/wolfcrypt/src/integer.o \
    wolfssl/wolfcrypt/src/logging.o \
    wolfssl/wolfcrypt/src/md5.o     \
    wolfssl/wolfcrypt/src/memory.o  \
    wolfssl/wolfcrypt/src/poly1305.o  \
    wolfssl/wolfcrypt/src/random.o  \
    wolfssl/wolfcrypt/src/rsa.o     \
    wolfssl/wolfcrypt/src/sha.o     \
    wolfssl/wolfcrypt/src/sha256.o  \
    wolfssl/wolfcrypt/src/sha512.o  \
    wolfssl/wolfcrypt/src/srp.o  \
    wolfssl/wolfcrypt/src/wc_port.o \
    wolfssl/wolfcrypt/src/wc_encrypt.o

COMPONENT_OBJS := $(HOMEKIT_OBJS) $(WOLFSSL_OBJS) 

WOLFSSL_SETTINGS =        \
    -DSIZEOF_LONG_LONG=8  \
    -DSMALL_SESSION_CACHE \
    -DWOLFSSL_SMALL_STACK \
	-DWOLFCRYPT_HAVE_SRP  \
	-DWOLFSSL_SHA512      \
    -DHAVE_CHACHA         \
	-DHAVE_HKDF			  \
    -DHAVE_ONE_TIME_AUTH  \
    -DHAVE_ED25519        \
	-DHAVE_ED25519_KEY_EXPORT\
	-DHAVE_ED25519_KEY_IMPORT\
    -DHAVE_OCSP           \
    -DHAVE_CURVE25519     \
	-DHAVE_POLY1305       \
    -DHAVE_SNI            \
    -DHAVE_TLS_EXTENSIONS \
    -DTIME_OVERRIDES      \
    -DNO_DES              \
    -DNO_DES3             \
    -DNO_DSA              \
    -DNO_ERROR_STRINGS    \
    -DNO_HC128            \
    -DNO_MD4              \
    -DNO_OLD_TLS          \
    -DNO_PSK              \
    -DNO_PWDBASED         \
    -DNO_RC4              \
    -DNO_RABBIT           \
    -DNO_STDIO_FILESYSTEM \
    -DNO_WOLFSSL_DIR      \
    -DNO_DH               \
    -DWOLFSSL_STATIC_RSA  \
    -DWOLFSSL_IAR_ARM     \
    -DNDEBUG              \
    -DHAVE_CERTIFICATE_STATUS_REQUEST \
    -DCUSTOM_RAND_GENERATE_SEED=os_get_random

LWIP_INCDIRS = \
    -I$(IDF_PATH)/components/lwip/system \
    -I$(IDF_PATH)/components/lwip/include/lwip \
    -I$(IDF_PATH)/components/lwip/include/lwip/port

FREERTOS_INCDIRS = \
    -I$(IDF_PATH)/components/freertos/include \
    -I$(IDF_PATH)/components/freertos/include/freertos

CFLAGS = \
    -fstrict-volatile-bitfields \
    -ffunction-sections         \
    -fdata-sections             \
    -mlongcalls                 \
    -nostdlib                   \
    -ggdb                       \
    -Os                         \
    -DNDEBUG                    \
    -std=gnu99                  \
    -Wno-old-style-declaration  \
    $(LWIP_INCDIRS)             \
    $(FREERTOS_INCDIRS)         \
    $(WOLFSSL_SETTINGS)
