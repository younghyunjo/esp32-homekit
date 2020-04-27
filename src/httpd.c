#include "httpd.h"
#include "pair_verify.h"
#include "pair_setup.h"
#include "chacha20_poly1305.h"
#include "accessories.h"

#include <esp_wifi.h>
#include <esp_event.h>
#include <esp_http_server.h>
#include <esp_log.h>
#include <esp_event_base.h>
#include <sys/param.h>
#include <mbedtls/base64.h>
#include <sys/socket.h>
#include <search.h>

#define TAG "httpd"

#define MAX_RX_LEN 1024
#define MAX_ENCRYPTED_PAYLOAD_LEN 2048


static char* s_rx_buffer;

static httpd_config_t s_config = HTTPD_DEFAULT_CONFIG();
static httpd_handle_t s_server = NULL;

static struct hap_accessory* s_accessory = NULL;

static void* s_connections = NULL;

struct connection_entry_t {
    int sock_fd;

    struct hap_connection* connection;

    /**
     * This buffer is used to store a full decrypted frame.
     */
    uint8_t* rx_decrypted_buffer;

    /**
     * Total number of bytes stored in rx_decrypted_buffer.
     */
    int rx_decrypted_buffer_len;

    /**
     * Number of bytes read from rx_decrypted_buffer so far.
     */
    int rx_decrypted_read_count;
};

static int _compare(const void *l, const void *r)
{
    const struct connection_entry_t* lm = l;
    const struct connection_entry_t* lr = r;

    if (lm == lr) {
        return 0;
    } else if (NULL == lm) {
        return 1;
    } else if (NULL == lr) {
        return -1;
    } else {
        return lr->sock_fd - lm->sock_fd;
    }
}

struct connection_entry_t *_get_entry(int sock_fd) {
    struct connection_entry_t key = {0};
    key.sock_fd = sock_fd;
    struct connection_entry_t *entry = *(struct connection_entry_t **) tfind(&key, &s_connections, _compare);
    return entry;
}


/**
 * Streams the body's content
 * @return ESP_FAIL if badness, or the total number of bytes received if > 0
 */
int _recv_body(httpd_req_t *req, size_t len, char *buf, size_t max_len) {
    int count = 0;
    int ret;

    if (len > max_len) {
        ESP_LOGE(TAG, "Exceeded max rx buffer length %d > %d", len, max_len);
        return ESP_FAIL;
    }

    while (len > 0) {
        if ((ret = httpd_req_recv(req, buf + count, len)) <= 0) {
            if (ret == HTTPD_SOCK_ERR_TIMEOUT) {
                /* Retry receiving if timeout occurred */
                continue;
            }
            return ESP_FAIL;
        }

        len -= ret;
        count += ret;
    }

    return count;
}

static esp_err_t _accessories_get(httpd_req_t *req) {
    ESP_LOGI(TAG, "[GET] accessories");

    char* res_body = NULL;
    int body_len = 0;
    hap_acc_accessories_do(s_accessory, &res_body, &body_len);

    httpd_resp_set_type(req, "application/hap+json");
    httpd_resp_send(req, res_body, body_len);

    free(res_body);
    return ESP_OK;
}

static esp_err_t _characteristics_get(httpd_req_t *req) {
    ESP_LOGI(TAG, "[GET] characteristics");

    int params_len = httpd_req_get_url_query_len(req);
    if (params_len > 0) {
        char* params = malloc(params_len);
        httpd_req_get_url_query_str(req, params, params_len+1);
        ESP_LOGI(TAG, "[GET] characteristics params: %.*s, len=%d", params_len, params, params_len-1);

        char* res_body = NULL;
        int body_len = 0;

        int ret = hap_acc_characteristic_get(s_accessory, params, params_len, &res_body, &body_len);
        if ( ret == ESP_OK) {
            httpd_resp_set_type(req, "application/hap+json");
            httpd_resp_send(req, res_body, body_len);
        }

        free(params);
        free(res_body);
        return ESP_OK;
    } else {
        ESP_LOGI(TAG, "Header did not contain 'id' tag");
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, NULL);
    }
}

static esp_err_t _characteristics_put(httpd_req_t *req) {
    ESP_LOGI(TAG, "[PUT] characteristics");

    char* res_body = NULL;
    int body_len = 0;

    int len =  _recv_body(req, req->content_len, s_rx_buffer, MAX_RX_LEN);
    if (len > 0) {
        hap_acc_characteristic_put(s_accessory, s_rx_buffer, len, &res_body, &body_len);

        httpd_resp_set_status(req, "204");
        httpd_resp_send(req, res_body, body_len);
    } else {
        ESP_LOGE(TAG, "[PUT] characteristics: Received body length invalid len=%d", len);
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, NULL);
    }

    free(res_body);
    return ESP_OK;
}


static esp_err_t _pair_verify_post(httpd_req_t *req) {
    ESP_LOGI(TAG, "[POST] pair-verify");

    // Get connection, die hard if if pointer is not valid, it would be a programming error.
    struct hap_connection *ctx = _get_entry(httpd_req_to_sockfd(req))->connection;

    if (ctx->pair_verified) {
        ESP_LOGW(TAG, "Already verified");
        httpd_resp_send_500(req);
        return ESP_OK;
    } else if (ctx->pair_verify == NULL) {
        ESP_LOGI(TAG, "Initiating verification");
        // Then we must have a valid verify instance
        ctx->pair_verify = pair_verify_init(
                s_accessory->id, s_accessory->iosdevices,
                s_accessory->keys.public, s_accessory->keys.private);
    }

    char* res_body = NULL;
    int body_len = 0;
    int len =  _recv_body(req, req->content_len, s_rx_buffer, MAX_RX_LEN);
    int verify_status = pair_verify_do(ctx->pair_verify, s_rx_buffer, len, &res_body, &body_len, ctx->session_key);

    if (verify_status == 1) {
        ESP_LOGI(TAG, "Connection verified.");

        hkdf_key_get(HKDF_KEY_TYPE_CONTROL_READ, (uint8_t*)ctx->session_key,
                CURVE25519_SECRET_LENGTH, ctx->encrypt_key);
        hkdf_key_get(HKDF_KEY_TYPE_CONTROL_WRITE, (uint8_t*)ctx->session_key,
                CURVE25519_SECRET_LENGTH, ctx->decrypt_key);

        // Clean up, we are done.
        free(ctx->pair_verify);
        ctx->pair_verify = NULL;
    } else if (verify_status < 0) {
        ESP_LOGE(TAG, "Verification failed.");
    }

    httpd_resp_set_type(req, "application/pairing+tlv8");
    httpd_resp_send(req, res_body, body_len);

    // Set verified flag after reply is sent
    ctx->pair_verified = (verify_status == 1);

    free(res_body);
    return ESP_OK;
}

static esp_err_t _pair_setup_post(httpd_req_t *req) {
    ESP_LOGI(TAG, "[POST] pair-setup");

    // Get connection, die hard if if pointer is not valid, it would be a programming error.
    struct hap_connection *ctx = _get_entry(httpd_req_to_sockfd(req))->connection;

    if (ctx->pair_setup == NULL) {
        ctx->pair_setup = pair_setup_init(
                s_accessory->id, s_accessory->pincode,
                s_accessory->iosdevices, s_accessory->keys.public, s_accessory->keys.private);
    }

    char* res_body = NULL;
    int body_len = 0;
    int len =  _recv_body(req, req->content_len, s_rx_buffer, MAX_RX_LEN);
    pair_setup_do(ctx->pair_setup, s_rx_buffer, len, &res_body, &body_len);

    httpd_resp_set_type(req, "application/pairing+tlv8");
    httpd_resp_send(req, res_body, body_len);

    free(res_body);
    return ESP_OK;
}

static esp_err_t _start_server() {
    // Start the httpd server
    ESP_LOGI(TAG, "Starting server on port: '%d'", s_config.server_port);
    esp_err_t ret = httpd_start(&s_server, &s_config);
    if (ret == ESP_OK) {

        // Set URI handlers
        ESP_LOGI(TAG, "Registering URI handlers");

        httpd_register_uri_handler(s_server, &(httpd_uri_t) {
                .uri       = "/accessories",
                .method    = HTTP_GET,
                .handler   = _accessories_get,
                .user_ctx  = NULL
        });

        httpd_register_uri_handler(s_server, &(httpd_uri_t) {
                .uri       = "/characteristics",
                .method    = HTTP_GET,
                .handler   = _characteristics_get,
                .user_ctx  = NULL
        });

        httpd_register_uri_handler(s_server, &(httpd_uri_t) {
                .uri       = "/characteristics",
                .method    = HTTP_PUT,
                .handler   = _characteristics_put,
                .user_ctx  = NULL
        });

        httpd_register_uri_handler(s_server, &(httpd_uri_t) {
                .uri       = "/pair-verify",
                .method    = HTTP_POST,
                .handler   = _pair_verify_post,
                .user_ctx  = NULL
        });

        httpd_register_uri_handler(s_server, &(httpd_uri_t) {
                .uri       = "/pair-setup",
                .method    = HTTP_POST,
                .handler   = _pair_setup_post,
                .user_ctx  = NULL
        });

    } else {
        ESP_LOGE(TAG, "Error starting server!");
    }

    return ret;
}

static void _stop_server() {
    ESP_LOGI(TAG, "Stopping server");
    httpd_stop(&s_server);
}

static void _disconnect_handler(void *arg, esp_event_base_t event_base,
                                int32_t event_id, void *event_data) {
    UNUSED_ARG(arg);
    UNUSED_ARG(event_base);
    UNUSED_ARG(event_id);
    UNUSED_ARG(event_data);

    _stop_server();
}

static void _connect_handler(void *arg, esp_event_base_t event_base,
                             int32_t event_id, void *event_data) {
    UNUSED_ARG(arg);
    UNUSED_ARG(event_base);
    UNUSED_ARG(event_id);
    UNUSED_ARG(event_data);

    _start_server();
}

static int _httpd_sock_err(const char *ctx, int sock_fd)
{
    UNUSED_ARG(sock_fd);

    int errval;
    ESP_LOGW(TAG, "Error in %s : %d", ctx, errno);

    switch(errno) {
        case EAGAIN:
        case EINTR:
            errval = HTTPD_SOCK_ERR_TIMEOUT;
            break;
        case EINVAL:
        case EBADF:
        case EFAULT:
        case ENOTSOCK:
            errval = HTTPD_SOCK_ERR_INVALID;
            break;
        default:
            errval = HTTPD_SOCK_ERR_FAIL;
    }
    return errval;
}

static int _handle_decrypt(struct connection_entry_t* entry, int sock_fd, char *buf, size_t buf_len, int flags){
    uint8_t* encrypted_buffer = NULL;
    int ret;

    if (!entry->rx_decrypted_buffer) {
        // This is the start of a new block, read the length of the cleartext payload size, post decrypt
        uint8_t aad_buf[2] = {0};
        ret = recv(sock_fd, aad_buf, 2, flags);
        if (ret != 2) {
            ESP_LOGE(TAG, "Failed to receive decrypted payload size, err: %d", ret);
            ret = HTTPD_SOCK_ERR_FAIL;
            goto error;
        }

        int encrypted_frame_length = aad_buf[1] * 256 + aad_buf[0] + CHACHA20_POLY1305_AUTH_TAG_LENGTH;
        if (encrypted_frame_length > MAX_ENCRYPTED_PAYLOAD_LEN) {
            ESP_LOGE(TAG, "Cannot decrypt payload, too big: %d", encrypted_frame_length);
            ret = HTTPD_SOCK_ERR_FAIL;
            goto error;
        }
        if (encrypted_frame_length < 0) {
            ESP_LOGE(TAG, "Cannot decrypt payload, negative length: %d", encrypted_frame_length);
            ret = HTTPD_SOCK_ERR_FAIL;
            goto error;
        }


        ESP_LOGI(TAG, "Starting decrypt of size %d", encrypted_frame_length);
        // Allocate encrypted buffer then
        encrypted_buffer = calloc(1, encrypted_frame_length);
        if (!encrypted_buffer) {
            ESP_LOGE(TAG, "Cannot allocated encrypted buffer of size %d, out o memory.", encrypted_frame_length);
            ret = HTTPD_SOCK_ERR_FAIL;
            goto error;
        }

        // Start reading
        int total = encrypted_frame_length;
        int remaining = total;
        while (remaining > 0) {
            ret = recv(sock_fd, encrypted_buffer + (total - remaining), remaining, flags);
            if (ret < 0) {
                ESP_LOGE(TAG, "Read error %d, stopping decrypt", ret);
                goto error;
            }

            remaining -= ret;
        }

        // Cool, so we now have all we need, do it.
        uint8_t nonce[12] = {0,};
        nonce[4] = entry->connection->decrypt_count % 256;
        nonce[5] = entry->connection->decrypt_count++ / 256;

        // Target buffer to receive all.
        entry->rx_decrypted_buffer_len = encrypted_frame_length - CHACHA20_POLY1305_AUTH_TAG_LENGTH;
        entry->rx_decrypted_read_count = 0;
        entry->rx_decrypted_buffer = calloc(1, entry->rx_decrypted_buffer_len);

        // Do it, finally decrypt it all
        if (chacha20_poly1305_decrypt_with_nonce(
                nonce, entry->connection->decrypt_key,
                aad_buf, 2,
                encrypted_buffer, encrypted_frame_length, entry->rx_decrypted_buffer) < 0) {
            ESP_LOGE(TAG, "chacha20_poly1305_decrypt_with_nonce failed");
            ret = HTTPD_SOCK_ERR_FAIL;
            goto error;
        }
    }

    // Send decrypted buffer to be consumed until done
    int read_count = MIN(buf_len, entry->rx_decrypted_buffer_len - entry->rx_decrypted_read_count);
    memcpy(buf, entry->rx_decrypted_buffer + entry->rx_decrypted_read_count, read_count);
    entry->rx_decrypted_read_count += read_count;
    if (entry->rx_decrypted_read_count == entry->rx_decrypted_buffer_len) {
        // We are done
        ESP_LOGW(TAG, "Read full frame of decrypted data: '%.*s'",
                entry->rx_decrypted_read_count, entry->rx_decrypted_buffer);

        free(entry->rx_decrypted_buffer);
        entry->rx_decrypted_buffer = NULL;
        entry->rx_decrypted_buffer_len = 0;
        entry->rx_decrypted_read_count = 0;
        ESP_LOGI(TAG, "Decrypt completed.");
    }

    return read_count;

    error:
    free(encrypted_buffer);
    free(entry->rx_decrypted_buffer);
    entry->rx_decrypted_buffer = NULL;
    entry->rx_decrypted_buffer_len = 0;
    entry->rx_decrypted_read_count = 0;
    return ret;
}


static char* _encrypt(struct hap_connection* hc, const char* msg, int len, int* encrypted_len)
{
#define AAD_LENGTH 2
    char* encrypted = calloc(1, len + (len / 1024 + 1) * (AAD_LENGTH + CHACHA20_POLY1305_AUTH_TAG_LENGTH) + 1);
    *encrypted_len = 0;

    uint8_t nonce[12] = {0,};
    uint8_t* decrypted_ptr = (uint8_t*)msg;
    uint8_t* encrypted_ptr = (uint8_t*)encrypted;
    while (len > 0) {
        int chunk_len = (len < 1024) ? len : 1024;
        len -= chunk_len;

        uint8_t aad[AAD_LENGTH];
        aad[0] = chunk_len % 256;
        aad[1] = chunk_len / 256;

        memcpy(encrypted_ptr, aad, AAD_LENGTH);
        encrypted_ptr += AAD_LENGTH;
        *encrypted_len += AAD_LENGTH;

        nonce[4] = hc->encrypt_count % 256;
        nonce[5] = hc->encrypt_count++ / 256;

        chacha20_poly1305_encrypt_with_nonce(nonce, hc->encrypt_key, aad, AAD_LENGTH, decrypted_ptr, chunk_len, encrypted_ptr);

        decrypted_ptr += chunk_len;
        encrypted_ptr += chunk_len + CHACHA20_POLY1305_AUTH_TAG_LENGTH;
        *encrypted_len += (chunk_len + CHACHA20_POLY1305_AUTH_TAG_LENGTH);
    }

    return encrypted;
}

int _receive(httpd_handle_t hd, int sock_fd, char *buf, size_t buf_len, int flags) {
    UNUSED_ARG(hd);

    if (buf == NULL) {
        return HTTPD_SOCK_ERR_INVALID;
    }

    // Check if we need to decrypt payloads
    int ret = 0;
    struct connection_entry_t *entry = _get_entry(sock_fd);
    if (entry && entry->connection) {
        if (entry->connection->pair_verified) {
            ret = _handle_decrypt(entry, sock_fd, buf, buf_len, flags);
        } else {
            ret = recv(sock_fd, buf, buf_len, flags);
        }

        if (ret < 0) {
            ret = _httpd_sock_err("recv", sock_fd);
        }
    } else {
        // It is not valid to not have a connection entry.
        ret = HTTPD_SOCK_ERR_INVALID;
    }

    return ret;
}

int _send(httpd_handle_t hd, int sock_fd, const char *buf, size_t buf_len, int flags) {
    UNUSED_ARG(hd);
    if (buf == NULL) {
        return HTTPD_SOCK_ERR_INVALID;
    }

    // Check if we need to decrypt payloads
    int ret = 0;
    struct connection_entry_t *entry = _get_entry(sock_fd);
    if (entry && entry->connection) {
        if (entry->connection->pair_verified) {
            ESP_LOGD(TAG, "Tx payload is encrypted %.*s", buf_len, buf);

            int encrypted_len = 0;
            char* encrypted_buffer = _encrypt(entry->connection, buf, buf_len, &encrypted_len);
            if (encrypted_len > 0) {
                ESP_LOGD(TAG, "Tx payload is encrypted len_orig=%d, len_enc=%d", buf_len, encrypted_len);
                int remainder = encrypted_len;
                while(remainder > 0) {
                    int actual = send(sock_fd, encrypted_buffer + (encrypted_len - remainder), remainder, flags);

                    // Check for error sending and breakout
                    if (actual < 0) {
                        ret = actual;
                        break;
                    }

                    remainder -= actual;
                }

                if (remainder == 0) {
                    // All good then, we've sent all bytes intended, but as encrypted
                    ret = buf_len;
                }
            }
            free(encrypted_buffer);
        } else {
            ESP_LOGD(TAG, "Tx payload is plain");
            ret = send(sock_fd, buf, buf_len, flags);
        }

        if (ret < 0) {
            ret = _httpd_sock_err("send", sock_fd);
        }
    } else {
        // It is not valid to not have a connection entry.
        ret = HTTPD_SOCK_ERR_INVALID;
    }

    return ret;
}

/**
 * Frees resources associated with a given connection.
 */
esp_err_t _free_entry(struct connection_entry_t *entry) {
    if (entry) {
        if (entry->connection) {
            if (entry->connection->pair_verify) {
                free(entry->connection->pair_verify);
            }

            if (entry->connection->pair_setup) {
                free(entry->connection->pair_setup);
            }

            free(entry->connection);
        }

        ESP_LOGI(TAG, "Connection entry deleted for %d", entry->sock_fd);
        free(entry);
        return ESP_OK;
    } else {
        return ESP_ERR_NOT_FOUND;
    }
}

/**
 * Called when a new connection is opened.
 *
 * This hook is used to associate specific session information with a new connection.
 */
esp_err_t _connection_opened(httpd_handle_t hd, int sock_fd) {

    // This is a new connection, we create a connection_entry_t container and use sock_fd as key.
    ESP_LOGI(TAG, "Connection opened for %d", sock_fd);
    struct connection_entry_t* entry = calloc(1, sizeof(struct connection_entry_t));
    if (entry) {
        entry->sock_fd = sock_fd;
        entry->connection = calloc(1, sizeof(struct hap_connection));
        if (entry->connection) {
            ESP_LOGI(TAG, "Connection indexed for %d", entry->sock_fd);
            tsearch(entry, &s_connections, _compare);

            // Override rx and tx handlers so we can trap encrypt/decrypt and pairing verify status
            httpd_sess_set_recv_override(hd, sock_fd, _receive);
            httpd_sess_set_send_override(hd, sock_fd, _send);
            return ESP_OK;
        }
    }

    ESP_LOGE(TAG, "Out of memory I am afraid.");
    return ESP_ERR_NO_MEM;
}

/**
 * Called when a connection is closed.
 *
 * This hook is used to un-index connection information and free associated resources.
 */
void _connection_closed(httpd_handle_t hd, int sock_fd) {
    UNUSED_ARG(hd);

    // Then we are done, un-index and free
    ESP_LOGI(TAG, "Connection closed for %d", sock_fd);
    struct connection_entry_t *entry = _get_entry(sock_fd);
    if (entry) {
        assert(entry->sock_fd == sock_fd);
        if (NULL == tdelete(entry, &s_connections, _compare)) {
            ESP_LOGE(TAG, "Could not un-index connection entry for %d.", entry->sock_fd);
        }
        _free_entry(entry);
    } else{
        ESP_LOGE(TAG, "No matching hap_connection for http close() call.");
    }
}


esp_err_t httpd_init(struct hap_accessory* accessory) {
    if (s_accessory != NULL) {
        ESP_LOGE(TAG, "Already initialised.");
        return -1;
    }

    s_accessory = accessory;

    s_config.server_port = s_accessory->port;
    s_config.recv_wait_timeout = 10;
    s_config.send_wait_timeout = 10;
    s_config.lru_purge_enable = true;
    s_config.stack_size = 1024 * 8;
    s_config.open_fn = _connection_opened;
    s_config.close_fn = _connection_closed;

    // Register listening on wifi start / stop to keep the server up
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &_connect_handler, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, WIFI_EVENT_STA_DISCONNECTED, &_disconnect_handler, NULL));

    // Allocate receive buffer
    s_rx_buffer = calloc(1, sizeof(char) * MAX_RX_LEN);

    return _start_server();
}

void httpd_terminate() {
    if (s_accessory == NULL) {
        ESP_LOGE(TAG, "Not initialised.");
        return;
    }

    // Register listening on wifi start / stop to keep the server up
    ESP_ERROR_CHECK(esp_event_handler_unregister(IP_EVENT, IP_EVENT_STA_GOT_IP, &_connect_handler));
    ESP_ERROR_CHECK(esp_event_handler_unregister(WIFI_EVENT, WIFI_EVENT_STA_DISCONNECTED, &_disconnect_handler));

    _stop_server();
    free(s_rx_buffer);
    s_accessory = NULL;
}

