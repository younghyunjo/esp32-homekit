#include "httpd_encrypted.h"
#include "pair_verify.h"
#include "pair_setup.h"
#include "chacha20_poly1305.h"
#include "accessories.h"
#include "pairings.h"
#include <search.h>

#include <esp_wifi.h>
#include <esp_http_server.h>
#include <esp_log.h>
#include <esp_event_base.h>
#include <sys/param.h>
#include <mbedtls/base64.h>
#include <sys/socket.h>
#include <search.h>


struct connection_entry_t {
    int sock_fd;

    struct hap_connection connection;

    /**
     * This buffer is used to store a full decrypted frame.
     */
    uint8_t *rx_decrypted_buffer;

    /**
     * Total number of bytes stored in rx_decrypted_buffer.
     */
    int rx_decrypted_buffer_len;

    /**
     * Number of bytes read from rx_decrypted_buffer so far.
     */
    int rx_decrypted_read_count;

};


static httpd_config_t s_config = HTTPD_DEFAULT_CONFIG();

static SemaphoreHandle_t s_semaphore = NULL;

static struct connection_entry_t *s_entries = NULL;


static struct connection_entry_t *_get_entry(int sock_fd) {
    struct connection_entry_t *entry = NULL;

    xSemaphoreTakeRecursive(s_semaphore, portMAX_DELAY);

    for (int i = 0; i < s_config.max_open_sockets; i++) {
        if (sock_fd == s_entries[i].sock_fd) {
            entry = &s_entries[i];
            break;
        }
    }

    xSemaphoreGiveRecursive(s_semaphore);
    return entry;
}

struct hap_connection *httpd_encrypted_get_connection(int sock_fd) {
    struct connection_entry_t *entry = _get_entry(sock_fd);
    if (entry) {
        return &entry->connection;
    } else {
        return NULL;
    }
}

static void _free_decrypt(struct connection_entry_t *entry) {
    free(entry->rx_decrypted_buffer);
    entry->rx_decrypted_buffer = NULL;
    entry->rx_decrypted_buffer_len = 0;
    entry->rx_decrypted_read_count = 0;
}

/**
 * Frees resources associated with a given connection.
 */
esp_err_t _free_entry(struct connection_entry_t *entry) {
    if (entry) {
        ESP_LOGI(TAG, "Deleting connection entry for %d", entry->sock_fd);

        free(entry->connection.pair_verify);
        free(entry->connection.pair_setup);
        _free_decrypt(entry);

        // Zero everything out.
        memset(entry, 0, sizeof(struct connection_entry_t));
        return ESP_OK;
    } else {
        return ESP_ERR_NOT_FOUND;
    }
}

/**
 * Streams the body's content
 * @return ESP_FAIL if badness, or the total number of bytes received if > 0
 */
int httpd_encrypted_recv_body(httpd_req_t *req, size_t len, char *buf, size_t max_len) {
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


esp_err_t httpd_encrypted_start(httpd_handle_t *server) {
    // Start the httpd server
    ESP_LOGI(TAG, "Starting server on port: '%d'", s_config.server_port);
    return httpd_start(server, &s_config);
}

void httpd_encrypted_stop(httpd_handle_t server) {
    ESP_LOGI(TAG, "Stopping server");
    httpd_stop(server);

    xSemaphoreTakeRecursive(s_semaphore, portMAX_DELAY);

    for (int i = 0; i < s_config.max_open_sockets; i++) {
        struct connection_entry_t *entry = &s_entries[i];
        if (entry->sock_fd > 0) {
            _free_entry(entry);
        }
    }

    xSemaphoreGiveRecursive(s_semaphore);
}


static int _httpd_sock_err(const char *ctx, int sock_fd) {
    UNUSED_ARG(sock_fd);

    int error_val;
    ESP_LOGW(TAG, "Error in %s : %d", ctx, errno);

    switch (errno) {
        case EAGAIN:
        case EINTR:
            error_val = HTTPD_SOCK_ERR_TIMEOUT;
            break;
        case EINVAL:
        case EBADF:
        case EFAULT:
        case ENOTSOCK:
            error_val = HTTPD_SOCK_ERR_INVALID;
            break;
        default:
            error_val = HTTPD_SOCK_ERR_FAIL;
    }
    return error_val;
}


static int _handle_decrypt(struct connection_entry_t *entry, int sock_fd, char *buf, size_t buf_len, int flags) {
    uint8_t *encrypted_buffer = NULL;
    int ret;

    if (!entry->rx_decrypted_buffer) {
        // This is the start of a new block, read the length of the cleartext payload size, post decrypt
        uint8_t aad_buf[2] = {0};
        ret = recv(sock_fd, aad_buf, 2, flags);
        if (ret == 0) {
            // Short read, this can happen, let it through.
            goto error;
        } else if (ret != 2) {
            ESP_LOGE(TAG, "Failed to receive decrypted payload size, err: %d", ret);
            ret = HTTPD_SOCK_ERR_FAIL;
            goto error;
        }

        int encrypted_frame_length = aad_buf[1] * 256 + aad_buf[0] + CHACHA20_POLY1305_AUTH_TAG_LENGTH;
        if (encrypted_frame_length > MAX_RX_LENGTH) {
            ESP_LOGE(TAG, "Cannot decrypt payload, too big: %d", encrypted_frame_length);
            ret = HTTPD_SOCK_ERR_FAIL;
            goto error;
        }
        if (encrypted_frame_length < 0) {
            ESP_LOGE(TAG, "Cannot decrypt payload, negative length: %d", encrypted_frame_length);
            ret = HTTPD_SOCK_ERR_FAIL;
            goto error;
        }


        ESP_LOGD(TAG, "Starting decrypt of size %d", encrypted_frame_length);
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
        nonce[4] = entry->connection.decrypt_count % 256;
        nonce[5] = entry->connection.decrypt_count++ / 256;

        // Target buffer to receive all.
        entry->rx_decrypted_buffer_len = encrypted_frame_length - CHACHA20_POLY1305_AUTH_TAG_LENGTH;
        entry->rx_decrypted_read_count = 0;
        entry->rx_decrypted_buffer = calloc(1, entry->rx_decrypted_buffer_len);

        // Do it, finally decrypt it all
        if (chacha20_poly1305_decrypt_with_nonce(
                nonce, entry->connection.decrypt_key,
                aad_buf, 2,
                encrypted_buffer, encrypted_frame_length, entry->rx_decrypted_buffer) < 0) {
            ESP_LOGE(TAG, "chacha20_poly1305_decrypt_with_nonce failed");
            ret = HTTPD_SOCK_ERR_FAIL;
            goto error;
        }

        free(encrypted_buffer);
    }

    // Send decrypted buffer to be consumed until done
    int read_count = MIN(buf_len, entry->rx_decrypted_buffer_len - entry->rx_decrypted_read_count);
    memcpy(buf, entry->rx_decrypted_buffer + entry->rx_decrypted_read_count, read_count);
    entry->rx_decrypted_read_count += read_count;
    if (entry->rx_decrypted_read_count == entry->rx_decrypted_buffer_len) {
        // We are done
        ESP_LOGD(TAG, "Read full frame of decrypted data: '%.*s'",
                 entry->rx_decrypted_read_count, entry->rx_decrypted_buffer);

        _free_decrypt(entry);
        ESP_LOGD(TAG, "Decrypt completed.");
    }

    return read_count;

    error:
    free(encrypted_buffer);
    _free_decrypt(entry);
    return ret;
}


static char *_encrypt(struct hap_connection *hc, const char *msg, int len, int *encrypted_len) {
#define AAD_LENGTH 2
    char *encrypted = calloc(1, len + (len / 1024 + 1) * (AAD_LENGTH + CHACHA20_POLY1305_AUTH_TAG_LENGTH) + 1);
    *encrypted_len = 0;

    ESP_LOGD(TAG, "encrypting %d", len);
    uint8_t nonce[12] = {0,};
    uint8_t *decrypted_ptr = (uint8_t *) msg;
    uint8_t *encrypted_ptr = (uint8_t *) encrypted;
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

        chacha20_poly1305_encrypt_with_nonce(nonce, hc->encrypt_key, aad, AAD_LENGTH, decrypted_ptr, chunk_len,
                                             encrypted_ptr);

        decrypted_ptr += chunk_len;
        encrypted_ptr += chunk_len + CHACHA20_POLY1305_AUTH_TAG_LENGTH;
        *encrypted_len += (chunk_len + CHACHA20_POLY1305_AUTH_TAG_LENGTH);
    }
    ESP_LOGD(TAG, "Done encrypting");

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
    if (entry) {
        if (entry->connection.pair_verified) {
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
    if (entry) {
        if (entry->connection.pair_verified) {
            ESP_LOGD(TAG, "Tx payload is encrypted %.*s", buf_len, buf);

            int encrypted_len = 0;
            char *encrypted_buffer = _encrypt(&entry->connection, buf, buf_len, &encrypted_len);
            if (encrypted_len > 0) {
                ESP_LOGD(TAG, "Tx payload is encrypted len_orig=%d, len_enc=%d", buf_len, encrypted_len);
                int remainder = encrypted_len;
                while (remainder > 0) {
                    ESP_LOGD(TAG, "Tx remain %d", remainder);
                    int actual = send(sock_fd, encrypted_buffer + (encrypted_len - remainder), remainder, flags);

                    // Check for error sending and breakout
                    if (actual <= 0) {
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

esp_err_t httpd_encrypted_send(httpd_req_t *req, const char *buf, size_t len) {
    xSemaphoreTakeRecursive(s_semaphore, portMAX_DELAY);
    esp_err_t ret = httpd_resp_send(req, buf, len);
    xSemaphoreGiveRecursive(s_semaphore);

    return ret;
}

esp_err_t httpd_encrypted_send_err(httpd_req_t *req, httpd_err_code_t error, const char *usr_msg) {
    xSemaphoreTakeRecursive(s_semaphore, portMAX_DELAY);
    esp_err_t ret = httpd_resp_send_err(req, error, usr_msg);
    xSemaphoreGiveRecursive(s_semaphore);

    return ret;
}

int httpd_encrypted_broadcast_event(httpd_handle_t server, const char *buffer, size_t len) {
    static char http_headers_format[] =
            "EVENT/1.0 200 OK\r\n"
            "Content-Type: application/hap+json\r\n"
            "Content-Length: %d\r\n\r\n";

    char *tmp = calloc(1, sizeof(http_headers_format) + 10);

    for (int i = 0; i < s_config.max_open_sockets; i++) {
        struct connection_entry_t *entry = &s_entries[i];

        xSemaphoreTakeRecursive(s_semaphore, portMAX_DELAY);
        if (entry->sock_fd > 0) {
            ESP_LOGD(TAG, "Sending event to socket %d.", entry->sock_fd);
            int header_len = sprintf(tmp, http_headers_format, len);
            int result = _send(server, entry->sock_fd, tmp, header_len, 0);
            if (result > 0) {
                ESP_LOGD(TAG, "Sending event to socket %d as %.*s %.*s", entry->sock_fd, header_len, tmp, len, buffer);
                result = _send(server, entry->sock_fd, buffer, len, 0);
                ESP_LOGD(TAG, "Sent result to %d: %d", entry->sock_fd, result);
            }

            if (result < 0) {
                // This one is a dude
                _free_entry(entry);
            }
        }
        xSemaphoreGiveRecursive(s_semaphore);

    }

    free(tmp);
    return ESP_OK;
}


/**
 * Called when a new connection is opened.
 *
 * This hook is used to associate specific session information with a new connection.
 */
esp_err_t _connection_opened(httpd_handle_t hd, int sock_fd) {

    // This is a new connection, we create a connection_entry_t container and use sock_fd as key.
    ESP_LOGI(TAG, "Connection opened for %d", sock_fd);

    xSemaphoreTakeRecursive(s_semaphore, portMAX_DELAY);

    struct connection_entry_t *entry = NULL;
    for (int i = 0; i < s_config.max_open_sockets; i++) {
        if (s_entries[i].sock_fd == 0) {
            entry = &s_entries[i];
            break;
        }
    }

    int ret;
    if (entry) {
        // Override rx and tx handlers so we can trap encrypt/decrypt and pairing verify status
        httpd_sess_set_recv_override(hd, sock_fd, _receive);
        httpd_sess_set_send_override(hd, sock_fd, _send);
        entry->sock_fd = sock_fd;
        ESP_LOGI(TAG, "Connection indexed for %d", entry->sock_fd);
        ret = ESP_OK;
    } else {
        ESP_LOGE(TAG, "No spare connection slot left.");
        ret = ESP_FAIL;
    }

    xSemaphoreGiveRecursive(s_semaphore);

    return ret;
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
        xSemaphoreTakeRecursive(s_semaphore, portMAX_DELAY);
        _free_entry(entry);
        xSemaphoreGiveRecursive(s_semaphore);
    } else {
        ESP_LOGW(TAG, "No matching hap_connection for http close() call.");
    }
}

int httpd_encrypted_get_port() {
    return s_config.server_port;
}


void httpd_encrypted_init(int port) {
    s_semaphore = xSemaphoreCreateRecursiveMutex();

    s_config.server_port = port;
    s_config.recv_wait_timeout = 5;
    s_config.send_wait_timeout = 5;
    s_config.lru_purge_enable = true;
    s_config.stack_size = 1024 * 8;
    s_config.open_fn = _connection_opened;
    s_config.close_fn = _connection_closed;

    s_entries = calloc(1, sizeof(struct connection_entry_t) * s_config.max_open_sockets);
}

void httpd_encrypted_terminate(httpd_handle_t s_server) {
    if (s_server == NULL) {
        ESP_LOGE(TAG, "Not initialised.");
        return;
    }

    httpd_encrypted_stop(s_server);
    free(s_entries);
    vSemaphoreDelete(s_semaphore);
}

