// spa_common.h (Common definitions for client and server)
#ifndef SPA_COMMON_H
#define SPA_COMMON_H

#include <stdint.h>
#include <netinet/in.h> // For IPPROTO_* constants
#include <stdlib.h>     // For size_t if needed standalone
#include <ctype.h>      // For isspace
#include <string.h>     // For strcasecmp, strlen etc
#include <arpa/inet.h>  // For INET_ADDRSTRLEN, inet_pton etc.
#include <openssl/ssl.h> // Include for SSL_CTX, SSL types needed in prototypes
#include <openssl/x509.h> // For X509 types if needed in prototypes (e.g., for verify callbacks)

// --- Configuration ---
#define SPA_LISTENER_PORT 62201
#define CONTROLLER_MTLS_PORT 9999
#define AH_MTLS_PORT_DEFAULT 10000
#define SPA_TIMESTAMP_WINDOW_SECONDS 60
#define SPA_DEFAULT_DURATION_SECONDS 30
#define SPA_INTERFACE       "eth0"

// --- Cryptography Details ---
#define SPA_ENCRYPTION_ALGO "aes-256-cbc"
#define SPA_HMAC_ALGO       "sha256"
#define SPA_HOTP_HMAC_ALGO  "sha1"
#define SPA_IV_LEN          16
#define SPA_HMAC_LEN        32
#define SPA_NONCE_LEN       16
#define MAX_KEY_LEN         64
#define HOTP_CODE_DIGITS    6
#define HOTP_COUNTER_SYNC_WINDOW 3
#define MAX_SERVICE_LEN     32

// --- Packet Structure ---
#define SPA_VERSION 1
typedef struct __attribute__((packed)) {
    uint8_t  version;
    uint64_t timestamp;
    uint32_t source_ip_internal;
    uint8_t  req_protocol;
    uint16_t req_port;
    uint8_t  nonce[SPA_NONCE_LEN];
    uint64_t hotp_counter;
    uint32_t hotp_code;
} spa_data_t;

// --- Wire Format ---
#define SPA_PACKET_MIN_LEN (SPA_IV_LEN + sizeof(spa_data_t) + SPA_HMAC_LEN)
#define SPA_PACKET_MAX_LEN (SPA_IV_LEN + sizeof(spa_data_t) + SPA_IV_LEN + SPA_HMAC_LEN)

// --- Helper Function Prototypes ---
// Implementations expected in spa_common.c

// OpenSSL Init/Cleanup
void initialize_openssl();
void cleanup_openssl();

// HOTP Generation
uint32_t generate_hotp(const unsigned char *key, size_t key_len, uint64_t counter, int digits);

// Protocol string/int conversion
const char* protocol_to_string(int proto);
int string_to_protocol(const char* proto_str);

// Config file parsing helpers
char* trim_whitespace(char *str);
int hex_string_to_bytes(const char *hex_string, unsigned char *byte_array, size_t max_len);

// Crypto helpers
void handle_openssl_error(const char *msg);
int constant_time_memcmp(const void *a, const void *b, size_t size);

// mTLS Helpers
SSL_CTX* create_ssl_context(int is_server); // is_server: 0 for client, 1 for server
int configure_ssl_context(SSL_CTX *ctx, const char* ca_path, const char* cert_path, const char* key_path, int is_server);
SSL* establish_mtls_connection(const char* server_ip, uint16_t port, SSL_CTX *ctx); // Client role specific
int send_data_over_mtls(SSL *ssl, const char *data); // Generic sender

// SPA Packet Sending Helper
int send_spa_packet(const char* target_ip, uint16_t target_port,
                    const unsigned char* enc_key, /* NO size_t enc_key_len, */
                    const unsigned char* hmac_key, size_t hmac_key_len,
                    const unsigned char* hotp_secret, size_t hotp_secret_len,
                    uint64_t hotp_counter,
                    uint8_t req_proto, uint16_t req_port_host);

#endif // SPA_COMMON_H