// spa_common.h (Common definitions & Prototypes - FINAL)
#ifndef SPA_COMMON_H
#define SPA_COMMON_H

#include <stdint.h>         // For fixed-width integers
#include <stdlib.h>         // For size_t, malloc, free, atoi, strtoull
#include <netinet/in.h>     // For IPPROTO_* constants, sockaddr_in, htons, htonl
#include <arpa/inet.h>      // For INET_ADDRSTRLEN, inet_pton, inet_ntop
#include <ctype.h>          // For isspace
#include <string.h>         // For strcasecmp, strlen, memset, memcpy, strchr, strdup, strtok
#include <openssl/ssl.h>    // For SSL_CTX, SSL types
#include <openssl/err.h>    // For OpenSSL error reporting
#include <openssl/x509.h>   // For X509 types

// --- Configuration Constants ---
#define SPA_LISTENER_PORT 62201         // Default UDP port for receiving SPA packets
#define CONTROLLER_MTLS_PORT 9999       // Default TCP port for Controller mTLS (IH/AH onboarding)
#define AH_MTLS_PORT_DEFAULT 10000     // Base port for ephemeral AH mTLS (can be overridden by Controller)
#define SPA_TIMESTAMP_WINDOW_SECONDS 60 // Allow +/- 60 seconds clock skew/delay
#define SPA_DEFAULT_DURATION_SECONDS 30 // Default access duration enforced by server/AH
#define SPA_INTERFACE       "eth0"        // Default sniffing interface if not specified

// --- Cryptography Constants ---
#define SPA_ENCRYPTION_ALGO "aes-256-cbc" // Symmetric encryption for SPA payload
#define SPA_HMAC_ALGO       "sha256"      // HMAC algorithm for SPA packet integrity
#define SPA_HOTP_HMAC_ALGO  "sha1"        // HMAC algorithm used internally by HOTP (RFC 4226 default)
#define SPA_IV_LEN          16            // AES block size (and thus IV length)
#define SPA_HMAC_LEN        32            // Output length of SHA256
#define SPA_NONCE_LEN       16            // Length of random nonce in SPA packet
#define MAX_KEY_LEN         64            // Max *binary* key length supported (bytes)
#define HOTP_CODE_DIGITS    6             // Number of digits in generated HOTP codes
#define HOTP_COUNTER_SYNC_WINDOW 3        // How many future HOTP codes server checks for resync
#define MAX_SERVICE_LEN     64            // Max length for "proto/port" or "proto/any" string

// --- SPA Packet Structure (Plaintext before encryption) ---
#define SPA_VERSION 1
typedef struct __attribute__((packed)) {
    uint8_t  version;           // SPA protocol version
    uint64_t timestamp;         // Unix timestamp (seconds) - Network Byte Order
    uint32_t source_ip_internal;// Optional: Client internal IP - Network Byte Order
    uint8_t  req_protocol;      // Requested protocol for target service (e.g., IPPROTO_TCP)
    uint16_t req_port;          // Requested *target* port - Network Byte Order (0 for 'any')
    uint8_t  nonce[SPA_NONCE_LEN]; // Random nonce
    uint64_t hotp_counter;      // HOTP counter value used - Network Byte Order
    uint32_t hotp_code;         // HOTP code generated - Network Byte Order
} spa_data_t;

// --- Wire Format & Size Calculation ---
// UDP Payload: [ IV (SPA_IV_LEN) | Encrypted spa_data_t | HMAC (SPA_HMAC_LEN) ]
#define SPA_PACKET_MIN_LEN (SPA_IV_LEN + sizeof(spa_data_t) + SPA_HMAC_LEN)
// Max length adds potential block padding (use cipher block size, often same as IV len)
#define SPA_PACKET_MAX_LEN (SPA_IV_LEN + sizeof(spa_data_t) + SPA_IV_LEN + SPA_HMAC_LEN)

// --- Helper Function Prototypes (Implementations in spa_common.c) ---

// OpenSSL Init/Cleanup (Call ONCE per process)
void initialize_openssl();
void cleanup_openssl();

// OpenSSL Error Reporting
void handle_openssl_error(const char *msg);

// HOTP Generation (RFC 4226)
// Returns HOTP code or (uint32_t)-1 on error
uint32_t generate_hotp(const unsigned char *key, size_t key_len, uint64_t counter, int digits);

// Protocol string/int conversion
const char* protocol_to_string(int proto);
int string_to_protocol(const char* proto_str);

// String/Data Helpers
char* trim_whitespace(char *str);
int hex_string_to_bytes(const char *hex_string, unsigned char *byte_array, size_t max_len);
int constant_time_memcmp(const void *a, const void *b, size_t size);

// Basic TCP Socket Helpers
int open_tcp_listener(int port);
int open_tcp_connection(const char *hostname, int port);

// TLS/mTLS Helpers (Reverted Signatures)
SSL_CTX* create_ssl_context(int is_server);
int configure_ssl_context(SSL_CTX *ctx, const char* ca_path, const char* cert_path, const char* key_path, int is_server);
SSL* establish_mtls_connection(const char* server_ip, uint16_t port, SSL_CTX *ctx); // Client role specific
int send_data_over_mtls(SSL *ssl, const char *data); // Generic sender
void show_peer_certificates(SSL* ssl);

// SPA Packet Sending Helper
int send_spa_packet(const char* target_ip, uint16_t target_port,
                    const unsigned char* enc_key, /* NO size_t enc_key_len, */
                    const unsigned char* hmac_key, size_t hmac_key_len,
                    const unsigned char* hotp_secret, size_t hotp_secret_len,
                    uint64_t hotp_counter,
                    uint8_t req_proto, uint16_t req_port_host);

#endif // SPA_COMMON_H