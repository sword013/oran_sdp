// spa_common.h (Common definitions - Updated for TUN/TAP)
#ifndef SPA_COMMON_H
#define SPA_COMMON_H

#include <stdint.h>
#include <netinet/in.h> // For IPPROTO_* constants
#include <stdlib.h>     // For size_t if needed standalone
#include <ctype.h>      // For isspace
#include <string.h>     // For strcasecmp, strlen etc
#include <arpa/inet.h>  // For INET_ADDRSTRLEN, inet_pton etc.
#include <openssl/ssl.h> // Include for SSL_CTX, SSL types needed in prototypes
#include <openssl/x509.h> // For X509 types if needed in prototypes

// --- Includes needed for TUN/TAP ---
#include <linux/if.h>
#include <linux/if_tun.h>
// ----------------------------------

// --- Configuration ---
#define SPA_LISTENER_PORT 62201
#define CONTROLLER_MTLS_PORT 9999
#define AH_MTLS_PORT_DEFAULT 10000 // Default port AH listens on for clients
#define SPA_TIMESTAMP_WINDOW_SECONDS 60
#define SPA_DEFAULT_DURATION_SECONDS 30 // Default firewall rule open time
#define SPA_INTERFACE       "ens18" // Default interface if none specified (AH SPA listener)

// --- Cryptography Details ---
#define SPA_ENCRYPTION_ALGO "aes-256-cbc"
#define SPA_HMAC_ALGO       "sha256"
#define SPA_HOTP_HMAC_ALGO  "sha1" // Algorithm for HOTP's underlying HMAC
#define SPA_IV_LEN          16     // AES block size
#define SPA_HMAC_LEN        32     // SHA-256 output size
#define SPA_NONCE_LEN       16
#define MAX_KEY_LEN         64     // Max binary key length (represents 128 hex chars)
#define HOTP_CODE_DIGITS    6      // Number of digits in the HOTP code
#define HOTP_COUNTER_SYNC_WINDOW 3 // How many future counters to check for HOTP sync
#define MAX_SERVICE_LEN     32

// --- Packet Structure ---
#define SPA_VERSION 1
typedef struct __attribute__((packed)) {
  uint8_t  version;
  uint64_t timestamp;          // UTC seconds since epoch (network byte order)
  uint32_t source_ip_internal; // Optional internal IP (network byte order)
  uint8_t  req_protocol;       // Protocol number requested by client
  uint16_t req_port;           // Port number requested by client (network byte order)
  uint8_t  nonce[SPA_NONCE_LEN]; // Random nonce
  uint64_t hotp_counter;       // HOTP counter used (network byte order)
  uint32_t hotp_code;          // HOTP code generated (network byte order)
} spa_data_t;


// --- Wire Format ---
// IV (16) + Encrypted(spa_data_t) + HMAC (32)
#define SPA_PACKET_MIN_LEN (SPA_IV_LEN + sizeof(spa_data_t) + SPA_HMAC_LEN)
// Allow for potential block padding (though not strictly needed for this exact size)
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

// Basic TCP Socket helpers (Still needed for mTLS setup)
// int open_tcp_listener(int port); // REMOVED - Not needed by IH anymore
int open_tcp_connection(const char *hostname, int port); // Opens an outbound TCP connection

// mTLS Helpers
SSL_CTX* create_ssl_context(int is_server); // is_server: 0 for client, 1 for server
int configure_ssl_context(SSL_CTX *ctx, const char* ca_path, const char* cert_path, const char* key_path, int is_server);
SSL* establish_mtls_connection(const char* server_ip, uint16_t port, SSL_CTX *ctx); // Client role specific
int send_data_over_mtls(SSL *ssl, const char *data); // Generic sender for short control messages
void show_peer_certificates(SSL* ssl); // Helper to print peer cert info

// SPA Packet Sending Helper
int send_spa_packet(const char* target_ip, uint16_t target_port,
                  const unsigned char* enc_key, /* NO size_t enc_key_len */
                  const unsigned char* hmac_key, size_t hmac_key_len,
                  const unsigned char* hotp_secret, size_t hotp_secret_len,
                  uint64_t hotp_counter,
                  uint8_t req_proto, uint16_t req_port_host); // req_port in host byte order

// --- TUN/TAP Helper ---
int tun_alloc(char *dev_name, int flags);
void print_hex(const char *title, const unsigned char *buf, size_t len, size_t max_print);


#endif // SPA_COMMON_H


