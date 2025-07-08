// spa_common.h (Common definitions for client and server)
#ifndef SPA_COMMON_H
#define SPA_COMMON_H

#include <stdint.h>
#include <netinet/in.h> // For IPPROTO_* constants

// --- Configuration ---
// WARNING: Hardcoded key is insecure! Use secure methods in production.
#define SPA_PSK             "your_super_secret_preshared_key_123"
#define SPA_SERVER_UDP_PORT 62201 // Port the server listens on for SPA packets
#define SPA_TIMESTAMP_WINDOW_SECONDS 60 // Allow +/- 60 seconds clock skew/delay
#define SPA_INTERFACE       "eth0" // Default interface for server sniffing (can be overridden)

// --- Cryptography Details ---
#define SPA_ENCRYPTION_ALGO "aes-256-cbc" // OpenSSL EVP cipher name
#define SPA_HMAC_ALGO       "sha256"       // OpenSSL EVP digest name
#define SPA_IV_LEN          16            // AES block size for IV
#define SPA_HMAC_LEN        32            // SHA256 output length
#define SPA_NONCE_LEN       16

// --- Packet Structure (Plaintext before encryption) ---
#define SPA_VERSION 1

// Use __attribute__((packed)) to avoid padding issues
typedef struct __attribute__((packed)) {
    uint8_t  version;         // SPA protocol version
    uint64_t timestamp;       // Unix timestamp (seconds)
    uint32_t source_ip;       // Optional: Client's intended source IP (server SHOULD use actual packet source)
                               // Network byte order. Can be 0 if unused.
    uint8_t  req_protocol;    // Requested protocol (IPPROTO_TCP, IPPROTO_UDP, IPPROTO_SCTP, etc.)
    uint16_t req_port;        // Requested port (Network byte order)
    uint16_t req_duration;    // Requested access duration in seconds (Host byte order - simple example)
    uint8_t  nonce[SPA_NONCE_LEN]; // Random nonce
    // --- Add other fields if needed ---
} spa_data_t;

// --- Wire Format ---
// The UDP payload will contain:
// [ IV (SPA_IV_LEN bytes) | Encrypted spa_data_t | HMAC (SPA_HMAC_LEN bytes) ]

#define SPA_PACKET_MIN_LEN (SPA_IV_LEN + sizeof(spa_data_t) + SPA_HMAC_LEN)
// Max length depends on padding, but roughly:
#define SPA_PACKET_MAX_LEN (SPA_IV_LEN + sizeof(spa_data_t) + SPA_IV_LEN + SPA_HMAC_LEN) // Add block size for padding


// Helper function prototype (implementation in common .c or duplicated)
const char* protocol_to_string(int proto);
int string_to_protocol(const char* proto_str);


#endif // SPA_COMMON_H