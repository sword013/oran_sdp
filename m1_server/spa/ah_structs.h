// ah_structs.h
#ifndef AH_STRUCTS_H
#define AH_STRUCTS_H

#include <stdint.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include "spa_common.h"

// Structure for ephemeral client permissions loaded from access_ah.conf
typedef struct ephemeral_policy {
    char ih_ip_str[INET_ADDRSTRLEN];
    unsigned char enc_key[MAX_KEY_LEN];
    size_t enc_key_len;
    unsigned char hmac_key[MAX_KEY_LEN];
    size_t hmac_key_len;
    unsigned char hotp_secret[MAX_KEY_LEN];
    size_t hotp_secret_len;
    uint64_t hotp_next_counter;
    uint8_t allowed_proto;
    uint16_t allowed_port; // 0 for any
    time_t expiry_timestamp;
    // Parsing flags
    int has_enc, has_hmac, has_hotp, has_counter, has_proto, has_port, has_expiry;
    struct ephemeral_policy *next;
} ephemeral_policy_t;

// Structure for controller onboarding config (subset of client/controller version)
typedef struct {
    char controller_ip[INET_ADDRSTRLEN];
    char ca_cert_path[256];
    char client_cert_path[256]; // AH's cert
    char client_key_path[256];  // AH's key
} ah_onboard_config_t;

// Structure passed to AH mTLS connection handler thread
typedef struct {
    SSL *ssl; // Connection from IH
    char peer_ip[INET_ADDRSTRLEN];
    uint8_t target_service_proto; // Backend service proto/port
    uint16_t target_service_port;
    char target_service_ip[INET_ADDRSTRLEN]; // Backend service IP (usually loopback/local)
} ah_thread_data_t;


// Globals for AH
extern ephemeral_policy_t *g_ephemeral_policies;
extern pthread_mutex_t g_eph_policy_lock; // Mutex for ephemeral policy list/file access
extern SSL_CTX *g_controller_ssl_ctx;   // SSL context for talking TO controller
extern SSL *g_controller_ssl_conn;      // Persistent connection TO controller
extern pthread_mutex_t g_ctrl_conn_lock; // Lock for controller connection

#endif // AH_STRUCTS_H