// controller_structs.h
#ifndef CONTROLLER_STRUCTS_H
#define CONTROLLER_STRUCTS_H

#include <stdint.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include "spa_common.h" // For MAX_KEY_LEN etc.

// Structure to hold onboarding info loaded from controller_onboard.conf
typedef struct onboard_credential { // Renamed struct tag for clarity
    char entity_ip[INET_ADDRSTRLEN];
    unsigned char enc_key[MAX_KEY_LEN];
    size_t enc_key_len;
    unsigned char hmac_key[MAX_KEY_LEN];
    size_t hmac_key_len;
    unsigned char hotp_secret[MAX_KEY_LEN];
    size_t hotp_secret_len;
    uint64_t hotp_next_counter; // Expected next counter value
    // Flags for parsing
    int has_enc;
    int has_hmac;
    int has_hotp;
    int has_counter;
    struct onboard_credential *next; // <<< ADDED THIS LINE
} onboard_credential_t;

// Structure for master policy rules loaded from controller_policy.conf
typedef struct policy_rule {
    char ih_ip[INET_ADDRSTRLEN];
    uint8_t service_proto;
    uint16_t service_port; // 0 for 'any'
    char ah_ip[INET_ADDRSTRLEN];
    struct policy_rule *next;
} policy_rule_t;

// Structure to track connected AHs
typedef struct connected_ah {
    char ah_ip[INET_ADDRSTRLEN];
    SSL* ssl_conn; // The active mTLS connection socket to this AH
    pthread_mutex_t lock; // Mutex to protect access to ssl_conn
    struct connected_ah *next;
} connected_ah_t;

// Structure passed to the mTLS connection handler thread
typedef struct {
    SSL *ssl; // The SSL connection for this client/AH
    char peer_ip[INET_ADDRSTRLEN]; // IP address of the connected peer
} connection_thread_data_t;

// Global state (extern declarations)
extern onboard_credential_t *g_onboard_creds;
extern policy_rule_t *g_policy_rules;
extern connected_ah_t *g_connected_ahs;
extern pthread_mutex_t g_onboard_lock;
extern pthread_mutex_t g_policy_lock;
extern pthread_mutex_t g_ah_list_lock;

#endif // CONTROLLER_STRUCTS_H