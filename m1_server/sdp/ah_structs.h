// ah_structs.h
#ifndef AH_STRUCTS_H
#define AH_STRUCTS_H

#include <stdint.h>
#include <time.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include "spa_common.h" // For MAX_KEY_LEN etc.

// Structure to hold onboarding config loaded from ah_onboard.conf
typedef struct {
   char controller_ip[INET_ADDRSTRLEN];
   unsigned char enc_key[MAX_KEY_LEN]; size_t enc_key_len;
   unsigned char hmac_key[MAX_KEY_LEN]; size_t hmac_key_len;
   unsigned char hotp_secret[MAX_KEY_LEN]; size_t hotp_secret_len;
   char ca_cert_path[256];
   char client_cert_path[256];
   char client_key_path[256];
   char my_ip[INET_ADDRSTRLEN]; // AH's own IP
   int has_enc, has_hmac, has_hotp, has_ca, has_cert, has_key, has_my_ip;
} ah_onboard_config_t;

// Structure to hold state information for the AH
typedef struct {
   uint64_t controller_hotp_counter; // Counter for SPA *to* Controller
   // No per-client counters needed here, they are in session_policy_t
} ah_state_t;

// Structure to store temporary session policy received from Controller
typedef struct ah_session_policy {
   char ih_ip[INET_ADDRSTRLEN];    // Allowed Initiating Host IP
   uint8_t service_proto;         // Requested protocol
   uint16_t service_port;          // Requested port (on AH)
   uint16_t ah_mtls_listen_port;   // Port AH should listen on for this session's mTLS
   char target_service_ip[INET_ADDRSTRLEN]; // Real service IP (usually 127.0.0.1)
   uint16_t target_service_port;  // Real service port (e.g., 38472)

   // Ephemeral Credentials for IH <-> AH communication
   unsigned char spa_enc_key[MAX_KEY_LEN]; size_t spa_enc_key_len;
   unsigned char spa_hmac_key[MAX_KEY_LEN]; size_t spa_hmac_key_len;
   unsigned char hotp_secret[MAX_KEY_LEN]; size_t hotp_secret_len;
   uint64_t hotp_next_counter;     // Expected *next* HOTP counter from IH

   // Paths to temporary PEM files saved by AH
   char ih_eph_cert_path[256];
   char ah_eph_cert_path[256];
   char ah_eph_key_path[256];     // AH needs its own ephemeral key

   time_t expiry_time;            // When this policy expires
   int active;                    // Is this policy currently active (mTLS tunnel up)?

   struct ah_session_policy *next; // For linked list
} ah_session_policy_t;

// Structure for passing data to AH's client mTLS handler threads
typedef struct {
    SSL *ssl;                      // The client SSL connection
    char peer_ip[INET_ADDRSTRLEN]; // Client's IP
    ah_session_policy_t *policy;   // Pointer to the relevant policy entry
} ah_client_conn_data_t;


// Global state (extern declarations if used across multiple .c files)
// If all in ah.c, can be static globals
// extern ah_onboard_config_t g_ah_onboard_conf;
// extern ah_state_t g_ah_state;
// extern ah_session_policy_t *g_session_policies;
// extern pthread_mutex_t g_policy_list_lock;
// extern SSL_CTX *g_controller_mtls_ctx; // Context for talking TO controller
// extern SSL *g_controller_ssl;          // Connection TO controller
// extern pthread_mutex_t g_controller_ssl_lock;

#endif // AH_STRUCTS_H