// controller.c
#define _GNU_SOURCE // For asprintf
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <sys/stat.h> // For mkdir
#include <sys/wait.h> // For system call checks
#include <sys/socket.h> // For struct sockaddr_in if needed directly
#include <netinet/in.h> // For struct sockaddr_in
#include <arpa/inet.h>  // For inet_pton


#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/conf.h>
#include <openssl/rand.h>


#include "spa_common.h"
#include "controller_structs.h"


// --- Define Global Variables (implementation) ---
// These lists hold the persistent state loaded from config or generated dynamically
onboard_credential_t *g_onboard_creds = NULL; // Populated by spa_server_controller.c
policy_rule_t *g_policy_rules = NULL;         // Populated by load_policy_rules here or elsewhere
connected_ah_t *g_connected_ahs = NULL;       // Populated by handle_connections_controller.c


// Mutexes declared extern in header, defined here for linking
pthread_mutex_t g_onboard_lock = PTHREAD_MUTEX_INITIALIZER;    // Protects g_onboard_creds (write access)
pthread_mutex_t g_policy_lock = PTHREAD_MUTEX_INITIALIZER;     // Protects g_policy_rules
pthread_mutex_t g_ah_list_lock = PTHREAD_MUTEX_INITIALIZER;    // Protects g_connected_ahs list structure


// --- Configuration Paths (Make these configurable later) ---
#define CA_KEY_PATH "controller_ca.key"         // CA Private Key
#define CA_CERT_PATH "controller_ca.crt"        // CA Certificate
#define POLICY_CONFIG_FILE "controller_policy.conf" // Master access policy file
#define EPH_CERT_DURATION_DAYS 1                // Ephemeral certs valid for 1 day


// --- Function Prototypes (Internal to controller.c) ---
// Policy Management
int load_policy_rules(const char *filename);
void free_policy_rules(policy_rule_t *head);
int check_policy(const char* ih_ip, uint8_t service_proto, uint16_t service_port, const char* ah_ip);


// Connected AH Management
connected_ah_t* find_connected_ah(const char* ah_ip); // Returns with g_ah_list_lock HELD!
int add_connected_ah(const char* ah_ip, SSL* ssl_conn);
int remove_connected_ah(const char* ah_ip);


// Credential Generation & Distribution
int generate_ephemeral_creds(const char* entity_cn, char** cert_pem_out, char** key_pem_out);
int notify_ah_with_creds(const char* ah_ip, const char* ih_ip, uint8_t service_proto, uint16_t service_port,
                         const char* ih_eph_cert_pem, const char* ah_eph_cert_pem,
                         const char* ah_eph_key_pem, // <<< ADDED AH KEY PEM
                         const unsigned char* eph_spa_enc_key, size_t eph_spa_enc_key_len,
                         const unsigned char* eph_spa_hmac_key, size_t eph_spa_hmac_key_len,
                         const unsigned char* eph_hotp_secret, size_t eph_hotp_secret_len);


// --- Assumed external functions (defined in other .c files linked) ---
// From spa_common.c (prototypes should be in spa_common.h)
extern char* trim_whitespace(char *str);
extern int string_to_protocol(const char* proto_str);
extern int hex_string_to_bytes(const char *hex_string, unsigned char *byte_array, size_t max_len);
extern int send_data_over_mtls(SSL *ssl, const char *data);
extern const char* protocol_to_string(int proto); // Added prototype assumption
extern void handle_openssl_error(const char *msg); // Added prototype assumption
// From spa_server_controller.c or elsewhere:
extern onboard_credential_t* find_onboard_credential(const char *ip_str); // Read access, lock may be needed if dynamic
extern void free_onboard_credentials(onboard_credential_t *head);


// --- Policy Loading ---
int load_policy_rules(const char *filename) {
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        perror("Error opening policy config file");
        fprintf(stderr,"[CTRL] Could not open policy file: %s\n", filename);
        return 0;
    }
    printf("[CTRL] Loading policy rules from: %s\n", filename);


    char line[1024];
    int line_num = 0;
    int rules_loaded = 0;


    pthread_mutex_lock(&g_policy_lock); // Lock for exclusive write access
    free_policy_rules(g_policy_rules); // Clear existing rules before load
    g_policy_rules = NULL; // Reset head pointer


    while (fgets(line, sizeof(line), fp)) {
        line_num++;
        char *trimmed_line = trim_whitespace(line);
        if (!trimmed_line || trimmed_line[0] == '\0' || trimmed_line[0] == '#') {
            continue; // Skip empty/comment lines
        }


        // Format: Allow <IH_IP> <Service_Proto/Port_or_any> <AH_IP>
        char *action = strtok(trimmed_line, " \t");
        char *ih_ip_str = strtok(NULL, " \t");
        char *service_str = strtok(NULL, " \t");
        char *ah_ip_str = strtok(NULL, " \t");


        if (!action || !ih_ip_str || !service_str || !ah_ip_str || strcasecmp(action, "Allow") != 0) {
            fprintf(stderr, "[CTRL] Warn: Malformed policy line %d: %s\n", line_num, line);
            continue;
        }


        // Parse service string (proto/port)
        char *proto_part = strtok(service_str, "/");
        char *port_part = strtok(NULL, "/");
        if (!proto_part || !port_part) {
            fprintf(stderr, "[CTRL] Warn: Malformed service '%s' in policy line %d\n", service_str, line_num);
            continue;
        }


        int proto = string_to_protocol(proto_part);
        if (proto < 0) {
            proto = atoi(proto_part); // Try parsing as number
            if (proto <= 0 || proto > 255) {
                fprintf(stderr, "[CTRL] Warn: Invalid protocol '%s' in policy line %d\n", proto_part, line_num);
                continue;
            }
        }


        uint16_t port;
        if (strcasecmp(port_part, "any") == 0) {
            port = 0; // 0 represents 'any' port for the given protocol
        } else {
            int p = atoi(port_part);
            if (p <= 0 || p > 65535) {
                fprintf(stderr, "[CTRL] Warn: Invalid port '%s' in policy line %d\n", port_part, line_num);
                continue;
            }
            port = (uint16_t)p;
        }


        // Basic IP validation using inet_pton
        struct sockaddr_in sa_ih, sa_ah;
        if (inet_pton(AF_INET, ih_ip_str, &sa_ih.sin_addr) != 1 || inet_pton(AF_INET, ah_ip_str, &sa_ah.sin_addr) != 1) {
            fprintf(stderr, "[CTRL] Warn: Invalid IP address format in policy line %d\n", line_num);
            continue;
        }


        // Add rule to the linked list
        policy_rule_t *new_rule = malloc(sizeof(policy_rule_t));
        if (!new_rule) {
            perror("[CTRL] malloc policy rule failed");
            // Abort loading further rules, but keep loaded ones
            break;
        }
        memset(new_rule, 0, sizeof(policy_rule_t)); // Initialize memory


        strncpy(new_rule->ih_ip, ih_ip_str, INET_ADDRSTRLEN - 1);
        new_rule->ih_ip[INET_ADDRSTRLEN - 1] = '\0'; // Ensure null termination
        strncpy(new_rule->ah_ip, ah_ip_str, INET_ADDRSTRLEN - 1);
        new_rule->ah_ip[INET_ADDRSTRLEN - 1] = '\0';


        new_rule->service_proto = (uint8_t)proto;
        new_rule->service_port = port; // Host byte order


        // Add to the beginning of the list
        new_rule->next = g_policy_rules;
        g_policy_rules = new_rule;


        rules_loaded++;
    }


    fclose(fp);
    pthread_mutex_unlock(&g_policy_lock); // Unlock policy list


    printf("[CTRL] Loaded %d policy rules.\n", rules_loaded);
    return rules_loaded >= 0; // Return true even if 0 rules loaded, false only on file open error
}


// Free the policy linked list
void free_policy_rules(policy_rule_t *head) {
    // Note: Assumes caller holds the g_policy_lock if needed
    policy_rule_t *current = head;
    policy_rule_t *next;
    printf("[CTRL] Freeing policy rules list...\n");
    while (current != NULL) {
        next = current->next;
        free(current);
        current = next;
    }
    // g_policy_rules should be set to NULL by the caller (load_policy_rules) after calling this
}


// Check if a specific request is allowed by the loaded policy rules
int check_policy(const char* ih_ip, uint8_t service_proto, uint16_t service_port, const char* ah_ip) {
    pthread_mutex_lock(&g_policy_lock); // Lock for read access
    policy_rule_t *rule = g_policy_rules;
    int allowed = 0;


    printf("[CTRL_POLICY] Checking: IH=%s, Service=%s/%u, AH=%s\n",
           ih_ip, protocol_to_string(service_proto), service_port, ah_ip);


    while (rule != NULL) {
        // Compare IH IP and AH IP first
        if (strcmp(rule->ih_ip, ih_ip) == 0 && strcmp(rule->ah_ip, ah_ip) == 0) {
            printf("  Comparing with rule: IH=%s, Service=%s/%u, AH=%s\n",
                   rule->ih_ip, protocol_to_string(rule->service_proto), rule->service_port, rule->ah_ip);


            // Check if protocol matches
            if (rule->service_proto == service_proto) {
                // Check if port matches OR the rule allows 'any' port (0)
                if (rule->service_port == service_port || rule->service_port == 0) {
                    allowed = 1;
                    printf("  POLICY MATCH!\n");
                    break; // Found a matching rule, no need to check further
                }
            }
        }
        rule = rule->next;
    }


    pthread_mutex_unlock(&g_policy_lock);
    printf("[CTRL_POLICY] Result: %s\n", allowed ? "ALLOWED" : "DENIED");
    return allowed;
}


// --- Connected AH Management ---


// Find a connected AH entry by IP address.
// IMPORTANT: Returns with g_ah_list_lock HELD if found, caller MUST unlock.
// Returns NULL if not found (lock is released in that case).
connected_ah_t* find_connected_ah(const char* ah_ip) {
    pthread_mutex_lock(&g_ah_list_lock);
    connected_ah_t *curr = g_connected_ahs;
    while(curr) {
        if (strcmp(curr->ah_ip, ah_ip) == 0) {
            // Found it. Return pointer WHILE HOLDING THE LIST LOCK.
            // Caller must unlock g_ah_list_lock after processing.
            return curr;
        }
        curr = curr->next;
    }
    // Not found
    pthread_mutex_unlock(&g_ah_list_lock);
    return NULL;
}


// Add a new AH to the list of connected AHs.
int add_connected_ah(const char* ah_ip, SSL* ssl_conn) {
    if (!ah_ip || !ssl_conn) return 0;


    printf("[CTRL_AH] Attempting to add connected AH: %s\n", ah_ip);


    // First, check if it's already there to prevent duplicates
    pthread_mutex_lock(&g_ah_list_lock);
    connected_ah_t *existing = g_connected_ahs;
    while (existing) {
        if (strcmp(existing->ah_ip, ah_ip) == 0) {
            fprintf(stderr,"[CTRL_AH] Error: AH %s is already in the connected list!\n", ah_ip);
            pthread_mutex_unlock(&g_ah_list_lock);
            // Maybe update the SSL* connection here? Or just fail? Let's fail for now.
            return 0;
        }
        existing = existing->next;
    }
    // If we reach here, it's not in the list yet. Keep list lock held.


    // Create the new entry
    connected_ah_t *new_ah = malloc(sizeof(connected_ah_t));
    if (!new_ah) {
        perror("[CTRL_AH] malloc for connected_ah_t failed");
        pthread_mutex_unlock(&g_ah_list_lock);
        return 0;
    }
    memset(new_ah, 0, sizeof(connected_ah_t));


    strncpy(new_ah->ah_ip, ah_ip, INET_ADDRSTRLEN - 1);
    new_ah->ah_ip[INET_ADDRSTRLEN - 1] = '\0';
    new_ah->ssl_conn = ssl_conn; // Store the SSL pointer


    // Initialize the mutex for this specific AH entry
    if (pthread_mutex_init(&new_ah->lock, NULL) != 0) {
         perror("[CTRL_AH] Failed to initialize mutex for new AH entry");
         free(new_ah);
         pthread_mutex_unlock(&g_ah_list_lock);
         return 0;
    }


    // Add to the front of the global list
    new_ah->next = g_connected_ahs;
    g_connected_ahs = new_ah;


    pthread_mutex_unlock(&g_ah_list_lock); // Release list lock
    printf("[CTRL_AH] Successfully added connected AH: %s\n", ah_ip);
    return 1;
}


// Remove an AH from the connected list.
int remove_connected_ah(const char* ah_ip) {
    if (!ah_ip) return 0;
    printf("[CTRL_AH] Attempting to remove connected AH: %s\n", ah_ip);


    pthread_mutex_lock(&g_ah_list_lock); // Lock the list for modification
    connected_ah_t *curr = g_connected_ahs;
    connected_ah_t *prev = NULL;
    int found = 0;


    while (curr != NULL) {
        if (strcmp(curr->ah_ip, ah_ip) == 0) {
            // Found the entry to remove
            if (prev == NULL) {
                // Removing the head of the list
                g_connected_ahs = curr->next;
            } else {
                // Removing an entry in the middle or end
                prev->next = curr->next;
            }


            // Unlock the LIST lock BEFORE destroying the node's mutex/memory
            pthread_mutex_unlock(&g_ah_list_lock);


            printf("[CTRL_AH] Removing AH node %s from list.\n", ah_ip);


            // The SSL* connection itself should be closed by the thread
            // that detected the disconnection *before* calling remove_connected_ah.
            // We just clean up the list node structure here.
            pthread_mutex_destroy(&curr->lock); // Destroy the node's mutex
            free(curr); // Free the list node memory
            found = 1;
            printf("[CTRL_AH] AH %s removed successfully.\n", ah_ip);
            return 1; // Exit loop and function after removal
        }
        // Move to the next node
        prev = curr;
        curr = curr->next;
    }


    // If the loop finishes without finding the entry
    pthread_mutex_unlock(&g_ah_list_lock); // Unlock list lock


    if (!found) {
        fprintf(stderr, "[CTRL_AH] Warn: AH %s not found in connected list for removal.\n", ah_ip);
    }
    return 0; // Not found
}


// --- Ephemeral Credential Generation (REVISED with Robust File Reading) ---
int generate_ephemeral_creds(const char* entity_cn, char** cert_pem_out, char** key_pem_out) {
    if (!entity_cn || !cert_pem_out || !key_pem_out) {
        fprintf(stderr, "[CTRL_CA] Error: Invalid arguments to generate_ephemeral_creds.\n");
        return 0;
    }


    *cert_pem_out = NULL;
    *key_pem_out = NULL;


    char key_file[128]; char csr_file[128]; char cert_file[128]; char serial_file[128];
    pid_t pid = getpid();
    snprintf(key_file, sizeof(key_file), "/tmp/eph_%s_%d.key", entity_cn, pid);
    snprintf(csr_file, sizeof(csr_file), "/tmp/eph_%s_%d.csr", entity_cn, pid);
    snprintf(cert_file, sizeof(cert_file), "/tmp/eph_%s_%d.crt", entity_cn, pid);
    snprintf(serial_file, sizeof(serial_file), "/tmp/eph_ca_%d.srl", pid);


    char *cmd = NULL;
    int sys_ret = 0;
    int success = 0; // Use 0 for failure, 1 for success
    FILE *fp = NULL;
    long file_len = 0;
    size_t read_len = 0;


    printf("[CTRL_CA] Generating ephemeral key for %s...\n", entity_cn);
    sys_ret = asprintf(&cmd, "openssl genpkey -algorithm RSA -out %s -pkeyopt rsa_keygen_bits:2048 > /dev/null 2>&1", key_file);
    if (sys_ret == -1 || system(cmd) != 0) { fprintf(stderr, "[CTRL_CA] Failed to generate ephemeral key\n"); free(cmd); cmd=NULL; goto eph_cleanup; }
    free(cmd); cmd = NULL;


    printf("[CTRL_CA] Generating ephemeral CSR for %s...\n", entity_cn);
    sys_ret = asprintf(&cmd, "openssl req -new -key %s -subj \"/CN=%s/O=MyOrg_Ephemeral\" -out %s > /dev/null 2>&1", key_file, entity_cn, csr_file);
    if (sys_ret == -1 || system(cmd) != 0) { fprintf(stderr, "[CTRL_CA] Failed to generate ephemeral CSR\n"); free(cmd); cmd=NULL; goto eph_cleanup; }
    free(cmd); cmd = NULL;


    printf("[CTRL_CA] Signing ephemeral CSR for %s using CA %s...\n", entity_cn, CA_CERT_PATH);
    // Try signing, attempt to create serial file if needed
    int sign_attempts = 0;
    while (sign_attempts < 2) {
        sys_ret = asprintf(&cmd, "openssl x509 -req -in %s -CA %s -CAkey %s -CAserial %s -out %s -days %d -sha256 > /dev/null 2>&1",
                          csr_file, CA_CERT_PATH, CA_KEY_PATH, serial_file, cert_file, EPH_CERT_DURATION_DAYS);
        if (sys_ret == -1) { free(cmd); cmd=NULL; goto eph_cleanup; } // asprintf error
        sys_ret = system(cmd);
        free(cmd); cmd = NULL;

        if (sys_ret == 0) break; // Success!

        // Check if it failed because serial file didn't exist
        FILE *check_srl = fopen(serial_file, "r");
        if (!check_srl && sign_attempts == 0) { // Serial doesn't exist, first attempt
            printf("[CTRL_CA] Serial file %s not found, attempting to create...\n", serial_file);
            FILE *srl_fp = fopen(serial_file, "w");
            if (srl_fp) { fprintf(srl_fp, "01\n"); fclose(srl_fp); }
            else { perror("[CTRL_CA] Failed to create serial file"); goto eph_cleanup; }
        } else {
            // Either serial exists but signing failed, or failed on second attempt
            if (check_srl) fclose(check_srl);
            fprintf(stderr, "[CTRL_CA] Failed to sign ephemeral CSR (system ret: %d)\n", sys_ret);
            goto eph_cleanup;
        }
        sign_attempts++;
    }
    if (sys_ret != 0) { goto eph_cleanup; } // Failed signing


    printf("[CTRL_CA] Reading generated key PEM %s...\n", key_file);
    fp = fopen(key_file, "rb");
    if (!fp) { perror("[CTRL_CA] Failed to open ephemeral key file"); goto eph_cleanup; }
    fseek(fp, 0, SEEK_END); file_len = ftell(fp); fseek(fp, 0, SEEK_SET);
    if (file_len <= 0) { fclose(fp); fp = NULL; fprintf(stderr, "[CTRL_CA] Ephemeral key file is empty.\n"); goto eph_cleanup; }
    *key_pem_out = malloc(file_len + 1);
    if (!*key_pem_out) { fclose(fp); fp = NULL; perror("[CTRL_CA] malloc for key PEM failed"); goto eph_cleanup; }
    read_len = fread(*key_pem_out, 1, file_len, fp);
    if (read_len != (size_t)file_len) { // *** Robustness Check ***
        fclose(fp); fp = NULL; free(*key_pem_out); *key_pem_out = NULL;
        fprintf(stderr, "[CTRL_CA] Failed to read ephemeral key file fully (read %zu, expected %ld).\n", read_len, file_len); goto eph_cleanup;
    }
    (*key_pem_out)[file_len] = '\0';
    fclose(fp); fp = NULL;


    printf("[CTRL_CA] Reading generated certificate PEM %s...\n", cert_file);
    fp = fopen(cert_file, "rb");
    if (!fp) { perror("[CTRL_CA] Failed to open ephemeral cert file"); goto eph_cleanup; }
    fseek(fp, 0, SEEK_END); file_len = ftell(fp); fseek(fp, 0, SEEK_SET);
    if (file_len <= 0) { fclose(fp); fp = NULL; fprintf(stderr, "[CTRL_CA] Ephemeral cert file is empty.\n"); goto eph_cleanup; }
    *cert_pem_out = malloc(file_len + 1);
    if (!*cert_pem_out) { fclose(fp); fp = NULL; perror("[CTRL_CA] malloc for cert PEM failed"); goto eph_cleanup; }
    read_len = fread(*cert_pem_out, 1, file_len, fp);
     if (read_len != (size_t)file_len) { // *** Robustness Check ***
        fclose(fp); fp = NULL; free(*cert_pem_out); *cert_pem_out = NULL;
        fprintf(stderr, "[CTRL_CA] Failed to read ephemeral cert file fully (read %zu, expected %ld).\n", read_len, file_len); goto eph_cleanup;
    }
    (*cert_pem_out)[file_len] = '\0';
    fclose(fp); fp = NULL;


    printf("[CTRL_CA] Successfully generated ephemeral credentials for %s\n", entity_cn);
    success = 1; // Mark success


eph_cleanup:
    if (fp) fclose(fp);
    if (cmd) free(cmd);
    remove(key_file); remove(csr_file); remove(cert_file); remove(serial_file);


    if (!success) { // If anything failed
        printf("[CTRL_CA] Cleaning up allocated PEM strings due to failure.\n");
        if (*key_pem_out) { free(*key_pem_out); *key_pem_out = NULL; }
        if (*cert_pem_out) { free(*cert_pem_out); *cert_pem_out = NULL; }
    }
    return success; // Return 1 on success, 0 on failure
}


// --- Notify AH with Ephemeral Credentials ---
int notify_ah_with_creds(const char* ah_ip, const char* ih_ip, uint8_t service_proto, uint16_t service_port,
                         const char* ih_eph_cert_pem, const char* ah_eph_cert_pem,
                         const char* ah_eph_key_pem, // <<< AH KEY PEM argument
                         const unsigned char* eph_spa_enc_key, size_t eph_spa_enc_key_len,
                         const unsigned char* eph_spa_hmac_key, size_t eph_spa_hmac_key_len,
                         const unsigned char* eph_hotp_secret, size_t eph_hotp_secret_len)
{
    // *** Add NULL checks for mandatory PEM strings ***
    if (!ih_eph_cert_pem || !ah_eph_cert_pem || !ah_eph_key_pem) {
         fprintf(stderr, "[CTRL] Error: NULL PEM string passed to notify_ah_with_creds!\n");
         return 0;
    }

    printf("[CTRL] Preparing to notify AH %s about IH %s access request...\n", ah_ip, ih_ip);
    connected_ah_t* ah_conn = find_connected_ah(ah_ip); // Returns with list lock HELD
    if (!ah_conn) { fprintf(stderr, "[CTRL] Error: Cannot notify AH %s (not connected).\n", ah_ip); return 0; }

    pthread_mutex_lock(&ah_conn->lock); // Lock specific AH entry
    pthread_mutex_unlock(&g_ah_list_lock); // Release global list lock

    SSL* ah_ssl = ah_conn->ssl_conn;
    if (!ah_ssl) {
        fprintf(stderr, "[CTRL] Error: AH %s connection is NULL after locking.\n", ah_ip);
        pthread_mutex_unlock(&ah_conn->lock);
        return 0;
    }

    // Convert binary SPA keys to hex
    char spa_enc_hex[MAX_KEY_LEN * 2 + 1]; char spa_hmac_hex[MAX_KEY_LEN * 2 + 1]; char hotp_secret_hex[MAX_KEY_LEN * 2 + 1];
    memset(spa_enc_hex, 0, sizeof(spa_enc_hex)); memset(spa_hmac_hex, 0, sizeof(spa_hmac_hex)); memset(hotp_secret_hex, 0, sizeof(hotp_secret_hex));
    for(size_t i = 0; i < eph_spa_enc_key_len; ++i) sprintf(spa_enc_hex + i * 2, "%02x", eph_spa_enc_key[i]);
    for(size_t i = 0; i < eph_spa_hmac_key_len; ++i) sprintf(spa_hmac_hex + i * 2, "%02x", eph_spa_hmac_key[i]);
    for(size_t i = 0; i < eph_hotp_secret_len; ++i) sprintf(hotp_secret_hex + i * 2, "%02x", eph_hotp_secret[i]);

    // Construct the notification message
    char *message = NULL;
    int msg_len = asprintf(&message,
             "NEW_SESSION\nIH_IP:%s\nSERVICE_PROTO:%u\nSERVICE_PORT:%u\n"
             "SPA_ENC_KEY:%s\nSPA_HMAC_KEY:%s\nHOTP_SECRET:%s\nHOTP_COUNTER:0\n"
             "IH_EPH_CERT:%s\nAH_EPH_CERT:%s\nAH_EPH_KEY:%s\nEND_SESSION\n", // Included AH_EPH_KEY
             ih_ip, service_proto, service_port,
             spa_enc_hex, spa_hmac_hex, hotp_secret_hex,
             ih_eph_cert_pem, ah_eph_cert_pem, ah_eph_key_pem); // Pass AH key PEM

    int success = 0;
    if (msg_len > 0 && message) {
        printf("[CTRL] Sending NEW_SESSION notification to AH %s (%d bytes)\n", ah_ip, msg_len);
        if (send_data_over_mtls(ah_ssl, message) > 0) {
            success = 1;
            printf("[CTRL] Notification sent successfully to AH %s.\n", ah_ip);
        } else {
            fprintf(stderr, "[CTRL] Failed to send notification to AH %s. Connection likely lost.\n", ah_ip);
            // Let handler thread detect and clean up the connection
        }
        free(message);
    } else {
        perror("[CTRL] asprintf failed for AH notification message");
        fprintf(stderr,"[CTRL] Failed to construct notification message for AH %s.\n", ah_ip);
    }

    pthread_mutex_unlock(&ah_conn->lock); // Unlock specific AH entry
    return success;
}

