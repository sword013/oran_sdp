// spa_server_controller.c
#define _GNU_SOURCE // For asprintf
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/err.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <ifaddrs.h>
#include <unistd.h>
#include <netdb.h>
#include <ctype.h>
#include <pthread.h> // Include pthread
#include <endian.h>

#include "spa_common.h"
#include "controller_structs.h" // Include controller-specific structs

// --- Function Prototypes ---
void spa_controller_cleanup(int signo);
int load_onboard_credentials(const char *filename); // Specific loader
onboard_credential_t* find_onboard_credential(const char *ip_str);
void free_onboard_credentials(onboard_credential_t *head);
// Assumed external or defined elsewhere:
// handle_openssl_error_server, constant_time_memcmp, get_interface_ip,
// protocol_to_string, string_to_protocol, trim_whitespace, hex_string_to_bytes

// --- Global Variables ---
pcap_t *spa_pcap_handle = NULL;
extern onboard_credential_t *g_onboard_creds; // Declared, not defined
extern pthread_mutex_t g_onboard_lock;        // Declared, not defined
// Other globals (policy, ah_list) managed by controller.c/handle_connections_controller.c

// --- Config Loading ---
int load_onboard_credentials(const char *filename) {
    // Similar logic to load_policies_ip_keyed, but populates onboard_credential_t
    FILE *fp = fopen(filename, "r");
    if (!fp) { perror("Error opening onboard cred file"); return 0; }
    printf("[SPA_CTRL] Loading onboarding credentials from: %s\n", filename);

    char line[1024]; int line_num = 0; int creds_loaded = 0;
    onboard_credential_t *current_cred = NULL;

    while (fgets(line, sizeof(line), fp)) {
        line_num++;
        char *trimmed_line = trim_whitespace(line);
        if (!trimmed_line || trimmed_line[0] == '\0' || trimmed_line[0] == '#') continue;

        if (trimmed_line[0] == '[' && trimmed_line[strlen(trimmed_line) - 1] == ']') {
            if (current_cred) { // Finalize previous
                if(current_cred->has_enc && current_cred->has_hmac && current_cred->has_hotp && current_cred->has_counter) {
                   current_cred->next = g_onboard_creds; g_onboard_creds = current_cred; creds_loaded++;
                   printf("  + Onboard creds loaded for: %s\n", current_cred->entity_ip);
                } else { fprintf(stderr,"[SPA_CTRL] Warn: Discard incomplete onboard entry for [%s] line %d\n", current_cred->entity_ip, line_num-1); free(current_cred); }
                current_cred = NULL;
            }
            // Start new
            current_cred = malloc(sizeof(onboard_credential_t));
            if (!current_cred) { perror("Malloc failed onboard cred"); fclose(fp); return 0; }
            memset(current_cred, 0, sizeof(onboard_credential_t));
            size_t id_len = strlen(trimmed_line) - 2;
            if (id_len == 0 || id_len >= INET_ADDRSTRLEN) {fprintf(stderr,"[SPA_CTRL] Invalid header line %d\n", line_num); free(current_cred); current_cred = NULL; continue; }
            strncpy(current_cred->entity_ip, trimmed_line + 1, id_len); current_cred->entity_ip[id_len] = '\0';
            struct sockaddr_in sa; if (inet_pton(AF_INET, current_cred->entity_ip, &sa.sin_addr)!=1){fprintf(stderr,"[SPA_CTRL] Invalid IP '%s' line %d\n",current_cred->entity_ip, line_num); free(current_cred); current_cred=NULL; continue;}
            printf("  Parsing onboard creds for IP: %s\n", current_cred->entity_ip);

        } else if (current_cred) {
             char *key = trimmed_line; char *value = NULL;
             for (char *p = key; *p != '\0'; ++p) { if (isspace((unsigned char)*p) || *p == '=') { *p = '\0'; value = p + 1; while (*value != '\0' && (isspace((unsigned char)*value) || *value == '=')) { value++; } break; } }

             if (value && *value != '\0') {
                key = trim_whitespace(key); value = trim_whitespace(value);
                if (strlen(key) == 0) continue;

                if (strcasecmp(key, "ENCRYPTION_KEY") == 0) { int len=hex_string_to_bytes(value, current_cred->enc_key, MAX_KEY_LEN); if(len>0){current_cred->enc_key_len=len; current_cred->has_enc=1;} else {fprintf(stderr,"[SPA_CTRL] Invalid ENC key line %d\n",line_num);} }
                else if (strcasecmp(key, "HMAC_KEY") == 0) { int len=hex_string_to_bytes(value, current_cred->hmac_key, MAX_KEY_LEN); if(len>0){current_cred->hmac_key_len=len; current_cred->has_hmac=1;} else {fprintf(stderr,"[SPA_CTRL] Invalid HMAC key line %d\n",line_num);} }
                else if (strcasecmp(key, "HOTP_SECRET") == 0) { int len=hex_string_to_bytes(value, current_cred->hotp_secret, MAX_KEY_LEN); if(len>0){current_cred->hotp_secret_len=len; current_cred->has_hotp=1;} else {fprintf(stderr,"[SPA_CTRL] Invalid HOTP secret line %d\n",line_num);} }
                else if (strcasecmp(key, "HOTP_NEXT_COUNTER") == 0) { current_cred->hotp_next_counter = strtoull(value, NULL, 10); current_cred->has_counter=1; }
                else { fprintf(stderr,"[SPA_CTRL] Warn: Unknown key '%s' line %d\n",key,line_num);}
            } else { fprintf(stderr,"[SPA_CTRL] Warn: Malformed line %d for %s\n",line_num,current_cred->entity_ip);}
        }
    }
    // Finalize last entry
     if (current_cred) { if(current_cred->has_enc && current_cred->has_hmac && current_cred->has_hotp && current_cred->has_counter) { current_cred->next = g_onboard_creds; g_onboard_creds = current_cred; creds_loaded++; printf("  + Onboard creds loaded for: %s\n", current_cred->entity_ip); } else { fprintf(stderr,"[SPA_CTRL] Warn: Discard incomplete onboard entry for [%s] EOF\n", current_cred->entity_ip); free(current_cred); } }

    fclose(fp);
    printf("[SPA_CTRL] Finished loading onboard credentials. %d entries loaded.\n", creds_loaded);
    return creds_loaded >= 0;
}

onboard_credential_t* find_onboard_credential(const char *ip_str) {
    if (!ip_str) return NULL;
    // No lock needed for read access if list is static after load
    onboard_credential_t *current = g_onboard_creds;
    while (current != NULL) {
        if (strcmp(current->entity_ip, ip_str) == 0) return current;
        current = current->next;
    }
    return NULL;
}

void free_onboard_credentials(onboard_credential_t *head) {
     onboard_credential_t *current = head, *next;
     printf("[SPA_CTRL] Freeing onboard credentials...\n");
     while(current){ next = current->next; free(current); current = next;}
     g_onboard_creds = NULL;
}

// --- Basic iptables Command Execution ---
// Very basic wrapper - consider more robust IPC or library for production
int run_iptables_rule(const char* action, const char* source_ip, uint16_t target_port) {
     char *command = NULL;
     int ret;
     // Simple rule allowing TCP to the controller's mTLS port
     if (asprintf(&command, "sudo iptables %s INPUT -s %s -p tcp --dport %u -m comment --comment \"SPA_CTRL_ALLOW_%s\" -j ACCEPT",
                  action, source_ip, target_port, source_ip) == -1) {
        perror("[SPA_CTRL] asprintf failed");
        return -1;
     }
     printf("[SPA_CTRL] Executing: %s\n", command);
     ret = system(command);
     free(command);

     if (ret == -1) { perror("[SPA_CTRL] system(iptables) failed"); return -1;}
     if (WIFEXITED(ret) && WEXITSTATUS(ret) == 0) {
         printf("[SPA_CTRL] iptables %s rule for %s successful.\n", action, source_ip);
         return 0; // Success
     } else {
         fprintf(stderr, "[SPA_CTRL] iptables %s rule for %s failed (status: %d)\n", action, source_ip, WEXITSTATUS(ret));
         return -1; // Failure
     }
}

// --- Packet Handler (Controller Onboarding SPA) ---
void spa_controller_packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    const int ETH_HDR_LEN = 14;
    char source_ip_str[INET_ADDRSTRLEN];
    struct tm *tm_info; time_t now; char time_buf[30];

    (void)user_data;

    now = time(NULL); tm_info = localtime(&now); strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", tm_info);
    printf("\n[%s] SPA Packet received (len %u)\n", time_buf, pkthdr->len);

    if (pkthdr->caplen < (unsigned int)ETH_HDR_LEN) return;
    const struct ip *ip_header = (struct ip *)(packet + ETH_HDR_LEN);
    int ip_hdr_len = ip_header->ip_hl * 4;
    if (pkthdr->caplen < (unsigned int)(ETH_HDR_LEN + ip_hdr_len)) return;
    if (ip_header->ip_p != IPPROTO_UDP) return;
    const struct udphdr *udp_header = (struct udphdr *)((u_char *)ip_header + ip_hdr_len);
    int udp_hdr_len = sizeof(struct udphdr);
    if (pkthdr->caplen < (unsigned int)(ETH_HDR_LEN + ip_hdr_len + udp_hdr_len)) return;

    inet_ntop(AF_INET, &(ip_header->ip_src), source_ip_str, INET_ADDRSTRLEN);
    printf("  Source IP: %s\n", source_ip_str);

    // --- Find Onboarding Credentials ---
    onboard_credential_t *creds = find_onboard_credential(source_ip_str);
    if (!creds) {
        printf("  -> Discarding: No onboard credentials found for source IP %s.\n", source_ip_str);
        return;
    }
    printf("  Onboarding creds found for %s. Validating SPA...\n", source_ip_str);

    // --- SPA Processing ---
    const u_char *payload = (u_char *)udp_header + udp_hdr_len;
    int payload_len = pkthdr->caplen - (ETH_HDR_LEN + ip_hdr_len + udp_hdr_len);
    if ((size_t)payload_len < SPA_PACKET_MIN_LEN || (size_t)payload_len > SPA_PACKET_MAX_LEN) {
        printf("  -> Discarding: Invalid payload len %d.\n", payload_len); return;
    }

    const unsigned char *iv = payload;
    const unsigned char *encrypted_data = payload + SPA_IV_LEN;
    int encrypted_len = payload_len - SPA_IV_LEN - SPA_HMAC_LEN;
    const unsigned char *received_hmac = payload + SPA_IV_LEN + encrypted_len;
    if (encrypted_len <= 0) { printf("  -> Discarding: Invalid encrypted len %d.\n", encrypted_len); return; }

    // --- 1. Verify HMAC (Onboarding Key) ---
    printf("  Verifying HMAC (Onboarding)... ");
    unsigned char calculated_hmac[EVP_MAX_MD_SIZE]; unsigned int calc_hmac_len = 0;
    const EVP_MD *digest = EVP_get_digestbyname(SPA_HMAC_ALGO); if (!digest) return;
    unsigned char data_to_hmac[SPA_IV_LEN + encrypted_len];
    memcpy(data_to_hmac, iv, SPA_IV_LEN); memcpy(data_to_hmac + SPA_IV_LEN, encrypted_data, encrypted_len);
    HMAC(digest, creds->hmac_key, creds->hmac_key_len, data_to_hmac, SPA_IV_LEN + encrypted_len, calculated_hmac, &calc_hmac_len);
    if (calc_hmac_len != SPA_HMAC_LEN || constant_time_memcmp(received_hmac, calculated_hmac, SPA_HMAC_LEN) != 0) {
        printf("FAILED (HMAC Mismatch)\n"); printf("  -> Discarding: Invalid HMAC for %s.\n", source_ip_str); return;
    }
    printf("OK\n");

    // --- 2. Decrypt Data (Onboarding Key) ---
    printf("  Decrypting data (Onboarding)... ");
    unsigned char decrypted_data[sizeof(spa_data_t)]; int decrypted_len = 0, final_len = 0; int decrypt_ok = 1;
    const EVP_CIPHER *cipher = EVP_get_cipherbyname(SPA_ENCRYPTION_ALGO); if (!cipher) return;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new(); if (!ctx) { handle_openssl_error("CTX New"); return; } // Use generic handler
    if (1!=EVP_DecryptInit_ex(ctx, cipher, NULL, creds->enc_key, iv)) { handle_openssl_error("DecryptInit"); decrypt_ok = 0; }
    if (decrypt_ok && 1!=EVP_DecryptUpdate(ctx, decrypted_data, &decrypted_len, encrypted_data, encrypted_len)) { ERR_clear_error(); decrypt_ok = 0; }
    if (decrypt_ok && 1!=EVP_DecryptFinal_ex(ctx, decrypted_data + decrypted_len, &final_len)) { ERR_clear_error(); decrypt_ok = 0; }
    EVP_CIPHER_CTX_free(ctx);
    if (!decrypt_ok) { printf("FAILED (Decryption Error)\n"); printf("  -> Discarding: Decryption failed for %s.\n", source_ip_str); return; }
    decrypted_len += final_len;
    printf("OK (Plaintext size %d)\n", decrypted_len);

    // --- 3. Validate Decrypted Payload & HOTP ---
    if ((size_t)decrypted_len != sizeof(spa_data_t)) { fprintf(stderr, " Error: Size %d != %zu.\n", decrypted_len, sizeof(spa_data_t)); return; }
    spa_data_t *spa_info = (spa_data_t *)decrypted_data;

    // Convert fields from Network to Host order for validation
    uint64_t received_timestamp = be64toh(spa_info->timestamp);
    uint64_t received_hotp_counter = be64toh(spa_info->hotp_counter);
    uint32_t received_hotp_code = ntohl(spa_info->hotp_code);

    if (spa_info->version != SPA_VERSION) { fprintf(stderr, "  Error: Invalid version %u.\n", spa_info->version); return; }
    time_t current_time = time(NULL); int64_t time_diff = (int64_t)current_time - (int64_t)received_timestamp;
    if (llabs(time_diff) > SPA_TIMESTAMP_WINDOW_SECONDS) { fprintf(stderr, "  Error: Timestamp invalid (Diff %llds > %ds).\n", (long long)time_diff, SPA_TIMESTAMP_WINDOW_SECONDS); return; }

    printf("  Timestamp/Version OK. Validating HOTP...\n");
    printf("    Received Counter: %llu, Received Code: %0*u\n", (unsigned long long)received_hotp_counter, HOTP_CODE_DIGITS, received_hotp_code);

    // HOTP Validation (Critical Section - Lock)
    pthread_mutex_lock(&g_onboard_lock); // Lock before accessing/modifying counter
    uint64_t expected_counter = creds->hotp_next_counter;
    int hotp_match = 0;
    uint64_t matched_counter = 0;

    // Check counter value is within reasonable range (not too far behind, not excessively ahead)
    if (received_hotp_counter < expected_counter || received_hotp_counter > expected_counter + HOTP_COUNTER_SYNC_WINDOW) {
        fprintf(stderr, "    HOTP Counter %llu out of sync window (expected >= %llu, <= %llu)\n",
                (unsigned long long)received_hotp_counter,
                (unsigned long long)expected_counter,
                (unsigned long long)(expected_counter + HOTP_COUNTER_SYNC_WINDOW));
    } else {
        // Check current and next few counter values (Sync Window)
        for (uint64_t counter_check = received_hotp_counter; counter_check <= expected_counter + HOTP_COUNTER_SYNC_WINDOW; ++counter_check) {
            uint32_t calculated_code = generate_hotp(creds->hotp_secret, creds->hotp_secret_len, counter_check, HOTP_CODE_DIGITS);
            printf("    Checking Counter: %llu -> Calculated Code: %0*u\n", (unsigned long long)counter_check, HOTP_CODE_DIGITS, calculated_code);
            if (calculated_code == received_hotp_code) {
                hotp_match = 1;
                matched_counter = counter_check;
                creds->hotp_next_counter = matched_counter + 1; // Update expected counter for next time
                printf("    HOTP MATCH FOUND at counter %llu! Updated next counter to %llu.\n",
                       (unsigned long long)matched_counter, (unsigned long long)creds->hotp_next_counter);
                break; // Found a match
            }
        }
    }
    pthread_mutex_unlock(&g_onboard_lock); // Unlock after check/update

    if (!hotp_match) {
        fprintf(stderr, "    HOTP Validation FAILED.\n");
        printf("  -> Discarding: Invalid HOTP for %s.\n", source_ip_str);
        return;
    }
    printf("  HOTP Validation OK.\n");

    // --- 4. Authorize Access to Controller mTLS Port ---
    printf("  VALID Onboarding SPA Packet from %s. Authorizing mTLS access...\n", source_ip_str);

    // Add iptables rule to allow TCP connection to CONTROLLER_MTLS_PORT
    if (run_iptables_rule("-I", source_ip_str, CONTROLLER_MTLS_PORT) == 0) {
        // Schedule removal of the rule (simplistic approach using background shell)
        char *remove_cmd = NULL;
        if (asprintf(&remove_cmd, "sh -c 'sleep %d && sudo iptables -D INPUT -s %s -p tcp --dport %u -m comment --comment \"SPA_CTRL_ALLOW_%s\" -j ACCEPT' &",
                     SPA_DEFAULT_DURATION_SECONDS, source_ip_str, CONTROLLER_MTLS_PORT, source_ip_str) != -1) {
            printf("  Scheduling iptables cleanup: %s\n", remove_cmd);
            system(remove_cmd); // Ignore return value for background task
            free(remove_cmd);
        } else {
            perror("[SPA_CTRL] asprintf failed for cleanup command");
        }
    } else {
        fprintf(stderr, "[SPA_CTRL] Failed to add iptables rule for %s\n", source_ip_str);
    }
    printf("----------------------------------------\n");
}


// --- Main SPA Server Function (Controller) ---
int main(int argc, char *argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE]; char *dev = NULL; bpf_u_int32 net, mask; struct bpf_program fp;
    char filter_exp[100]; int use_strdup = 0;

    if (geteuid() != 0) { fprintf(stderr, "[SPA_CTRL] Error: Requires root privileges.\n"); return 1; }

    // --- Load Onboarding Credentials ---
    if (!load_onboard_credentials("controller_onboard.conf")) {
        fprintf(stderr, "[SPA_CTRL] Fatal: No valid onboarding credentials loaded.\n"); return 1;
    }
    if (!g_onboard_creds) { fprintf(stderr,"[SPA_CTRL] Fatal: Credential list is empty after load.\n"); return 1;}

    // --- Interface selection ---
     if (argc > 2 && strcmp(argv[1], "-i") == 0) {
        if (argc > 2 && argv[2] != NULL) { dev = argv[2]; }
        else { fprintf(stderr, "[SPA_CTRL] Error: -i requires interface name.\n"); free_onboard_credentials(g_onboard_creds); return 1; }
    } else if (argc > 1) { fprintf(stderr, "[SPA_CTRL] Usage: %s [-i interface]\n", argv[0]); free_onboard_credentials(g_onboard_creds); return 1; }
    else {
        printf("[SPA_CTRL] Finding default interface (using deprecated pcap_lookupdev)...\n");
        dev = pcap_lookupdev(errbuf);
        if (!dev) { fprintf(stderr, "[SPA_CTRL] Warn: %s\n", errbuf); dev = strdup(SPA_INTERFACE); if (!dev) { perror("strdup"); free_onboard_credentials(g_onboard_creds); return 2;} use_strdup = 1; printf("Warn: Using fallback '%s'\n", dev); }
    }
    printf("[SPA_CTRL] Using interface: %s\n", dev);

    // --- Crypto Init ---
    OpenSSL_add_all_algorithms(); ERR_load_crypto_strings();
    // Check algos needed by SPA packet itself
    if (!EVP_get_cipherbyname(SPA_ENCRYPTION_ALGO)) { fprintf(stderr, "Fatal: Enc Algo '%s'\n", SPA_ENCRYPTION_ALGO); if(use_strdup)free(dev); free_onboard_credentials(g_onboard_creds); return 1; }
    if (!EVP_get_digestbyname(SPA_HMAC_ALGO)) { fprintf(stderr, "Fatal: HMAC Algo '%s'\n", SPA_HMAC_ALGO); if(use_strdup)free(dev); free_onboard_credentials(g_onboard_creds); return 1; }
    // Check algos needed by HOTP
    if (!EVP_get_digestbyname(SPA_HOTP_HMAC_ALGO)) { fprintf(stderr, "Fatal: HOTP HMAC Algo '%s'\n", SPA_HOTP_HMAC_ALGO); if(use_strdup)free(dev); free_onboard_credentials(g_onboard_creds); return 1; }
    printf("[SPA_CTRL] Crypto algorithms OK.\n");

    // --- Pcap Setup ---
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) { fprintf(stderr, "[SPA_CTRL] Warn: No netmask: %s\n", errbuf); net=0; mask=0; }
    spa_pcap_handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (!spa_pcap_handle) { fprintf(stderr, "[SPA_CTRL] Fatal: pcap_open_live %s: %s\n", dev, errbuf); if(use_strdup)free(dev); free_onboard_credentials(g_onboard_creds); return 2; }
    if (pcap_datalink(spa_pcap_handle) != DLT_EN10MB) { fprintf(stderr, "[SPA_CTRL] Warn: %s not Ethernet.\n", dev); }
    snprintf(filter_exp, sizeof(filter_exp), "udp dst port %d", SPA_LISTENER_PORT);
    printf("[SPA_CTRL] Compiling filter: '%s'\n", filter_exp);
    if (pcap_compile(spa_pcap_handle, &fp, filter_exp, 0, net) == -1) { fprintf(stderr, "[SPA_CTRL] Fatal: Compile: %s\n", pcap_geterr(spa_pcap_handle)); pcap_close(spa_pcap_handle); if(use_strdup)free(dev); free_onboard_credentials(g_onboard_creds); return 2; }
    if (pcap_setfilter(spa_pcap_handle, &fp) == -1) { fprintf(stderr, "[SPA_CTRL] Fatal: Set filter: %s\n", pcap_geterr(spa_pcap_handle)); pcap_freecode(&fp); pcap_close(spa_pcap_handle); if(use_strdup)free(dev); free_onboard_credentials(g_onboard_creds); return 2; }

    printf("[SPA_CTRL] SPA Server listening on %s, UDP port %d (for Onboarding)...\n", dev, SPA_LISTENER_PORT);
    printf("[SPA_CTRL] Waiting for SPA packets. Ctrl+C to exit.\n");

    // --- Signal Handling & Pcap Loop ---
    signal(SIGINT, spa_controller_cleanup); signal(SIGTERM, spa_controller_cleanup);
    int pcap_ret = pcap_loop(spa_pcap_handle, -1, spa_controller_packet_handler, NULL);

    // --- Cleanup ---
    printf("\n[SPA_CTRL] Pcap loop ended (ret %d).\n", pcap_ret);
    if (pcap_ret == -1) { fprintf(stderr, "[SPA_CTRL] Pcap loop error: %s\n", pcap_geterr(spa_pcap_handle)); }
    printf("[SPA_CTRL] Cleaning up...\n");
    pcap_freecode(&fp);
    if (spa_pcap_handle) { pcap_close(spa_pcap_handle); spa_pcap_handle = NULL; }
    if (use_strdup) { free(dev); dev = NULL; }
    EVP_cleanup(); ERR_free_strings();
    free_onboard_credentials(g_onboard_creds); // Free loaded credentials
    pthread_mutex_destroy(&g_onboard_lock); // Destroy mutex
    printf("[SPA_CTRL] SPA Server shutdown complete.\n");
    return 0;
}

// --- Signal Handler Definition ---
void spa_controller_cleanup(int signo) {
    printf("\n[SPA_CTRL] Caught signal %d, shutting down SPA listener...\n", signo);
    if (spa_pcap_handle) {
        pcap_breakloop(spa_pcap_handle); // Request pcap_loop to exit gracefully
    }
}