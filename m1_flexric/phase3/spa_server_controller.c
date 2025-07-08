// spa_server_controller.c
#define _GNU_SOURCE // For asprintf
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <pcap.h> // Ensure this is included
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
#include <pthread.h> 
#include <endian.h>

#include "spa_common.h"
#include "controller_structs.h" 

// --- Function Prototypes --- (Assume these are unchanged from your version)
void spa_controller_cleanup(int signo);
int load_onboard_credentials(const char *filename); 
onboard_credential_t* find_onboard_credential(const char *ip_str);
void free_onboard_credentials(onboard_credential_t *head);
int run_iptables_rule(const char* action, const char* source_ip, uint16_t target_port); // Keep existing

// --- Global Variables --- (Assume these are unchanged from your version)
pcap_t *spa_pcap_handle = NULL;
onboard_credential_t *g_onboard_creds = NULL; // Defined here
pthread_mutex_t g_onboard_lock = PTHREAD_MUTEX_INITIALIZER; // Defined here


// --- Config Loading --- (load_onboard_credentials, find_onboard_credential, free_onboard_credentials)
// --- These functions remain IDENTICAL to your provided spa_server_controller.c code. ---
// --- For brevity, I'm not repeating them. Assume they are present. ---
int load_onboard_credentials(const char *filename) { /* ... Your code ... */ 
    FILE *fp = fopen(filename, "r"); if (!fp) return 0;
    char line[1024]; int line_num = 0; int creds_loaded = 0; onboard_credential_t *current_cred = NULL;
    while (fgets(line, sizeof(line), fp)) { line_num++; char *trimmed_line = trim_whitespace(line); if (!trimmed_line || trimmed_line[0] == '\0' || trimmed_line[0] == '#') continue;
        if (trimmed_line[0] == '[' && trimmed_line[strlen(trimmed_line) - 1] == ']') {
            if (current_cred) { if(current_cred->has_enc && current_cred->has_hmac && current_cred->has_hotp && current_cred->has_counter) { current_cred->next = g_onboard_creds; g_onboard_creds = current_cred; creds_loaded++; } else { free(current_cred); } current_cred = NULL; }
            current_cred = malloc(sizeof(onboard_credential_t)); if (!current_cred) { fclose(fp); return 0; } memset(current_cred, 0, sizeof(onboard_credential_t));
            size_t id_len = strlen(trimmed_line) - 2; if (id_len == 0 || id_len >= INET_ADDRSTRLEN) {free(current_cred); current_cred = NULL; continue; }
            strncpy(current_cred->entity_ip, trimmed_line + 1, id_len); current_cred->entity_ip[id_len] = '\0';
            struct sockaddr_in sa; if (inet_pton(AF_INET, current_cred->entity_ip, &sa.sin_addr)!=1){free(current_cred); current_cred=NULL; continue;}
        } else if (current_cred) {
            char *key = trimmed_line; char *value = NULL; for (char *p = key; *p != '\0'; ++p) { if (isspace((unsigned char)*p) || *p == '=') { *p = '\0'; value = p + 1; while (*value != '\0' && (isspace((unsigned char)*value) || *value == '=')) { value++; } break; } }
            if (value && *value != '\0') { key = trim_whitespace(key); value = trim_whitespace(value); if (strlen(key) == 0) continue;
                if (strcasecmp(key, "ENCRYPTION_KEY") == 0) { int len=hex_string_to_bytes(value, current_cred->enc_key, MAX_KEY_LEN); if(len>0){current_cred->enc_key_len=len; current_cred->has_enc=1;} }
                else if (strcasecmp(key, "HMAC_KEY") == 0) { int len=hex_string_to_bytes(value, current_cred->hmac_key, MAX_KEY_LEN); if(len>0){current_cred->hmac_key_len=len; current_cred->has_hmac=1;} }
                else if (strcasecmp(key, "HOTP_SECRET") == 0) { int len=hex_string_to_bytes(value, current_cred->hotp_secret, MAX_KEY_LEN); if(len>0){current_cred->hotp_secret_len=len; current_cred->has_hotp=1;} }
                else if (strcasecmp(key, "HOTP_NEXT_COUNTER") == 0) { current_cred->hotp_next_counter = strtoull(value, NULL, 10); current_cred->has_counter=1; }
            }
        }
    }
    if (current_cred) { if(current_cred->has_enc && current_cred->has_hmac && current_cred->has_hotp && current_cred->has_counter) { current_cred->next = g_onboard_creds; g_onboard_creds = current_cred; creds_loaded++; } else { free(current_cred); } }
    fclose(fp); return creds_loaded >= 0;
}
onboard_credential_t* find_onboard_credential(const char *ip_str) { /* ... Your code ... */ 
    if (!ip_str) return NULL; onboard_credential_t *current = g_onboard_creds;
    while (current != NULL) { if (strcmp(current->entity_ip, ip_str) == 0) return current; current = current->next; } return NULL;
}
void free_onboard_credentials(onboard_credential_t *head) { /* ... Your code ... */ 
    onboard_credential_t *current = head, *next; while(current){ next = current->next; free(current); current = next;} g_onboard_creds = NULL;
}

// --- Basic iptables Command Execution --- (Keep your existing version from spa_server_controller.c)
int run_iptables_rule(const char* action, const char* source_ip, uint16_t target_port) {
    char *command = NULL;
    int ret;
    // Note: The comment here includes the target_port which is CONTROLLER_MTLS_PORT
    if (asprintf(&command, "sudo iptables %s INPUT -s %s -p tcp --dport %u -m comment --comment \"SPA_CTRL_ALLOW_%s_%u\" -j ACCEPT",
                 action, source_ip, target_port, source_ip, target_port) == -1) { // Added target_port to comment
       // perror("[SPA_CTRL] asprintf failed for iptables"); // Output commented
       return -1;
    }
    // printf("[SPA_CTRL] Executing: %s\n", command); // Output commented
    fflush(stdout); // Good practice before system()
    ret = system(command);
    free(command);

    if (ret == -1) { /*perror("[SPA_CTRL] system(iptables) failed");*/ return -1;}
    if (WIFEXITED(ret) && WEXITSTATUS(ret) == 0) {
        // printf("[SPA_CTRL] iptables %s rule for %s to port %u successful.\n", action, source_ip, target_port); // Output commented
        return 0; 
    } else {
        // fprintf(stderr, "[SPA_CTRL] iptables %s rule for %s to port %u failed (status: %d)\n", action, source_ip, target_port, WEXITSTATUS(ret)); // Output commented
        return -1; 
    }
}


// --- Packet Handler (Controller Onboarding SPA) with Timestamping ---
void spa_controller_packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
   const int ETH_HDR_LEN = 14;
   char source_ip_str[INET_ADDRSTRLEN];
   // For precise timing
   struct timespec t_spa_ctrl_received, t_before_ctrl_iptables, t_after_ctrl_iptables;
   clock_gettime(CLOCK_MONOTONIC, &t_spa_ctrl_received);

   time_t now_log = time(NULL); struct tm *tm_info_log = localtime(&now_log); char time_buf_log[30];
   strftime(time_buf_log, sizeof(time_buf_log), "%H:%M:%S", tm_info_log);


   (void)user_data;

   // Basic packet validation (length checks for headers)
   if (pkthdr->caplen < (unsigned int)ETH_HDR_LEN) return;
   const struct ip *ip_header = (struct ip *)(packet + ETH_HDR_LEN);
   int ip_hdr_len = ip_header->ip_hl * 4;
   if (ip_hdr_len < 20 || pkthdr->caplen < (unsigned int)(ETH_HDR_LEN + ip_hdr_len)) return;
   if (ip_header->ip_p != IPPROTO_UDP) return;
   const struct udphdr *udp_header = (struct udphdr *)((u_char *)ip_header + ip_hdr_len);
   int udp_hdr_len = sizeof(struct udphdr);
   if (pkthdr->caplen < (unsigned int)(ETH_HDR_LEN + ip_hdr_len + udp_hdr_len)) return;

   inet_ntop(AF_INET, &(ip_header->ip_src), source_ip_str, INET_ADDRSTRLEN);
   // printf("\n[%s.%03ld] CTRL_SPA: Packet received from %s (len %u)\n", 
   //        time_buf_log, t_spa_ctrl_received.tv_nsec / 1000000, source_ip_str, pkthdr->len); // Output commented

   onboard_credential_t *creds = find_onboard_credential(source_ip_str);
   if (!creds) {
       // printf("  -> CTRL_SPA: Discarding: No onboard credentials for %s.\n", source_ip_str); // Output commented
       return;
   }

   // --- SPA Processing (HMAC, Decrypt, HOTP) ---
   // (This part is identical to your existing spa_controller_packet_handler's crypto logic)
   const u_char *payload = (u_char *)udp_header + udp_hdr_len;
   int payload_len = pkthdr->caplen - (ETH_HDR_LEN + ip_hdr_len + udp_hdr_len);
   if ((size_t)payload_len < SPA_PACKET_MIN_LEN || (size_t)payload_len > SPA_PACKET_MAX_LEN) return;
   const unsigned char *iv = payload; const unsigned char *encrypted_data = payload + SPA_IV_LEN;
   int encrypted_len = payload_len - SPA_IV_LEN - SPA_HMAC_LEN; const unsigned char *received_hmac = payload + SPA_IV_LEN + encrypted_len;
   if (encrypted_len <= 0) return;
   unsigned char calculated_hmac[EVP_MAX_MD_SIZE]; unsigned int calc_hmac_len = 0; const EVP_MD *digest = EVP_get_digestbyname(SPA_HMAC_ALGO); if (!digest) return;
   unsigned char *data_to_hmac_buf = malloc(SPA_IV_LEN + encrypted_len); if (!data_to_hmac_buf) return;
   memcpy(data_to_hmac_buf, iv, SPA_IV_LEN); memcpy(data_to_hmac_buf + SPA_IV_LEN, encrypted_data, encrypted_len);
   HMAC(digest, creds->hmac_key, creds->hmac_key_len, data_to_hmac_buf, SPA_IV_LEN + encrypted_len, calculated_hmac, &calc_hmac_len); free(data_to_hmac_buf);
   if (calc_hmac_len != SPA_HMAC_LEN || constant_time_memcmp(received_hmac, calculated_hmac, SPA_HMAC_LEN) != 0) return;
   unsigned char decrypted_data_buf[sizeof(spa_data_t)+EVP_MAX_BLOCK_LENGTH]; int decrypted_len_val = 0, final_len_val = 0; int decrypt_ok_stat = 1; // Renamed
   const EVP_CIPHER *cipher_ptr = EVP_get_cipherbyname(SPA_ENCRYPTION_ALGO); if (!cipher_ptr) return; // Renamed
   EVP_CIPHER_CTX *ctx_ptr = EVP_CIPHER_CTX_new(); if (!ctx_ptr) return; // Renamed
   if (1!=EVP_DecryptInit_ex(ctx_ptr, cipher_ptr, NULL, creds->enc_key, iv)) decrypt_ok_stat=0;
   if (decrypt_ok_stat && 1!=EVP_DecryptUpdate(ctx_ptr, decrypted_data_buf, &decrypted_len_val, encrypted_data, encrypted_len)) ERR_clear_error();
   if (decrypt_ok_stat && 1!=EVP_DecryptFinal_ex(ctx_ptr, decrypted_data_buf + decrypted_len_val, &final_len_val)) {ERR_clear_error(); decrypt_ok_stat=0;}
   EVP_CIPHER_CTX_free(ctx_ptr);
   if (!decrypt_ok_stat) return;
   decrypted_len_val += final_len_val;
   if ((size_t)decrypted_len_val != sizeof(spa_data_t)) return;
   spa_data_t *spa_info_ptr = (spa_data_t *)decrypted_data_buf; // Renamed
   uint64_t received_timestamp_val = be64toh(spa_info_ptr->timestamp); // Renamed
   time_t current_time_val = time(NULL); // Renamed
   if (spa_info_ptr->version != SPA_VERSION || llabs((int64_t)current_time_val - (int64_t)received_timestamp_val) > SPA_TIMESTAMP_WINDOW_SECONDS) return;
   
   pthread_mutex_lock(&g_onboard_lock); 
   uint64_t expected_counter = creds->hotp_next_counter; int hotp_match_found = 0; uint64_t matched_counter_val = 0; // Renamed
   uint64_t received_hotp_counter_val = be64toh(spa_info_ptr->hotp_counter); // Renamed
   uint32_t received_hotp_code_val = ntohl(spa_info_ptr->hotp_code); // Renamed
   if (received_hotp_counter_val >= expected_counter && received_hotp_counter_val <= expected_counter + HOTP_COUNTER_SYNC_WINDOW) {
       for (uint64_t c_chk = received_hotp_counter_val; c_chk <= expected_counter + HOTP_COUNTER_SYNC_WINDOW; ++c_chk) { // Renamed
           uint32_t calc_code = generate_hotp(creds->hotp_secret, creds->hotp_secret_len, c_chk, HOTP_CODE_DIGITS); // Renamed
           if (calc_code == received_hotp_code_val) { hotp_match_found = 1; matched_counter_val = c_chk; creds->hotp_next_counter = matched_counter_val + 1; break; }
       }
   }
   pthread_mutex_unlock(&g_onboard_lock); 
   if (!hotp_match_found) return;
   // --- End SPA Crypto ---

   // printf("  [%s.%03ld] CTRL_SPA: VALID Onboarding SPA Packet from %s. Authorizing mTLS access to port %u...\n",
   //        time_buf_log, t_spa_ctrl_received.tv_nsec / 1000000, source_ip_str, CONTROLLER_MTLS_PORT); // Output commented

   clock_gettime(CLOCK_MONOTONIC, &t_before_ctrl_iptables);
   int iptables_add_status = run_iptables_rule("-I", source_ip_str, CONTROLLER_MTLS_PORT);
   clock_gettime(CLOCK_MONOTONIC, &t_after_ctrl_iptables);

   double time_taken_iptables = (t_after_ctrl_iptables.tv_sec - t_before_ctrl_iptables.tv_sec) * 1000.0;
   time_taken_iptables += (t_after_ctrl_iptables.tv_nsec - t_before_ctrl_iptables.tv_nsec) / 1000000.0;
   // printf("  [%s.%03ld] CTRL_SPA: iptables call for %s to port %u took %.3f ms (Status: %d).\n",
   //        time_buf_log, t_after_ctrl_iptables.tv_nsec / 1000000,
   //        source_ip_str, CONTROLLER_MTLS_PORT, time_taken_iptables, iptables_add_status); // Output commented

   if (iptables_add_status == 0) {
       char *remove_cmd = NULL;
       // Use CONTROLLER_MTLS_PORT in the comment for deletion
       if (asprintf(&remove_cmd, "sh -c 'sleep %d && sudo iptables -D INPUT -s %s -p tcp --dport %u -m comment --comment \"SPA_CTRL_ALLOW_%s_%u\" -j ACCEPT > /dev/null 2>&1' &",
                    SPA_DEFAULT_DURATION_SECONDS, source_ip_str, CONTROLLER_MTLS_PORT, source_ip_str, CONTROLLER_MTLS_PORT) != -1) { // Added port to comment
           // printf("  [%s.%03ld] CTRL_SPA: Scheduling iptables cleanup: %s\n", time_buf_log, t_after_ctrl_iptables.tv_nsec / 1000000, remove_cmd); // Output commented
           system(remove_cmd); 
           free(remove_cmd);
       } else {
           // perror("[SPA_CTRL] asprintf failed for cleanup command"); // Output commented
       }
   } else {
       // fprintf(stderr, "[%s.%03ld] CTRL_SPA: FAILED to add iptables rule for %s to port %u.\n", 
       //         time_buf_log, t_after_ctrl_iptables.tv_nsec / 1000000, source_ip_str, CONTROLLER_MTLS_PORT); // Output commented
   }
   // printf("----------------------------------------\n"); // Output commented
}


// --- Main SPA Server Function (Controller) ---
int main(int argc, char *argv[]) {
   char errbuf[PCAP_ERRBUF_SIZE]; char *dev = NULL; bpf_u_int32 net, mask; struct bpf_program fp;
   char filter_exp[100]; int use_strdup_local = 0; // Renamed to avoid conflict if main is in another file

   if (geteuid() != 0) { /*fprintf(stderr, "[SPA_CTRL] Error: Requires root privileges.\n");*/ return 1; } // Output commented

   if (!load_onboard_credentials("controller_onboard.conf")) {
       /*fprintf(stderr, "[SPA_CTRL] Fatal: No valid onboard credentials loaded.\n");*/ return 1; // Output commented
   }
   if (!g_onboard_creds) { /*fprintf(stderr,"[SPA_CTRL] Fatal: Credential list is empty after load.\n");*/ return 1;} // Output commented

   // --- Interface selection --- (Keep your existing logic)
   if (argc > 2 && strcmp(argv[1], "-i") == 0) { if (argc > 2 && argv[2] != NULL) { dev = argv[2]; } else { /*fprintf(stderr, "[SPA_CTRL] Error: -i requires interface name.\n");*/ free_onboard_credentials(g_onboard_creds); return 1; } }
   else if (argc > 1) { /*fprintf(stderr, "[SPA_CTRL] Usage: %s [-i interface]\n", argv[0]);*/ free_onboard_credentials(g_onboard_creds); return 1; }
   else { dev = pcap_lookupdev(errbuf); if (!dev) { /*fprintf(stderr, "[SPA_CTRL] Warn: %s\n", errbuf);*/ dev = strdup(SPA_INTERFACE); if (!dev) { /*perror("strdup");*/ free_onboard_credentials(g_onboard_creds); return 2;} use_strdup_local = 1; /*printf("Warn: Using fallback '%s'\n", dev);*/ } } // Output commented
   // printf("[SPA_CTRL] Using interface: %s\n", dev); // Output commented

   // --- Crypto Init --- (Keep your existing logic)
   OpenSSL_add_all_algorithms(); ERR_load_crypto_strings();
   if (!EVP_get_cipherbyname(SPA_ENCRYPTION_ALGO)) { /*...*/ if(use_strdup_local)free(dev); free_onboard_credentials(g_onboard_creds); return 1; }
   if (!EVP_get_digestbyname(SPA_HMAC_ALGO)) { /*...*/ if(use_strdup_local)free(dev); free_onboard_credentials(g_onboard_creds); return 1; }
   if (!EVP_get_digestbyname(SPA_HOTP_HMAC_ALGO)) { /*...*/ if(use_strdup_local)free(dev); free_onboard_credentials(g_onboard_creds); return 1; }
   // printf("[SPA_CTRL] Crypto algorithms OK.\n"); // Output commented

   // --- Pcap Setup ---
   if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) { /*fprintf(stderr, "[SPA_CTRL] Warn: No netmask: %s\n", errbuf);*/ net=0; mask=0; } // Output commented
   
   // MODIFIED: pcap_open_live timeout and set_immediate_mode
   spa_pcap_handle = pcap_open_live(dev, BUFSIZ, 1 /*promisc*/, 50 /*timeout_ms - REDUCED*/, errbuf);
   if (!spa_pcap_handle) { /*fprintf(stderr, "[SPA_CTRL] Fatal: pcap_open_live %s: %s\n", dev, errbuf);*/ if(use_strdup_local)free(dev); free_onboard_credentials(g_onboard_creds); return 2; } // Output commented

    #if defined(PCAP_VERSION_MAJOR) && (PCAP_VERSION_MAJOR > 1 || (PCAP_VERSION_MAJOR == 1 && PCAP_VERSION_MINOR >= 5))
       if (pcap_set_immediate_mode(spa_pcap_handle, 1) != 0) {
           // fprintf(stderr, "[SPA_CTRL] Warning: pcap_set_immediate_mode failed: %s\n", pcap_geterr(spa_pcap_handle)); // Output commented
       } else {
           // printf("[SPA_CTRL] pcap immediate mode set.\n"); // Output commented
       }
    #else
       // printf("[SPA_CTRL] Note: pcap_set_immediate_mode not available/attempted.\n"); // Output commented
    #endif

   if (pcap_datalink(spa_pcap_handle) != DLT_EN10MB) { /*fprintf(stderr, "[SPA_CTRL] Warn: %s not Ethernet.\n", dev);*/ } // Output commented
   snprintf(filter_exp, sizeof(filter_exp), "udp dst port %d", SPA_LISTENER_PORT);
   // printf("[SPA_CTRL] Compiling filter: '%s'\n", filter_exp); // Output commented
   if (pcap_compile(spa_pcap_handle, &fp, filter_exp, 0, net) == -1) { /*...*/ pcap_close(spa_pcap_handle); if(use_strdup_local)free(dev); free_onboard_credentials(g_onboard_creds); return 2; } // Output commented
   if (pcap_setfilter(spa_pcap_handle, &fp) == -1) { /*...*/ pcap_freecode(&fp); pcap_close(spa_pcap_handle); if(use_strdup_local)free(dev); free_onboard_credentials(g_onboard_creds); return 2; } // Output commented
   pcap_freecode(&fp);


   // printf("[SPA_CTRL] SPA Server listening on %s, UDP port %d (for Onboarding)...\n", dev, SPA_LISTENER_PORT); // Output commented
   // printf("[SPA_CTRL] Waiting for SPA packets. Ctrl+C to exit.\n"); // Output commented

   signal(SIGINT, spa_controller_cleanup); signal(SIGTERM, spa_controller_cleanup);
   int pcap_ret = pcap_loop(spa_pcap_handle, -1, spa_controller_packet_handler, NULL);

   // printf("\n[SPA_CTRL] Pcap loop ended (ret %d).\n", pcap_ret); // Output commented
   if (pcap_ret == -1) { /*fprintf(stderr, "[SPA_CTRL] Pcap loop error: %s\n", pcap_geterr(spa_pcap_handle));*/ } // Output commented
   // printf("[SPA_CTRL] Cleaning up...\n"); // Output commented
   // pcap_freecode(&fp); // fp is already freed after pcap_setfilter
   if (spa_pcap_handle) { pcap_close(spa_pcap_handle); spa_pcap_handle = NULL; }
   if (use_strdup_local) { free(dev); dev = NULL; }
   EVP_cleanup(); ERR_free_strings();
   free_onboard_credentials(g_onboard_creds); 
   pthread_mutex_destroy(&g_onboard_lock); 
   // printf("[SPA_CTRL] SPA Server shutdown complete.\n"); // Output commented
   return 0;
}

// --- Signal Handler Definition ---
void spa_controller_cleanup(int signo) {
   // printf("\n[SPA_CTRL] Caught signal %d, shutting down SPA listener...\n", signo); // Output commented
   if (spa_pcap_handle) {
       pcap_breakloop(spa_pcap_handle); 
   }
}


