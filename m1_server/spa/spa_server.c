// spa_server.c
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
#include <sys/wait.h>   // Included for WEXITSTATUS
#include <ifaddrs.h>
#include <unistd.h>
#include <netdb.h>
#include <ctype.h>      // Include for isspace

#include "spa_common.h" // Common definitions

// --- Data Structures for Policies ---
#define MAX_SERVICE_LEN 32 // Max length for "proto/port" string
// CONFIG_FILE defines where to look for access.conf
#define CONFIG_FILE "access.conf"

typedef struct allowed_service {
    uint8_t protocol;
    uint16_t port; // 0 means 'any' port for this protocol
    struct allowed_service *next;
} allowed_service_t;

typedef struct client_policy {
    char source_ip_str[INET_ADDRSTRLEN]; // Key for lookup: Client Source IP
    unsigned char hmac_key[MAX_KEY_LEN];
    size_t hmac_key_len;
    unsigned char enc_key[MAX_KEY_LEN];
    size_t enc_key_len;
    allowed_service_t *allowed_services; // Linked list of allowed proto/port pairs
    // Internal flags for parsing validation
    int has_enc_key;
    int has_hmac_key;
    int has_ports;
    struct client_policy *next;
} client_policy_t;

// --- Global Variables ---
client_policy_t *g_policy_list = NULL; // Global head of the policy list
pcap_t *pcap_handle = NULL;           // Global pcap handle for signal handler

// --- Function Prototypes ---
void cleanup(int signo); // Prototype for the signal handler
int load_policies_ip_keyed(const char *filename);
// *** NOTE: Implementations for protocol_to_string and string_to_protocol ***
// ***       are expected to be in the linked spa_common.o file.          ***
// ***       Only their prototypes are implicitly included via spa_common.h ***
void handle_openssl_error_server(const char *msg);
int constant_time_memcmp(const void *a, const void *b, size_t size);
int get_interface_ip(const char *if_name, char *ip_buf, size_t len);
void free_policies(client_policy_t *head);
void free_allowed_services(allowed_service_t *head);
char* trim_whitespace(char *str);
int hex_string_to_bytes(const char *hex_string, unsigned char *byte_array, size_t max_len);
int add_allowed_service(client_policy_t *policy, uint8_t protocol, uint16_t port);
int is_request_allowed(const client_policy_t *policy, uint8_t req_protocol, uint16_t req_port_host);
client_policy_t* find_policy_by_ip(const char *ip_str);


// --- Helper Functions Implementation ---

// Trim leading/trailing whitespace from a string (in-place)
char* trim_whitespace(char *str) {
    if (str == NULL) return NULL;
    char *end;
    while(isspace((unsigned char)*str)) str++;
    if(*str == 0) return str;
    end = str + strlen(str) - 1;
    while(end > str && isspace((unsigned char)*end)) end--;
    end[1] = '\0';
    return str;
}

// Convert hex string to byte array
int hex_string_to_bytes(const char *hex_string, unsigned char *byte_array, size_t max_len) {
    if (!hex_string || !byte_array) return -1;
    size_t len = strlen(hex_string);
    if (len == 0 || len % 2 != 0) { return -1; }
    size_t byte_len = len / 2;
    if (byte_len > max_len) { return -1; }
    for (size_t i = 0; i < byte_len; i++) {
        if (sscanf(hex_string + 2 * i, "%2hhx", &byte_array[i]) != 1) { return -1; }
    }
    return (int)byte_len;
}

// Free the linked list of allowed services
void free_allowed_services(allowed_service_t *head) {
   allowed_service_t *current = head, *next;
    while (current != NULL) {
        next = current->next;
        free(current);
        current = next;
    }
}

// Free the entire policy list
void free_policies(client_policy_t *head) {
    client_policy_t *current = head, *next;
    printf("Freeing loaded policies...\n");
    while (current != NULL) {
        next = current->next;
        printf("  - Freeing policy for %s\n", current->source_ip_str);
        free_allowed_services(current->allowed_services);
        free(current);
        current = next;
    }
    g_policy_list = NULL; // Reset global pointer
}

// Add an allowed service to a policy
int add_allowed_service(client_policy_t *policy, uint8_t protocol, uint16_t port) {
    if (!policy) return 0;
    allowed_service_t *new_service = malloc(sizeof(allowed_service_t));
    if (!new_service) {
        perror("Failed to allocate memory for allowed service");
        return 0;
    }
    new_service->protocol = protocol;
    new_service->port = port; // Port can be 0 for 'any'
    new_service->next = policy->allowed_services; // Add to front
    policy->allowed_services = new_service;
    return 1;
}

// Check if a request matches the client's allowed policy (WITH DEBUGGING)
int is_request_allowed(const client_policy_t *policy, uint8_t req_protocol, uint16_t req_port_host) {
    if (!policy || !policy->allowed_services) {
         printf("DEBUG ALLOWED CHECK: No policy/services for client.\n");
        return 0;
    }
    allowed_service_t *current = policy->allowed_services;
    printf("DEBUG ALLOWED CHECK: Checking Request Proto=%u, Port=%u\n", req_protocol, req_port_host);
    while (current != NULL) {
         printf("DEBUG ALLOWED CHECK: Comparing with Policy Proto=%u, Port=%u\n", current->protocol, current->port);
        if (current->protocol == req_protocol && (current->port == req_port_host || current->port == 0)) {
             printf("DEBUG ALLOWED CHECK: MATCH FOUND!\n");
            return 1; // Found a match
        }
        current = current->next;
    }
     printf("DEBUG ALLOWED CHECK: No match found in policy list.\n");
    return 0; // No match found
}


// Find a policy based on the source IP address string
client_policy_t* find_policy_by_ip(const char *ip_str) {
    if (!ip_str) return NULL;
    client_policy_t *current = g_policy_list;
    while (current != NULL) {
        if (strcmp(current->source_ip_str, ip_str) == 0) {
            return current; // Found matching policy
        }
        current = current->next;
    }
    return NULL; // No policy found for this IP
}

// --- Policy Loading (fwknop style, keyed by IP, WITH DEBUGGING and FIXES) ---
int load_policies_ip_keyed(const char *filename) {
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        perror("Error opening policy file");
        fprintf(stderr, "Could not open config file: %s\n", filename);
        return 0;
    }
    printf("Loading policies from: %s (IP-keyed stanzas)\n", filename);

    char line[1024];
    int line_num = 0;
    int policies_loaded = 0;
    client_policy_t *current_policy = NULL; // Policy being parsed

    while (fgets(line, sizeof(line), fp)) {
        line_num++;
        char *trimmed_line = trim_whitespace(line);

        if (!trimmed_line || trimmed_line[0] == '\0' || trimmed_line[0] == '#') continue;

        // Check for start of a new stanza [IP_Address]
        if (trimmed_line[0] == '[' && trimmed_line[strlen(trimmed_line) - 1] == ']') {
            // --- Finalize the previous policy ---
            if (current_policy != NULL) {
                if (current_policy->has_enc_key && current_policy->has_hmac_key && current_policy->has_ports) {
                    current_policy->next = g_policy_list; g_policy_list = current_policy; policies_loaded++;
                    printf("  + Completed policy for: %s\n", current_policy->source_ip_str);
                } else {
                    fprintf(stderr, "Warning: Discarding incomplete policy for [%s] ending at line %d.\n", current_policy->source_ip_str, line_num -1);
                    free_allowed_services(current_policy->allowed_services); free(current_policy);
                }
                current_policy = NULL;
            }

            // --- Start parsing the new policy ---
            current_policy = malloc(sizeof(client_policy_t));
            if (!current_policy) { perror("Malloc failed for policy"); fclose(fp); return 0; }
            memset(current_policy, 0, sizeof(client_policy_t));

            size_t id_len = strlen(trimmed_line) - 2;
            if (id_len == 0) { fprintf(stderr, "Error: Empty stanza header [] line %d.\n", line_num); free(current_policy); current_policy = NULL; continue; }
            if (id_len >= INET_ADDRSTRLEN) id_len = INET_ADDRSTRLEN - 1;
            strncpy(current_policy->source_ip_str, trimmed_line + 1, id_len);
            current_policy->source_ip_str[id_len] = '\0';

            struct sockaddr_in sa;
            if (inet_pton(AF_INET, current_policy->source_ip_str, &(sa.sin_addr)) != 1) {
                 fprintf(stderr, "Error: Invalid IP address '%s' in stanza header line %d.\n", current_policy->source_ip_str, line_num);
                 free(current_policy); current_policy = NULL; continue;
            }
            printf("  Parsing stanza for IP: %s\n", current_policy->source_ip_str);

        } else if (current_policy != NULL) {
            // --- Parse KEY = VALUE or KEY VALUE line ---
            char *key = trimmed_line;
            char *value = NULL;
            for (char *p = key; *p != '\0'; ++p) {
                if (isspace((unsigned char)*p) || *p == '=') { *p = '\0'; value = p + 1; while (*value != '\0' && (isspace((unsigned char)*value) || *value == '=')) { value++; } break; }
            }

            if (value != NULL && *value != '\0') {
                key = trim_whitespace(key); value = trim_whitespace(value);
                if (strlen(key) == 0) { fprintf(stderr, "Warn: Empty key line %d for %s.\n", line_num, current_policy->source_ip_str); continue; }

                if (strcasecmp(key, "ENCRYPTION_KEY") == 0) {
                    int key_len = hex_string_to_bytes(value, current_policy->enc_key, MAX_KEY_LEN);
                    if (key_len > 0) { current_policy->enc_key_len = (size_t)key_len; current_policy->has_enc_key = 1; }
                    else { fprintf(stderr, "Error: Invalid ENCRYPTION_KEY format for %s line %d.\n", current_policy->source_ip_str, line_num); }
                } else if (strcasecmp(key, "HMAC_KEY") == 0) {
                    int key_len = hex_string_to_bytes(value, current_policy->hmac_key, MAX_KEY_LEN);
                    if (key_len > 0) { current_policy->hmac_key_len = (size_t)key_len; current_policy->has_hmac_key = 1; }
                    else { fprintf(stderr, "Error: Invalid HMAC_KEY format for %s line %d.\n", current_policy->source_ip_str, line_num); }
                } else if (strcasecmp(key, "OPEN_PORTS") == 0) {
                    // --- Corrected OPEN_PORTS Parsing Logic ---
                    int service_parse_ok = 1;
                    current_policy->has_ports = 0;
                    char *current_pos = value;
                    char *next_comma;

                    while (current_pos != NULL && *current_pos != '\0') {
                        next_comma = strchr(current_pos, ',');
                        char service_buffer[MAX_SERVICE_LEN + 1];

                        if (next_comma != NULL) {
                            size_t len = next_comma - current_pos;
                            if (len > MAX_SERVICE_LEN) len = MAX_SERVICE_LEN;
                            strncpy(service_buffer, current_pos, len);
                            service_buffer[len] = '\0';
                            current_pos = next_comma + 1;
                        } else {
                            strncpy(service_buffer, current_pos, MAX_SERVICE_LEN);
                            service_buffer[MAX_SERVICE_LEN] = '\0';
                            current_pos = NULL; // End loop
                        }

                        char *trimmed_service = trim_whitespace(service_buffer);

                        if (trimmed_service && strlen(trimmed_service) > 0) {
                            char *proto_str_tok = trimmed_service;
                            char *port_str_tok = strchr(proto_str_tok, '/');

                            if (port_str_tok != NULL) {
                                *port_str_tok = '\0'; // Split proto/port
                                port_str_tok++;
                                proto_str_tok = trim_whitespace(proto_str_tok);
                                port_str_tok = trim_whitespace(port_str_tok);

                                if (proto_str_tok && port_str_tok && *proto_str_tok != '\0' && *port_str_tok != '\0') {
                                    int proto = string_to_protocol(proto_str_tok);
                                    if (proto < 0) { proto = atoi(proto_str_tok); if (proto <= 0 || proto > 255) { fprintf(stderr, "Error: Invalid proto '%s' for %s line %d.\n", proto_str_tok, current_policy->source_ip_str, line_num); service_parse_ok = 0; break; } }

                                    uint16_t port;
                                    if (strcasecmp(port_str_tok, "any") == 0) { port = 0; }
                                    else { int p = atoi(port_str_tok); if (p <= 0 || p > 65535) { fprintf(stderr, "Error: Invalid port '%s' for %s line %d.\n", port_str_tok, current_policy->source_ip_str, line_num); service_parse_ok = 0; break; } port = (uint16_t)p; }

                                    printf("    DEBUG PARSE: ProtoStr='%s' PortStr='%s' -> ProtoInt=%d PortInt=%u\n", proto_str_tok, port_str_tok, proto, port);

                                    if (!add_allowed_service(current_policy, (uint8_t)proto, port)) { fprintf(stderr, "Error: Failed adding service %s/%s line %d.\n", proto_str_tok, port_str_tok, line_num); service_parse_ok = 0; break; }
                                    else { current_policy->has_ports = 1; }
                                } else { fprintf(stderr, "Error: Empty proto/port after splitting '%s' line %d.\n", service_buffer, line_num); service_parse_ok = 0; break; }
                            } else { fprintf(stderr, "Error: Malformed service '%s' (missing '/') line %d.\n", trimmed_service, line_num); service_parse_ok = 0; break; }
                        }
                         if (!service_parse_ok) break; // Stop processing ports on this line if error
                    } // end while (current_pos != NULL)
                    //--- End Corrected OPEN_PORTS Parsing ---
                } else {
                    fprintf(stderr, "Warning: Unknown key '%s' for IP %s line %d.\n", key, current_policy->source_ip_str, line_num);
                }
            } else {
                 fprintf(stderr, "Warning: Malformed line %d for IP %s (No valid separator/value found?). Ignoring: %s\n", line_num, current_policy->source_ip_str, trimmed_line);
            }
        } else {
             fprintf(stderr, "Warning: Ignoring line %d outside of stanza: %s\n", line_num, trimmed_line);
        }
    } // end while fgets

    // --- Add the last parsed policy if valid ---
    if (current_policy != NULL) {
        if (current_policy->has_enc_key && current_policy->has_hmac_key && current_policy->has_ports) {
            current_policy->next = g_policy_list; g_policy_list = current_policy; policies_loaded++;
            printf("  + Completed policy for: %s\n", current_policy->source_ip_str);
        } else {
            fprintf(stderr, "Warning: Discarding incomplete policy for [%s] at end of file.\n", current_policy->source_ip_str);
            free_allowed_services(current_policy->allowed_services); free(current_policy);
        }
    }

    fclose(fp);
    printf("Finished loading policies. %d policies loaded.\n", policies_loaded);
    return policies_loaded >= 0;
}


// --- Crypto/Network Helpers Implementation ---
void handle_openssl_error_server(const char *msg) { fprintf(stderr, "OSSL Error (%s): ", msg); ERR_print_errors_fp(stderr); fprintf(stderr, "\n"); }
int constant_time_memcmp(const void *a, const void *b, size_t size) { const unsigned char *ap = a, *bp = b; volatile unsigned char r = 0; for (size_t i = 0; i < size; ++i) r |= ap[i] ^ bp[i]; return r != 0; }
// Assumes protocol_to_string and string_to_protocol are defined elsewhere (e.g., spa_common.c)
int get_interface_ip(const char *if_name, char *ip_buf, size_t len) { struct ifaddrs *ifaddr, *ifa; int fam, s; char host[NI_MAXHOST]; int found = 0; if(getifaddrs(&ifaddr)==-1){perror("getifaddrs");return -1;} for(ifa=ifaddr; ifa!=NULL; ifa=ifa->ifa_next){if(ifa->ifa_addr == NULL) continue; fam=ifa->ifa_addr->sa_family; if(strcmp(ifa->ifa_name, if_name)==0 && fam==AF_INET){s=getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in), host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST); if(s==0){strncpy(ip_buf, host, len-1); ip_buf[len-1]='\0'; found=1; break;} else {fprintf(stderr,"getnameinfo fail: %s\n",gai_strerror(s));}}} freeifaddrs(ifaddr); return found?0:-1; }

// --- Packet Handler (Main Logic) ---
void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    const int ETH_HDR_LEN = 14;
    char source_ip_str[INET_ADDRSTRLEN];
    char dest_ip_str[INET_ADDRSTRLEN]; // For logging, not policy
    uint16_t source_port, dest_port;   // For logging, not policy
    struct tm *tm_info; time_t now; char time_buf[30];

    (void)user_data; // Mark as unused to silence warning

    now = time(NULL); tm_info = localtime(&now); strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", tm_info);
    printf("\n[%s] Packet received (len %u)\n", time_buf, pkthdr->len);

    // --- Basic Packet Parsing (Ethernet, IP, UDP) ---
    if (pkthdr->caplen < (unsigned int)ETH_HDR_LEN) { printf("  -> Discard: < ETH_HDR_LEN\n"); return; }
    const struct ip *ip_header = (struct ip *)(packet + ETH_HDR_LEN);
    int ip_hdr_len = ip_header->ip_hl * 4;
    if (pkthdr->caplen < (unsigned int)(ETH_HDR_LEN + ip_hdr_len)) { printf("  -> Discard: < IP_HDR_LEN\n"); return; }
    if (ip_header->ip_p != IPPROTO_UDP) { /* Filtered by pcap */ return; }
    const struct udphdr *udp_header = (struct udphdr *)((u_char *)ip_header + ip_hdr_len);
    int udp_hdr_len = sizeof(struct udphdr);
     if (pkthdr->caplen < (unsigned int)(ETH_HDR_LEN + ip_hdr_len + udp_hdr_len)) { printf("  -> Discard: < UDP_HDR_LEN\n"); return; }

    // Get Source IP - Crucial for policy lookup
    inet_ntop(AF_INET, &(ip_header->ip_src), source_ip_str, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), dest_ip_str, INET_ADDRSTRLEN);
    source_port = ntohs(udp_header->source);
    dest_port = ntohs(udp_header->uh_dport);
    printf("  Source: %s:%u, Dest: %s:%u\n", source_ip_str, source_port, dest_ip_str, dest_port);


    // --- Find Policy for this Source IP ---
    client_policy_t *policy = find_policy_by_ip(source_ip_str);
    if (!policy) {
        printf("  -> Discarding: No policy found for source IP %s.\n", source_ip_str);
        return; // No policy defined for this client IP
    }
    printf("  Policy found for %s. Proceeding with validation...\n", source_ip_str);

    // --- SPA Processing (using the found policy) ---
    const u_char *payload = (u_char *)udp_header + udp_hdr_len;
    int payload_len = pkthdr->caplen - (ETH_HDR_LEN + ip_hdr_len + udp_hdr_len);
    if ((size_t)payload_len < SPA_PACKET_MIN_LEN || (size_t)payload_len > SPA_PACKET_MAX_LEN) {
         printf(" -> Discarding: Invalid payload length %d (Min %zu, Max %zu).\n",
                payload_len, (size_t)SPA_PACKET_MIN_LEN, (size_t)SPA_PACKET_MAX_LEN);
         return;
    }

    const unsigned char *iv = payload;
    const unsigned char *encrypted_data = payload + SPA_IV_LEN;
    int encrypted_len = payload_len - SPA_IV_LEN - SPA_HMAC_LEN;
    const unsigned char *received_hmac = payload + SPA_IV_LEN + encrypted_len;
    if (encrypted_len <= 0) { printf(" -> Discarding: Invalid encrypted length %d.\n", encrypted_len); return; }

    // --- 1. Verify HMAC using policy's HMAC_KEY ---
    printf("  Verifying HMAC using key for %s... ", source_ip_str);
    unsigned char calculated_hmac[EVP_MAX_MD_SIZE]; unsigned int calc_hmac_len = 0;
    const EVP_MD *digest = EVP_get_digestbyname(SPA_HMAC_ALGO);
    if (!digest) { fprintf(stderr, "HMAC Algo '%s' failed!\n", SPA_HMAC_ALGO); return; }
    unsigned char data_to_hmac[SPA_IV_LEN + encrypted_len];
    memcpy(data_to_hmac, iv, SPA_IV_LEN); memcpy(data_to_hmac + SPA_IV_LEN, encrypted_data, encrypted_len);

    // Use the specific key and length from the policy
    HMAC(digest, policy->hmac_key, policy->hmac_key_len,
         data_to_hmac, SPA_IV_LEN + encrypted_len, calculated_hmac, &calc_hmac_len);

    if (calc_hmac_len != SPA_HMAC_LEN) { printf("FAILED (Internal HMAC length error)\n"); return; }
    if (constant_time_memcmp(received_hmac, calculated_hmac, SPA_HMAC_LEN) != 0) {
        printf("FAILED (HMAC Mismatch)\n"); printf("  -> Discarding: Invalid HMAC for policy %s.\n", source_ip_str); return;
    }
    printf("OK\n");

    // --- 2. Decrypt Data using policy's ENCRYPTION_KEY ---
    printf("  Decrypting data using key for %s... ", source_ip_str);
    unsigned char decrypted_data[sizeof(spa_data_t)]; int decrypted_len = 0, final_len = 0; int decrypt_ok = 1;
    const EVP_CIPHER *cipher = EVP_get_cipherbyname(SPA_ENCRYPTION_ALGO);
    if (!cipher) { fprintf(stderr, "Cipher Algo '%s' failed!\n", SPA_ENCRYPTION_ALGO); return; }
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new(); if (!ctx) { handle_openssl_error_server("CTX New"); return; }

    // Use the specific key and length from the policy
    if (1 != EVP_DecryptInit_ex(ctx, cipher, NULL, policy->enc_key, iv)) { handle_openssl_error_server("DecryptInit"); decrypt_ok = 0; }
    if (decrypt_ok && 1 != EVP_DecryptUpdate(ctx, decrypted_data, &decrypted_len, encrypted_data, encrypted_len)) { ERR_clear_error(); decrypt_ok = 0; }
    if (decrypt_ok && 1 != EVP_DecryptFinal_ex(ctx, decrypted_data + decrypted_len, &final_len)) { ERR_clear_error(); decrypt_ok = 0; }
    EVP_CIPHER_CTX_free(ctx);

    if (!decrypt_ok) { printf("FAILED (Decryption Error)\n"); printf("  -> Discarding: Decryption failed for policy %s (Wrong ENC Key?).\n", source_ip_str); return; }
    decrypted_len += final_len;
    printf("OK (Plaintext size %d)\n", decrypted_len);

    // --- 3. Validate Decrypted Payload ---
    if ((size_t)decrypted_len != sizeof(spa_data_t)) { fprintf(stderr, "  Error: Decrypted size %d != expected %zu.\n", decrypted_len, sizeof(spa_data_t)); return; }
    spa_data_t *spa_info = (spa_data_t *)decrypted_data;

    if (spa_info->version != SPA_VERSION) { fprintf(stderr, "  Error: Invalid version %u.\n", spa_info->version); return; }
    time_t current_time = time(NULL); int64_t time_diff = (int64_t)current_time - (int64_t)spa_info->timestamp;
    if (llabs(time_diff) > SPA_TIMESTAMP_WINDOW_SECONDS) { fprintf(stderr, "  Error: Timestamp invalid (Diff %llds > %ds).\n", (long long)time_diff, SPA_TIMESTAMP_WINDOW_SECONDS); return; }
    printf("  Payload validation OK (Version %u, Timestamp diff %llds).\n", spa_info->version, (long long)time_diff);

    // --- 4. Policy Check: Is the requested service allowed for this client? ---
    uint16_t requested_target_port = ntohs(spa_info->req_port);
    uint8_t requested_protocol = spa_info->req_protocol;
    const char* requested_proto_str = protocol_to_string(requested_protocol);
    char requested_port_str[12]; // Buffer for port string or "any"
    if (requested_target_port == 0) { strcpy(requested_port_str, "any"); }
    else { snprintf(requested_port_str, sizeof(requested_port_str), "%u", requested_target_port); }
    printf("  Client %s requests access to %s/%s.\n", source_ip_str, requested_proto_str, requested_port_str);

    if (is_request_allowed(policy, requested_protocol, requested_target_port)) {
        // --- REQUEST ALLOWED BY POLICY ---
        printf("  POLICY CHECK: Request ALLOWED for %s.\n", source_ip_str);
        const uint16_t duration = SPA_DEFAULT_DURATION_SECONDS;

        printf("----------------------------------------\n");
        printf("  POLICY VALIDATED SPA Packet!\n");
        printf("  Client Source IP:  %s\n", source_ip_str);
        printf("  Requested Service: %s/%s\n", requested_proto_str, requested_port_str);
        printf("  Access Duration:   %u seconds\n", duration);
        printf("----------------------------------------\n");

        // --- 5. Execute Firewall Command ---
        printf("FIREWALL ACTION:\n");
        if (requested_protocol > 0) { // Ensure protocol is valid
            char iptables_add_cmd[512]; char iptables_del_cmd[512]; char comment_str[128]; int ret;
            char dport_arg[32];

            if (requested_target_port == 0) { dport_arg[0] = '\0'; } // No --dport argument for 'any' port
            else { snprintf(dport_arg, sizeof(dport_arg), "--dport %u", requested_target_port); }

            snprintf(comment_str, sizeof(comment_str), "SPA[%s] Allow %s:%s/%s (%us)", source_ip_str, source_ip_str, requested_proto_str, requested_port_str, duration);
            snprintf(iptables_add_cmd, sizeof(iptables_add_cmd), "iptables -I INPUT 1 -s %s -p %s %s -m conntrack --ctstate NEW -m comment --comment \"%s\" -j ACCEPT", source_ip_str, requested_proto_str, dport_arg, comment_str);

            printf("  Executing ADD rule:\n  %s\n", iptables_add_cmd);
            ret = system(iptables_add_cmd);
            if (ret == -1) { perror("  ERROR: system(iptables ADD) failed"); }
             else if (WIFEXITED(ret) && WEXITSTATUS(ret) != 0) { fprintf(stderr, "  WARNING: iptables ADD command exited with non-zero status: %d\n", WEXITSTATUS(ret)); }
            else if (WIFSIGNALED(ret)) { fprintf(stderr, "  WARNING: iptables ADD command killed by signal: %d\n", WTERMSIG(ret)); }
            else {
                printf("  iptables ADD executed successfully.\n");
                snprintf(iptables_del_cmd, sizeof(iptables_del_cmd), "sh -c 'sleep %u && iptables -D INPUT -s %s -p %s %s -m conntrack --ctstate NEW -m comment --comment \"%s\" -j ACCEPT' &", duration, source_ip_str, requested_proto_str, dport_arg, comment_str);
                printf("  Scheduling REMOVE rule:\n  %s\n", iptables_del_cmd);
                ret = system(iptables_del_cmd); // Execute in background
                 printf("  iptables REMOVE command scheduled (system ret %d).\n", ret); // Log return value, less critical for background task
            }
            printf("\n  NOTE: Assumes pre-existing: iptables ... ESTABLISHED,RELATED ...\n");
        } else {
            printf("  -> Invalid protocol %d prevented rule execution.\n", requested_protocol);
        }
         printf("----------------------------------------\n");

    } else {
        // --- REQUEST DENIED BY POLICY ---
        printf("  POLICY CHECK: Request DENIED for %s.\n", source_ip_str);
        fprintf(stderr, "  POLICY VIOLATION: Client %s requested %s/%s, which is not allowed by policy.\n",
                source_ip_str, requested_proto_str, requested_port_str);
        // Silently discard after internal logging
    }
}


// --- Main Function ---
int main(int argc, char *argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE]; char *dev = NULL; bpf_u_int32 net, mask; struct bpf_program fp;
    char filter_exp[100]; char server_ip_buf[INET_ADDRSTRLEN] = "N/A"; int use_strdup = 0;

    // Check root privileges first
    if (geteuid() != 0) { fprintf(stderr, "Error: Requires root privileges.\n"); return 1; }

    // --- Load Policies (IP-Keyed) ---
    if (!load_policies_ip_keyed(CONFIG_FILE)) {
        fprintf(stderr, "Warning: Failed to load policies or config file '%s' is empty/invalid.\n", CONFIG_FILE);
    }
    if (g_policy_list == NULL) { fprintf(stderr, "WARNING: No valid client policies loaded! Server will not authorize any SPA requests.\n"); }
    // ----------------------------------

    // --- Interface selection ---
    if (argc > 2 && strcmp(argv[1], "-i") == 0) {
        if (argc > 2 && argv[2] != NULL) { dev = argv[2]; }
        else { fprintf(stderr, "Error: -i requires interface name.\n"); free_policies(g_policy_list); return 1; }
    } else if (argc > 1) { fprintf(stderr, "Usage: %s [-i interface]\n", argv[0]); free_policies(g_policy_list); return 1; }
    else {
        // Using pcap_lookupdev is deprecated, but using it for simplicity.
        printf("Attempting to find default interface (using deprecated pcap_lookupdev)...\n");
        dev = pcap_lookupdev(errbuf);
        if (dev == NULL) { fprintf(stderr, "Warn: pcap_lookupdev: %s\n", errbuf); dev = strdup(SPA_INTERFACE); if (!dev) { perror("strdup failed"); free_policies(g_policy_list); return 2;} use_strdup = 1; printf("Warn: Using fallback '%s'\n", dev); }
    }
    printf("Using interface: %s\n", dev);
    if (get_interface_ip(dev, server_ip_buf, sizeof(server_ip_buf)) == 0) { printf("Server IP on %s: %s\n", dev, server_ip_buf); } else { fprintf(stderr, "Warn: Could not get IP for %s.\n", dev); }

    // --- Crypto Init ---
    OpenSSL_add_all_algorithms(); ERR_load_crypto_strings();
    if (!EVP_get_cipherbyname(SPA_ENCRYPTION_ALGO)) { fprintf(stderr, "Fatal: Enc Algo '%s' missing\n", SPA_ENCRYPTION_ALGO); if(use_strdup)free(dev); free_policies(g_policy_list); return EXIT_FAILURE; }
    if (!EVP_get_digestbyname(SPA_HMAC_ALGO)) { fprintf(stderr, "Fatal: HMAC Algo '%s' missing\n", SPA_HMAC_ALGO); if(use_strdup)free(dev); free_policies(g_policy_list); return EXIT_FAILURE; }
    printf("Crypto algorithms OK (%s / %s).\n", SPA_ENCRYPTION_ALGO, SPA_HMAC_ALGO);

    // --- Pcap Setup ---
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) { fprintf(stderr, "Warn: No netmask for %s: %s\n", dev, errbuf); net=0; mask=0; }
    pcap_handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf); // BUFSIZ defined in stdio.h
    if (!pcap_handle) { fprintf(stderr, "Fatal: pcap_open_live %s: %s\n", dev, errbuf); if(use_strdup)free(dev); free_policies(g_policy_list); return 2; }
    if (pcap_datalink(pcap_handle) != DLT_EN10MB) { fprintf(stderr, "Warn: %s not Ethernet (Datalink %d).\n", dev, pcap_datalink(pcap_handle)); }
    snprintf(filter_exp, sizeof(filter_exp), "udp dst port %d", SPA_SERVER_UDP_PORT);
    printf("Compiling filter: '%s'\n", filter_exp);
    if (pcap_compile(pcap_handle, &fp, filter_exp, 0, net) == -1) { fprintf(stderr, "Fatal: Compile filter: %s\n", pcap_geterr(pcap_handle)); pcap_close(pcap_handle); if(use_strdup)free(dev); free_policies(g_policy_list); return 2; }
    if (pcap_setfilter(pcap_handle, &fp) == -1) { fprintf(stderr, "Fatal: Set filter: %s\n", pcap_geterr(pcap_handle)); pcap_freecode(&fp); pcap_close(pcap_handle); if(use_strdup)free(dev); free_policies(g_policy_list); return 2; }

    printf("SPA Server listening on %s (IP: %s), UDP port %d...\n", dev, server_ip_buf, SPA_SERVER_UDP_PORT);
    printf("Using policy file: %s\n", CONFIG_FILE);
    printf("Waiting for SPA packets. Ctrl+C to exit.\n");

    // --- Signal Handling & Pcap Loop ---
    signal(SIGINT, cleanup); signal(SIGTERM, cleanup); // Setup signal handlers
    int pcap_ret = pcap_loop(pcap_handle, -1, packet_handler, NULL);

    // --- Cleanup ---
    printf("\nPcap loop ended (ret %d).\n", pcap_ret);
    if (pcap_ret == -1) { fprintf(stderr, "Pcap loop error: %s\n", pcap_geterr(pcap_handle)); }
    printf("Cleaning up...\n");
    pcap_freecode(&fp);
    if (pcap_handle) { pcap_close(pcap_handle); pcap_handle = NULL; } // Close pcap handle
    if (use_strdup) { free(dev); dev = NULL; } // Free device name if strdup'd
    EVP_cleanup(); ERR_free_strings(); // OpenSSL cleanup
    free_policies(g_policy_list); // Free loaded policies
    printf("Server shutdown complete.\n");
    return 0;
}

// --- Signal Handler Definition ---
void cleanup(int signo) {
    printf("\nCaught signal %d, shutting down...\n", signo);
    if (pcap_handle) {
        pcap_breakloop(pcap_handle); // Request pcap_loop to exit gracefully
    }
    // Main loop will continue and perform cleanup after pcap_loop returns
}
