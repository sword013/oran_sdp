// spa_client.c (Standalone Utility - Reads Keys from File)
#define _GNU_SOURCE // For asprintf
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/err.h>
#include <ctype.h> // For isspace
#include <endian.h> // For htobe64/32

#include "spa_common.h" // Include common definitions

// --- Client-side Key Storage ---
typedef struct {
    unsigned char enc_key[MAX_KEY_LEN];     size_t enc_key_len;
    unsigned char hmac_key[MAX_KEY_LEN];    size_t hmac_key_len;
    unsigned char hotp_secret[MAX_KEY_LEN]; size_t hotp_secret_len;
} target_server_keys_t;

// --- Helper Functions (Subset needed for key loading) ---
// Assumed defined in linked spa_common.o:
//   trim_whitespace()
//   hex_string_to_bytes()
//   generate_hotp()
//   handle_openssl_error()
//   protocol_to_string()
//   string_to_protocol()

// Load keys for a specific server IP from the config file
int load_keys_for_target(const char *filename, const char *target_server_ip, target_server_keys_t *keys_out) {
    FILE *fp = fopen(filename, "r");
    if (!fp) { perror("Error opening client key config file"); fprintf(stderr, "Could not open: %s\n", filename); return 0; }
    printf("[SPA_CLIENT] Loading keys for target %s from %s\n", target_server_ip, filename);
    memset(keys_out, 0, sizeof(target_server_keys_t)); // Zero out structure

    char line[1024]; int line_num = 0; int in_correct_stanza = 0;
    int found_enc = 0, found_hmac = 0, found_hotp = 0;

    while (fgets(line, sizeof(line), fp)) {
        line_num++;
        char *trimmed_line = trim_whitespace(line);
        if (!trimmed_line || trimmed_line[0] == '\0' || trimmed_line[0] == '#') continue;

        if (trimmed_line[0] == '[' && trimmed_line[strlen(trimmed_line) - 1] == ']') {
            char current_ip[INET_ADDRSTRLEN]; size_t id_len = strlen(trimmed_line) - 2;
            if (id_len < INET_ADDRSTRLEN && id_len > 0) { strncpy(current_ip, trimmed_line + 1, id_len); current_ip[id_len] = '\0'; if (strcmp(current_ip, target_server_ip) == 0) { printf("  Found stanza for %s\n", target_server_ip); in_correct_stanza = 1; } else { if (in_correct_stanza) break; in_correct_stanza = 0; } } else { in_correct_stanza = 0; }
        } else if (in_correct_stanza) {
            char *key = trimmed_line; char *value = NULL;
            for (char *p = key; *p != '\0'; ++p) { if (isspace((unsigned char)*p) || *p == '=') { *p = '\0'; value = p + 1; while (*value != '\0' && (isspace((unsigned char)*value) || *value == '=')) { value++; } break; } }
            if (value != NULL && *value != '\0') {
                key = trim_whitespace(key); char *cmt = strchr(value,'#'); if(cmt) *cmt = '\0'; value = trim_whitespace(value);
                if (strlen(key) == 0 || strlen(value) == 0) continue;
                if (strcasecmp(key, "ENCRYPTION_KEY") == 0) { int len = hex_string_to_bytes(value, keys_out->enc_key, MAX_KEY_LEN); if (len > 0) { keys_out->enc_key_len = (size_t)len; found_enc = 1; } else { fprintf(stderr, "Error: Invalid ENC key line %d\n", line_num); fclose(fp); return 0; } }
                else if (strcasecmp(key, "HMAC_KEY") == 0) { int len = hex_string_to_bytes(value, keys_out->hmac_key, MAX_KEY_LEN); if (len > 0) { keys_out->hmac_key_len = (size_t)len; found_hmac = 1; } else { fprintf(stderr, "Error: Invalid HMAC key line %d\n", line_num); fclose(fp); return 0; } }
                else if (strcasecmp(key, "HOTP_SECRET") == 0) { int len = hex_string_to_bytes(value, keys_out->hotp_secret, MAX_KEY_LEN); if (len > 0) { keys_out->hotp_secret_len = (size_t)len; found_hotp = 1; } else { fprintf(stderr, "Error: Invalid HOTP secret line %d\n", line_num); fclose(fp); return 0; } }
                if (found_enc && found_hmac && found_hotp) break; // Early exit once all found
            }
        }
    }
    fclose(fp);
    if (!in_correct_stanza) { fprintf(stderr, "Error: Stanza for %s not found in %s\n", target_server_ip, filename); return 0; }
    if (!found_enc || !found_hmac || !found_hotp) { fprintf(stderr, "Error: Missing keys for %s in %s\n", target_server_ip, filename); return 0; }
    printf("Successfully loaded keys for %s\n", target_server_ip); return 1;
}


// --- Main Client Logic ---
int main(int argc, char *argv[]) {
    if (argc != 6) {
        fprintf(stderr, "Usage: %s <target_ip> <protocol> <target_port> <hotp_counter> <key_config_file>\n", argv[0]);
        return EXIT_FAILURE;
    }
    const char *target_ip = argv[1];
    const char *req_protocol_str = argv[2];
    int req_target_port_num = atoi(argv[3]);
    uint64_t current_hotp_counter = strtoull(argv[4], NULL, 10);
    const char *key_config_file = argv[5];

    target_server_keys_t keys;
    if (!load_keys_for_target(key_config_file, target_ip, &keys)) { return EXIT_FAILURE; }

    int req_protocol = string_to_protocol(req_protocol_str);
    if (req_protocol < 0) { req_protocol = atoi(req_protocol_str); if (req_protocol <= 0 || req_protocol > 255) { fprintf(stderr, "Invalid protocol '%s'.\n", req_protocol_str); return EXIT_FAILURE; } }
    if (req_target_port_num < 0 || req_target_port_num > 65535) { fprintf(stderr, "Invalid target port %d.\n", req_target_port_num); return EXIT_FAILURE; }

    // Init OpenSSL (Needed for RAND, EVP, HMAC)
    initialize_openssl(); // Assumes spa_common.c linked

    printf("Generating HOTP for counter %llu...\n", (unsigned long long)current_hotp_counter);
    uint32_t hotp_code = generate_hotp(keys.hotp_secret, keys.hotp_secret_len, current_hotp_counter, HOTP_CODE_DIGITS);
    if (hotp_code == (uint32_t)-1) { fprintf(stderr, "Error generating HOTP code.\n"); cleanup_openssl(); return EXIT_FAILURE; }
    printf("Generated HOTP Code: %0*u\n", HOTP_CODE_DIGITS, hotp_code);

    spa_data_t spa_data; memset(&spa_data, 0, sizeof(spa_data));
    spa_data.version = SPA_VERSION; spa_data.timestamp = htobe64(time(NULL)); spa_data.source_ip_internal = 0;
    spa_data.req_protocol = (uint8_t)req_protocol; spa_data.req_port = htons((uint16_t)req_target_port_num);
    if (RAND_bytes(spa_data.nonce, SPA_NONCE_LEN) != 1) { handle_openssl_error("Nonce gen failed"); cleanup_openssl(); return EXIT_FAILURE; }
    spa_data.hotp_counter = htobe64(current_hotp_counter); spa_data.hotp_code = htonl(hotp_code);

    printf("SPA Data Prepared (To be encrypted):\n"); // Add logging if needed

    unsigned char iv[SPA_IV_LEN]; if (RAND_bytes(iv, SPA_IV_LEN)!=1) { handle_openssl_error("IV Gen"); cleanup_openssl(); return EXIT_FAILURE;}
    unsigned char *encrypted_data_buf = malloc(sizeof(spa_data_t) + SPA_IV_LEN); if(!encrypted_data_buf) {perror("malloc enc buf"); cleanup_openssl(); return EXIT_FAILURE;}
    unsigned char hmac_result[EVP_MAX_MD_SIZE]; unsigned int hmac_len = 0; int encrypted_len = 0, final_len = 0;
    const EVP_CIPHER *cipher = EVP_get_cipherbyname(SPA_ENCRYPTION_ALGO); if (!cipher) { handle_openssl_error("Get Cipher"); free(encrypted_data_buf); cleanup_openssl(); return EXIT_FAILURE;}
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new(); if (!ctx) { handle_openssl_error("CTX New"); free(encrypted_data_buf); cleanup_openssl(); return EXIT_FAILURE;}

    printf("Encrypting using loaded key (len %zu)...\n", keys.enc_key_len);
    if (1!=EVP_EncryptInit_ex(ctx, cipher, NULL, keys.enc_key, iv)) { handle_openssl_error("EncryptInit"); goto client_cleanup_ctx; }
    if (1!=EVP_EncryptUpdate(ctx, encrypted_data_buf, &encrypted_len, (const unsigned char*)&spa_data, sizeof(spa_data))) { handle_openssl_error("EncryptUpdate"); goto client_cleanup_ctx; }
    if (1!=EVP_EncryptFinal_ex(ctx, encrypted_data_buf + encrypted_len, &final_len)) { handle_openssl_error("EncryptFinal"); goto client_cleanup_ctx; }
    encrypted_len += final_len; EVP_CIPHER_CTX_free(ctx); ctx = NULL; printf("Encryption OK. Len: %d\n", encrypted_len);

    size_t data_to_hmac_len = SPA_IV_LEN + encrypted_len; unsigned char *data_to_hmac = malloc(data_to_hmac_len); if (!data_to_hmac) { perror("malloc data_hmac"); goto client_cleanup_noctx; }
    memcpy(data_to_hmac, iv, SPA_IV_LEN); memcpy(data_to_hmac + SPA_IV_LEN, encrypted_data_buf, encrypted_len);
    const EVP_MD *digest = EVP_get_digestbyname(SPA_HMAC_ALGO); if (!digest) { handle_openssl_error("Get Digest"); free(data_to_hmac); goto client_cleanup_noctx; }
    printf("Calculating HMAC using loaded key (len %zu)...\n", keys.hmac_key_len);
    if (HMAC(digest, keys.hmac_key, keys.hmac_key_len, data_to_hmac, data_to_hmac_len, hmac_result, &hmac_len) == NULL) { handle_openssl_error("HMAC Calc"); free(data_to_hmac); goto client_cleanup_noctx; }
    free(data_to_hmac); data_to_hmac = NULL;
    if (hmac_len != SPA_HMAC_LEN) { fprintf(stderr, "Bad HMAC length %u\n", hmac_len); goto client_cleanup_noctx; } printf("HMAC OK. Len: %u\n", hmac_len);

    size_t final_packet_len = SPA_IV_LEN + encrypted_len + hmac_len; unsigned char *final_packet = malloc(final_packet_len); if (!final_packet) { perror("Malloc final"); goto client_cleanup_noctx; }
    memcpy(final_packet, iv, SPA_IV_LEN); memcpy(final_packet + SPA_IV_LEN, encrypted_data_buf, encrypted_len); memcpy(final_packet + SPA_IV_LEN + encrypted_len, hmac_result, hmac_len); free(encrypted_data_buf); encrypted_data_buf=NULL; // Free now

    int sockfd = -1; struct sockaddr_in server_addr; int result = EXIT_FAILURE;
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) { perror("socket"); goto client_cleanup_final; }
    memset(&server_addr, 0, sizeof(server_addr)); server_addr.sin_family = AF_INET; server_addr.sin_port = htons(SPA_LISTENER_PORT);
    if (inet_pton(AF_INET, target_ip, &server_addr.sin_addr) <= 0) { fprintf(stderr, "Invalid target IP: %s\n", target_ip); goto client_cleanup_final; }
    printf("Sending SPA packet (%zu bytes) to %s:%u...\n", final_packet_len, target_ip, SPA_LISTENER_PORT);
    ssize_t bytes_sent = sendto(sockfd, final_packet, final_packet_len, 0, (const struct sockaddr *)&server_addr, sizeof(server_addr));
    if (bytes_sent < 0) { perror("sendto failed"); } else if ((size_t)bytes_sent != final_packet_len) { fprintf(stderr, "Partial send %zd/%zu\n", bytes_sent, final_packet_len); } else { printf("SPA packet sent successfully.\n"); result = EXIT_SUCCESS; }

client_cleanup_final:
    if(sockfd >= 0) close(sockfd);
    if(final_packet) free(final_packet);
client_cleanup_noctx: // Label used if ctx is already freed
    if(encrypted_data_buf) free(encrypted_data_buf); // Free if allocated
    if(data_to_hmac) free(data_to_hmac); // Free if allocated
    cleanup_openssl(); // Call common cleanup
    return result;
client_cleanup_ctx: // Label used if ctx needs freeing
    if(ctx) EVP_CIPHER_CTX_free(ctx);
    goto client_cleanup_noctx; // Jump to common cleanup after freeing context
}