// spa_client.c
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

#include "spa_common.h" // Include common definitions

void handle_openssl_error(const char *msg) {
    fprintf(stderr, "OpenSSL Error (%s): ", msg);
    ERR_print_errors_fp(stderr);
    fprintf(stderr, "\n");
    exit(EXIT_FAILURE);
}

int main(int argc, char *argv[]) {
    if (argc != 5) {
        fprintf(stderr, "Usage: %s <server_ip> <protocol> <port> <duration_seconds>\n", argv[0]);
        fprintf(stderr, "  protocol: tcp, udp, sctp, or numeric IPPROTO value\n");
        fprintf(stderr, "Example: %s 192.168.1.100 sctp 9999 300\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *server_ip_str = argv[1];
    const char *req_protocol_str = argv[2];
    int req_port_num = atoi(argv[3]);
    int req_duration_num = atoi(argv[4]);

    // --- Validate Input ---
    int req_protocol = string_to_protocol(req_protocol_str);
    if (req_protocol < 0) {
        // Try parsing as a number
        req_protocol = atoi(req_protocol_str);
        if (req_protocol <= 0 || req_protocol > 255) {
             fprintf(stderr, "Error: Invalid protocol '%s'. Use common names (tcp, udp, sctp) or IPPROTO number (1-255).\n", req_protocol_str);
             return EXIT_FAILURE;
        }
        printf("Warning: Using numeric protocol %d\n", req_protocol);
    }

    if (req_port_num <= 0 || req_port_num > 65535) {
        fprintf(stderr, "Error: Invalid port number %d.\n", req_port_num);
        return EXIT_FAILURE;
    }
     if (req_duration_num <= 0 || req_duration_num > 65535) {
        fprintf(stderr, "Error: Invalid duration %d. Should be > 0 and <= 65535.\n", req_duration_num);
        return EXIT_FAILURE;
    }

    // --- Prepare SPA Data ---
    spa_data_t spa_data;
    memset(&spa_data, 0, sizeof(spa_data));

    spa_data.version = SPA_VERSION;
    spa_data.timestamp = time(NULL);
    spa_data.source_ip = 0; // Set to 0; server uses actual packet source IP
    spa_data.req_protocol = (uint8_t)req_protocol;
    spa_data.req_port = htons((uint16_t)req_port_num); // Network byte order
    spa_data.req_duration = (uint16_t)req_duration_num; // Host byte order (simple)

    // Generate Nonce
    if (RAND_bytes(spa_data.nonce, SPA_NONCE_LEN) != 1) {
        handle_openssl_error("Failed to generate nonce");
    }

    printf("SPA Data Prepared:\n");
    printf("  Version:   %u\n", spa_data.version);
    printf("  Timestamp: %llu\n", (unsigned long long)spa_data.timestamp);
    printf("  Protocol:  %s (%d)\n", protocol_to_string(spa_data.req_protocol), spa_data.req_protocol);
    printf("  Port:      %u\n", ntohs(spa_data.req_port));
    printf("  Duration:  %u seconds\n", spa_data.req_duration);
    // Don't print nonce/key

    // --- Cryptographic Operations ---
    unsigned char iv[SPA_IV_LEN];
    unsigned char encrypted_data[sizeof(spa_data_t) + SPA_IV_LEN]; // Max possible size with padding
    unsigned char hmac_result[EVP_MAX_MD_SIZE]; // Use max size for safety
    unsigned int hmac_len = 0;
    int encrypted_len = 0;
    int final_len = 0;

    // Generate IV
    if (RAND_bytes(iv, SPA_IV_LEN) != 1) {
        handle_openssl_error("Failed to generate IV");
    }

    // Load crypto algorithms
    OpenSSL_add_all_algorithms(); // Required for EVP_get_cipherbyname etc.
    ERR_load_crypto_strings();

    const EVP_CIPHER *cipher = EVP_get_cipherbyname(SPA_ENCRYPTION_ALGO);
    if (!cipher) handle_openssl_error("Failed to get cipher");
    const EVP_MD *digest = EVP_get_digestbyname(SPA_HMAC_ALGO);
     if (!digest) handle_openssl_error("Failed to get digest");

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handle_openssl_error("Failed to create cipher context");

    // Encrypt
    if (1 != EVP_EncryptInit_ex(ctx, cipher, NULL, (const unsigned char*)SPA_PSK, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        handle_openssl_error("EVP_EncryptInit_ex failed");
    }

    // EVP encrypt functions handle padding automatically
    if (1 != EVP_EncryptUpdate(ctx, encrypted_data, &encrypted_len, (const unsigned char*)&spa_data, sizeof(spa_data))) {
        EVP_CIPHER_CTX_free(ctx);
        handle_openssl_error("EVP_EncryptUpdate failed");
    }

    if (1 != EVP_EncryptFinal_ex(ctx, encrypted_data + encrypted_len, &final_len)) {
        EVP_CIPHER_CTX_free(ctx);
        handle_openssl_error("EVP_EncryptFinal_ex failed");
    }
    encrypted_len += final_len;
    EVP_CIPHER_CTX_free(ctx);

    printf("Encryption successful. Ciphertext length: %d\n", encrypted_len);

    // Prepare data for HMAC: IV + Ciphertext
    unsigned char data_to_hmac[SPA_IV_LEN + encrypted_len];
    memcpy(data_to_hmac, iv, SPA_IV_LEN);
    memcpy(data_to_hmac + SPA_IV_LEN, encrypted_data, encrypted_len);

    // Calculate HMAC
    HMAC(digest, SPA_PSK, strlen(SPA_PSK), data_to_hmac, SPA_IV_LEN + encrypted_len, hmac_result, &hmac_len);

    if (hmac_len != SPA_HMAC_LEN) {
         fprintf(stderr, "Error: Unexpected HMAC length %u (expected %d)\n", hmac_len, SPA_HMAC_LEN);
         return EXIT_FAILURE;
    }
    printf("HMAC calculated successfully. HMAC length: %u\n", hmac_len);


    // --- Assemble Final Packet ---
    size_t final_packet_len = SPA_IV_LEN + encrypted_len + hmac_len;
    unsigned char *final_packet = malloc(final_packet_len);
    if (!final_packet) {
        perror("Failed to allocate memory for final packet");
        return EXIT_FAILURE;
    }

    memcpy(final_packet, iv, SPA_IV_LEN);                             // IV
    memcpy(final_packet + SPA_IV_LEN, encrypted_data, encrypted_len); // Ciphertext
    memcpy(final_packet + SPA_IV_LEN + encrypted_len, hmac_result, hmac_len); // HMAC

    // --- Send UDP Packet ---
    int sockfd;
    struct sockaddr_in server_addr;

    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket creation failed");
        free(final_packet);
        return EXIT_FAILURE;
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SPA_SERVER_UDP_PORT);
    if (inet_pton(AF_INET, server_ip_str, &server_addr.sin_addr) <= 0) {
        fprintf(stderr, "Invalid server IP address: %s\n", server_ip_str);
        close(sockfd);
        free(final_packet);
        return EXIT_FAILURE;
    }

    printf("Sending SPA packet (%zu bytes) to %s:%d...\n", final_packet_len, server_ip_str, SPA_SERVER_UDP_PORT);

    ssize_t bytes_sent = sendto(sockfd, final_packet, final_packet_len, 0,
                                (const struct sockaddr *)&server_addr, sizeof(server_addr));

    if (bytes_sent < 0) {
        perror("sendto failed");
    } else if ((size_t)bytes_sent != final_packet_len) {
        fprintf(stderr, "Error: sendto sent %zd bytes, expected %zu\n", bytes_sent, final_packet_len);
    } else {
        printf("SPA packet sent successfully.\n");
    }

    // --- Cleanup ---
    close(sockfd);
    free(final_packet);
    EVP_cleanup(); // Clean up OpenSSL algorithms
    ERR_free_strings(); // Clean up OpenSSL error strings

    return (bytes_sent == (ssize_t)final_packet_len) ? EXIT_SUCCESS : EXIT_FAILURE;
}