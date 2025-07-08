#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <libconfig.h>

#define MAX_PAYLOAD_SIZE 256
#define MAX_CIPHERTEXT_SIZE 512
#define KEY_SIZE 32
#define HMAC_SIZE 32
#define IV_SIZE 16

typedef struct {
    char server_ip[16];
    int server_port;
    unsigned char key[KEY_SIZE];
    unsigned char hmac_key[HMAC_SIZE];
    char network_interface[16];
} spa_config;

typedef struct {
    unsigned char iv[IV_SIZE];
    unsigned char hmac[HMAC_SIZE];
    unsigned char encrypted[MAX_CIPHERTEXT_SIZE];
    size_t encrypted_len;
} spa_packet;

int load_config(const char *filename, spa_config *config) {
    config_t cfg;
    config_init(&cfg);

    if (!config_read_file(&cfg, filename)) {
        fprintf(stderr, "Config error: %s:%d - %s\n",
                config_error_file(&cfg),
                config_error_line(&cfg),
                config_error_text(&cfg));
        config_destroy(&cfg);
        return -1;
    }

    const char *key_base64, *hmac_key_base64;
    
    if (!config_lookup_string(&cfg, "SPA.server_ip", &config->server_ip) ||
        !config_lookup_int(&cfg, "SPA.server_port", &config->server_port) ||
        !config_lookup_string(&cfg, "SPA.key_base64", &key_base64) ||
        !config_lookup_string(&cfg, "SPA.hmac_key_base64", &hmac_key_base64) ||
        !config_lookup_string(&cfg, "SPA.network_interface", &config->network_interface)) {
        fprintf(stderr, "Missing required config values\n");
        config_destroy(&cfg);
        return -1;
    }

    // Base64 decode keys
    BIO *bio, *b64;
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new_mem_buf(key_base64, -1);
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_read(bio, config->key, KEY_SIZE);
    BIO_free_all(bio);

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new_mem_buf(hmac_key_base64, -1);
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_read(bio, config->hmac_key, HMAC_SIZE);
    BIO_free_all(bio);

    config_destroy(&cfg);
    return 0;
}

void generate_spa_packet(const char *client_ip, const char *port, const char *protocol, 
                        const spa_config *config, spa_packet *packet) {
    // Generate random IV
    if (!RAND_bytes(packet->iv, IV_SIZE)) {
        perror("IV generation failed");
        exit(EXIT_FAILURE);
    }

    // Create JSON payload
    char payload[MAX_PAYLOAD_SIZE];
    int payload_len = snprintf(payload, sizeof(payload),
            "{\"timestamp\":%ld,\"client_ip\":\"%s\",\"port\":\"%s\",\"protocol\":\"%s\",\"interface\":\"%s\"}",
            time(NULL), client_ip, port, protocol, config->network_interface);
    
    if (payload_len >= sizeof(payload)) {
        fprintf(stderr, "Payload too large\n");
        exit(EXIT_FAILURE);
    }

    // Initialize encryption
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, config->key, packet->iv)) {
        fprintf(stderr, "Encryption init failed\n");
        EVP_CIPHER_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    // Encrypt payload
    int len;
    if (!EVP_EncryptUpdate(ctx, packet->encrypted, &len, 
                         (unsigned char *)payload, payload_len)) {
        fprintf(stderr, "Encryption failed\n");
        EVP_CIPHER_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }
    packet->encrypted_len = len;

    if (!EVP_EncryptFinal_ex(ctx, packet->encrypted + len, &len)) {
        fprintf(stderr, "Encryption finalization failed\n");
        EVP_CIPHER_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }
    packet->encrypted_len += len;
    EVP_CIPHER_CTX_free(ctx);

    // Generate HMAC
    EVP_MD_CTX *hmac_ctx = EVP_MD_CTX_new();
    EVP_PKEY *pkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, config->hmac_key, HMAC_SIZE);
    
    if (!EVP_DigestSignInit(hmac_ctx, NULL, EVP_sha256(), NULL, pkey) ||
        !EVP_DigestSignUpdate(hmac_ctx, packet->iv, IV_SIZE) ||
        !EVP_DigestSignUpdate(hmac_ctx, packet->encrypted, packet->encrypted_len)) {
        fprintf(stderr, "HMAC generation failed\n");
        EVP_MD_CTX_free(hmac_ctx);
        EVP_PKEY_free(pkey);
        exit(EXIT_FAILURE);
    }

    size_t hmac_len = HMAC_SIZE;
    if (!EVP_DigestSignFinal(hmac_ctx, packet->hmac, &hmac_len)) {
        fprintf(stderr, "HMAC finalization failed\n");
        EVP_MD_CTX_free(hmac_ctx);
        EVP_PKEY_free(pkey);
        exit(EXIT_FAILURE);
    }

    EVP_MD_CTX_free(hmac_ctx);
    EVP_PKEY_free(pkey);
}

int main(int argc, char *argv[]) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <client_ip> <port> <protocol>\n", argv[0]);
        fprintf(stderr, "Example: %s 10.9.64.244 22 tcp\n", argv[0]);
        return EXIT_FAILURE;
    }

    // Load configuration
    spa_config config;
    if (load_config("spa_client.conf", &config) != 0) {
        return EXIT_FAILURE;
    }

    // Validate inputs
    struct in_addr addr;
    if (inet_pton(AF_INET, argv[1], &addr) != 1) {
        fprintf(stderr, "Invalid IP address\n");
        return EXIT_FAILURE;
    }

    long port = strtol(argv[2], NULL, 10);
    if (port <= 0 || port > 65535) {
        fprintf(stderr, "Invalid port number\n");
        return EXIT_FAILURE;
    }

    if (strcmp(argv[3], "tcp") != 0 && strcmp(argv[3], "udp") != 0) {
        fprintf(stderr, "Protocol must be tcp or udp\n");
        return EXIT_FAILURE;
    }

    // Create and send packet
    spa_packet packet;
    generate_spa_packet(argv[1], argv[2], argv[3], &config, &packet);

    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("Socket creation failed");
        return EXIT_FAILURE;
    }

    struct sockaddr_in servaddr = {
        .sin_family = AF_INET,
        .sin_port = htons(config.server_port),
        .sin_addr.s_addr = inet_addr(config.server_ip)
    };

    size_t packet_size = IV_SIZE + HMAC_SIZE + packet.encrypted_len;
    if (sendto(sockfd, &packet, packet_size, 0,
              (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
        perror("Packet send failed");
        close(sockfd);
        return EXIT_FAILURE;
    }

    printf("SPA packet successfully sent to %s:%d\n", config.server_ip, config.server_port);
    close(sockfd);
    return EXIT_SUCCESS;
}