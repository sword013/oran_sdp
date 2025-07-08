// spa_common.c (Complete Code)
#define _DEFAULT_SOURCE // For endian.h, timersub on some systems
#define _GNU_SOURCE     // For asprintf
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>      // For getaddrinfo
#include <openssl/hmac.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h> // For certificate checking
#include <endian.h>
#include <math.h>
#include <ctype.h>

#include "spa_common.h"

// --- OpenSSL Initialization and Cleanup ---
void initialize_openssl() {
   // Load error strings for libcrypto and libssl
   SSL_load_error_strings();
   // Load algorithms
   OpenSSL_add_ssl_algorithms(); // Or OPENSSL_init_ssl for newer OpenSSL
   printf("[COMMON] OpenSSL Initialized.\n");
}

void cleanup_openssl() {
   // Free loaded error strings
   ERR_free_strings();
   // Free digests and ciphers
   EVP_cleanup();
   // Optional: Deinitialize library in newer OpenSSL (consult docs)
   // CONF_modules_unload(1);
   // CRYPTO_cleanup_all_ex_data();
   printf("[COMMON] OpenSSL Cleaned up.\n");
}

// --- OpenSSL Error Handler ---
void handle_openssl_error(const char *msg) {
   fprintf(stderr, "--> OpenSSL Error Occurred (%s):\n", msg);
   unsigned long err_code;
   while ((err_code = ERR_get_error()) != 0) {
       char err_buf[256];
       ERR_error_string_n(err_code, err_buf, sizeof(err_buf));
       fprintf(stderr, "  - %s\n", err_buf);
   }
   fflush(stderr);
}

// --- HOTP Generation (RFC 4226) ---
uint32_t generate_hotp(const unsigned char *key, size_t key_len, uint64_t counter, int digits) {
   unsigned char hmac_result[EVP_MAX_MD_SIZE];
   unsigned int hmac_len = 0;
   unsigned char counter_bytes[8];
   uint32_t code = (uint32_t)-1; // Indicate error by default
   int offset;

   if (!key || key_len == 0 || digits <= 0 || digits > 9) {
       fprintf(stderr, "Error: Invalid arguments to generate_hotp\n");
       return code;
   }

   // Convert counter to network byte order (big-endian) byte array
   uint64_t counter_be = htobe64(counter); // Host to Big-Endian
   memcpy(counter_bytes, &counter_be, 8);

   // Calculate HMAC-SHA1 (as specified in RFC 4226 for HOTP)
   // Note: SPA HMAC uses SPA_HMAC_ALGO (sha256), HOTP uses sha1
   if (HMAC(EVP_sha1(), key, key_len, counter_bytes, 8, hmac_result, &hmac_len) == NULL) {
       handle_openssl_error("HMAC calculation in generate_hotp");
       return code;
   }

   if (hmac_len < 20) { // Should be 20 bytes for SHA-1
       fprintf(stderr, "Error: HMAC-SHA1 result too short (%u bytes)\n", hmac_len);
       return code;
   }

   // Dynamic truncation (RFC 4226 Section 5.3)
   offset = hmac_result[19] & 0x0f;

   // Extract 4 bytes starting at the offset, mask MSB
   uint32_t binary =
       ((hmac_result[offset]   & 0x7f) << 24) |
       ((hmac_result[offset+1] & 0xff) << 16) |
       ((hmac_result[offset+2] & 0xff) << 8)  |
       (hmac_result[offset+3] & 0xff);

   // Calculate the code modulo 10^digits
   double power_double = pow(10.0, digits);
   if (power_double <= 0 || power_double > UINT32_MAX) {
        fprintf(stderr, "Error: Too many digits requested for HOTP (%d), power overflow.\n", digits);
        return code;
   }
   uint32_t power_of_10 = (uint32_t)power_double;

   code = binary % power_of_10;

   return code;
}

// --- Protocol Converters (Formatted for Readability) ---
const char* protocol_to_string(int proto) {
   static char p_str[16];
   switch(proto) {
       case IPPROTO_TCP: return "tcp";
       case IPPROTO_UDP: return "udp";
       case 132:         return "sctp"; // Standard SCTP Number
       case IPPROTO_ICMP: return "icmp";
       default:
           snprintf(p_str, sizeof(p_str), "%d", proto);
           return p_str;
   }
}

int string_to_protocol(const char* proto_str) {
   if (!proto_str) {
        return -1;
   }
   if (strcasecmp(proto_str, "tcp") == 0) {
       return IPPROTO_TCP;
   }
   if (strcasecmp(proto_str, "udp") == 0) {
       return IPPROTO_UDP;
   }
   if (strcasecmp(proto_str, "sctp") == 0) {
       return 132; // Standard SCTP Number
   }
   if (strcasecmp(proto_str, "icmp") == 0) {
       return IPPROTO_ICMP;
   }
   // Try to parse as a number
   char *endptr;
   long num = strtol(proto_str, &endptr, 10);
   // Check if conversion was successful (no leftover chars) and in valid proto range
   if (*endptr == '\0' && num > 0 && num <= 255) {
       return (int)num;
   }
   return -1; // Unknown string or invalid number
}

// --- String/Data Helpers ---
char* trim_whitespace(char *str) {
   if (str == NULL) { return NULL; }
   char *end;
   // Trim leading space
   while(isspace((unsigned char)*str)) { str++; }
   if(*str == 0) { return str; } // All spaces?
   // Trim trailing space
   end = str + strlen(str) - 1;
   while(end > str && isspace((unsigned char)*end)) { end--; }
   // Write new null terminator character
   end[1] = '\0';
   return str;
}

int hex_string_to_bytes(const char *hex_string, unsigned char *byte_array, size_t max_len) {
   if (!hex_string || !byte_array) { return -1; }
   size_t len = strlen(hex_string);
   if (len == 0 || len % 2 != 0) { return -1; } // Must be even length
   size_t byte_len = len / 2;
   if (byte_len > max_len) { return -1; } // Output buffer too small
   for (size_t i = 0; i < byte_len; i++) {
       // Use hhx format specifier for unsigned char
       if (sscanf(hex_string + 2 * i, "%2hhx", &byte_array[i]) != 1) {
            return -1; // Invalid hex character
       }
   }
   return (int)byte_len;
}

int constant_time_memcmp(const void *a, const void *b, size_t size) {
    const unsigned char *ap = a;
    const unsigned char *bp = b;
    volatile unsigned char result = 0; // Use volatile to prevent optimization
    for (size_t i = 0; i < size; ++i) {
        result |= (ap[i] ^ bp[i]); // XOR bytes; result is non-zero if any bytes differ
    }
    return (result != 0); // Return 0 if equal, non-zero if different (like memcmp)
}

// --- Basic TCP Socket Helpers ---
int open_tcp_listener(int port) {
   int sd = -1;
   struct sockaddr_in addr;

   sd = socket(PF_INET, SOCK_STREAM, 0);
   if (sd < 0) { perror("socket(listener)"); return -1; }

   // Allow reuse of local addresses
   int reuse = 1;
   if (setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
       perror("setsockopt(SO_REUSEADDR)");
       // Non-fatal, continue anyway?
   }

   memset(&addr, 0, sizeof(addr));
   addr.sin_family = AF_INET;
   addr.sin_port = htons(port);
   addr.sin_addr.s_addr = htonl(INADDR_ANY); // Listen on all interfaces

   if (bind(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
       fprintf(stderr, "[COMMON] Error binding listener port %d: %s\n", port, strerror(errno));
       close(sd);
       return -1;
   }

   // Set socket to listening state
   if (listen(sd, SOMAXCONN) != 0) { // SOMAXCONN is typical backlog size
       perror("listen");
       close(sd);
       return -1;
   }

   printf("[COMMON] TCP Listener opened on port %d (FD %d)\n", port, sd);
   return sd;
}

int open_tcp_connection(const char *hostname, int port) {
    int sd = -1;
    struct addrinfo hints, *res = NULL, *rp = NULL;
    char port_str[16];

    snprintf(port_str, sizeof(port_str), "%d", port);
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;       // IPv4 only for simplicity here
    hints.ai_socktype = SOCK_STREAM;

    // printf("[COMMON] Resolving %s...\n", hostname); // Less verbose
    int status = getaddrinfo(hostname, port_str, &hints, &res);
    if (status != 0) {
        fprintf(stderr, "[COMMON] getaddrinfo for %s:%s failed: %s\n",
                hostname, port_str, gai_strerror(status));
        return -1;
    }

    // printf("[COMMON] Attempting TCP connection to %s:%d...\n", hostname, port);
    // Iterate through the results and connect to the first we can
    for (rp = res; rp != NULL; rp = rp->ai_next) {
        sd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sd == -1) {
            continue; // Try next address
        }

        if (connect(sd, rp->ai_addr, rp->ai_addrlen) != -1) {
            break; // Success
        }

        // Connect failed for this address
        close(sd);
        sd = -1;
    }

    freeaddrinfo(res); // Free the linked list

    if (sd == -1) {
        // No address succeeded
        fprintf(stderr, "[COMMON] Failed to connect to %s:%d\n", hostname, port);
    }
    // else { printf("[COMMON] TCP established (FD %d)\n", sd); } // Less verbose
    return sd;
}

// --- Revised mTLS Helper Implementations --- (Using TLS 1.2+ preferred)
SSL_CTX* create_ssl_context(int is_server) {
    const SSL_METHOD *method = TLS_method();
    if (!method) {
        handle_openssl_error("TLS_method()");
        return NULL;
    }

    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        handle_openssl_error("SSL_CTX_new");
        return NULL;
    }

    // Disable problematic CPU-specific optimizations
    long options = SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | 
                  SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1;
    SSL_CTX_set_options(ctx, options);

    // Force basic cipher suite
    const char* ciphers = "ECDHE-ECDSA-AES128-GCM-SHA256:"
                         "ECDHE-RSA-AES128-GCM-SHA256";
    if (!SSL_CTX_set_cipher_list(ctx, ciphers)) {
        handle_openssl_error("SSL_CTX_set_cipher_list");
        SSL_CTX_free(ctx);
        return NULL;
    }

    printf("[COMMON] SSL Context created (safe mode).\n");
    return ctx;
}
// Configure context with CA, Cert, Key, and Verify settings
int configure_ssl_context(SSL_CTX *ctx, const char* ca_path, const char* cert_path, const char* key_path, int is_server) {
    if (!ctx || !ca_path || !cert_path || !key_path) return 0;

    printf("[COMMON] Configuring SSL Context: CA=%s Cert=%s Key=%s ServerMode=%d\n",
            ca_path, cert_path, key_path, is_server);

    // Load the CA certificate store for verifying the peer
    if (SSL_CTX_load_verify_locations(ctx, ca_path, NULL) != 1) {
        fprintf(stderr, "  [!] Failed loading CA file: %s\n", ca_path);
        handle_openssl_error("SSL_CTX_load_verify_locations");
        return 0;
    }

    // Load our own certificate chain
    if (SSL_CTX_use_certificate_chain_file(ctx, cert_path) != 1) {
        fprintf(stderr, "  [!] Failed loading Certificate Chain file: %s\n", cert_path);
        handle_openssl_error("SSL_CTX_use_certificate_chain_file");
        return 0;
    }

    // Load our private key
    if (SSL_CTX_use_PrivateKey_file(ctx, key_path, SSL_FILETYPE_PEM) != 1 ) {
        fprintf(stderr, "  [!] Failed loading Private Key file: %s\n", key_path);
        handle_openssl_error("SSL_CTX_use_PrivateKey_file");
        return 0;
    }

    // Check if the private key matches the certificate
    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "  [!] Private key does not match the certificate %s\n", cert_path);
        handle_openssl_error("SSL_CTX_check_private_key");
        return 0;
    }

    // --- Set Verification Flags --- 
    if (is_server) {
        // Server mode: Verify the client certificate
        // SSL_VERIFY_PEER: Request a certificate from the client.
        // SSL_VERIFY_FAIL_IF_NO_PEER_CERT: Fail handshake if client doesn't provide one.
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL); // No custom verify callback for now

        // Set the list of CAs to send to the client (helps client choose the right cert)
        SSL_CTX_set_client_CA_list(ctx, SSL_load_client_CA_file(ca_path));
        if (SSL_CTX_get_client_CA_list(ctx) == NULL) {
             fprintf(stderr, "  [!] Failed to load client CA list from %s\n", ca_path);
             handle_openssl_error("SSL_load_client_CA_file");
             // Continue? Or return 0? Let's continue but warn.
        }
    }
    else {
        // Client mode: Verify the server certificate
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL); // No custom verify callback
    }

    printf("[COMMON] SSL Context configured successfully.\n");
    return 1;
}

// Helper to display peer certificate information
void show_peer_certificates(SSL* ssl) {
   X509 *cert = SSL_get_peer_certificate(ssl);
   if (cert != NULL) {
        printf("Peer Certificates Presented:\n");
        char *line_subj = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        char *line_iss = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("  Subject: %s\n", line_subj ? line_subj : "<EMPTY>");
        printf("  Issuer:  %s\n", line_iss ? line_iss : "<EMPTY>");
        OPENSSL_free(line_subj);
        OPENSSL_free(line_iss);
        // You could add more details here like validity period, serial number, etc.
        X509_free(cert);
   } else {
        printf("No peer certificates presented.\n");
   }
}

// Establish mTLS connection (Client Role)
SSL* establish_mtls_connection(const char* server_ip, uint16_t port, SSL_CTX *ctx) {
    int sock = -1;
    SSL *ssl = NULL;
    int ret;

    // 1. Open raw TCP connection
    sock = open_tcp_connection(server_ip, port);
    if (sock < 0) {
        return NULL; // Error message printed in open_tcp_connection
    }

    // 2. Create SSL structure
    ssl = SSL_new(ctx);
    if (!ssl) {
        handle_openssl_error("SSL_new");
        close(sock);
        return NULL;
    }

    // 3. Associate SSL structure with the socket
    if (SSL_set_fd(ssl, sock) == 0) {
        handle_openssl_error("SSL_set_fd");
        SSL_free(ssl); // This also closes the socket 'sock' via SSL_free
        return NULL;
    }

    // 4. Set SNI (Server Name Indication) - Good practice!
    if (SSL_set_tlsext_host_name(ssl, server_ip) != 1) {
        handle_openssl_error("SSL Set SNI failed");
        // Non-fatal? Continue for now.
    }

    // 5. Perform the SSL/TLS handshake (Client initiates)
    printf("[COMMON_mTLS] Performing SSL/TLS handshake with %s:%u (SSL_connect)...\n", server_ip, port);
    ret = SSL_connect(ssl);
    if (ret <= 0) {
        int ssl_error = SSL_get_error(ssl, ret);
        fprintf(stderr, "[COMMON_mTLS] *** SSL_connect FAILED [Code: %d] ***\n", ssl_error);
        handle_openssl_error("SSL_connect stage");
        SSL_free(ssl); // Frees SSL struct and underlying socket
        return NULL;
    }
    printf(" --> mTLS Handshake OK. Cipher: %s Version: %s\n", SSL_get_cipher(ssl), SSL_get_version(ssl));

    // 6. Verify the server's certificate
    printf(" Verifying peer certificate...\n");
    // Optional: Show cert details
    // show_peer_certificates(ssl);

    long verify_result = SSL_get_verify_result(ssl);
    if (verify_result != X509_V_OK) {
        fprintf(stderr," Error: Peer certificate verification failed: %s (%ld)\n",
                X509_verify_cert_error_string(verify_result), verify_result);
        SSL_shutdown(ssl); // Attempt clean shutdown
        SSL_free(ssl); // Frees SSL struct and underlying socket
        return NULL;
    }
    printf(" Peer certificate verification OK (X509_V_OK).\n");

    // If CN or SAN verification against 'server_ip' is needed, do it here.
    // X509 *cert = SSL_get_peer_certificate(ssl);
    // ... verification logic using X509_check_host() or similar ...
    // X509_free(cert);

    return ssl; // Return the established SSL connection
}

// Send data over an established mTLS connection
int send_data_over_mtls(SSL *ssl, const char *data) {
     if (!ssl || !data) { return -1; }
     int len = strlen(data);
     int bytes_written = SSL_write(ssl, data, len);
     if (bytes_written <= 0) {
         int ssl_error = SSL_get_error(ssl, bytes_written);
         // Don't print error for clean shutdown or non-blocking would-block scenarios
         if (ssl_error != SSL_ERROR_ZERO_RETURN && ssl_error != SSL_ERROR_WANT_WRITE && ssl_error != SSL_ERROR_WANT_READ) {
             fprintf(stderr, "[COMMON] SSL_write failed: %d - ", ssl_error);
             handle_openssl_error("SSL_write"); // Print detailed error
         }
         return -1; // Indicate failure
     }
     return bytes_written;
}

// --- Integrated SPA Packet Sending Function (Corrected Signature) ---
int send_spa_packet(const char* target_ip, uint16_t target_port,
                   const unsigned char* enc_key, // <<< NO size_t enc_key_len argument
                   const unsigned char* hmac_key, size_t hmac_key_len,
                   const unsigned char* hotp_secret, size_t hotp_secret_len,
                   uint64_t hotp_counter,
                   uint8_t req_proto, uint16_t req_port_host) // req_port is host byte order
{
   printf("[SPA_SEND] Prep SPA for %s:%u (Ctr:%llu Req:%u/%u)\n", target_ip, target_port,
          (unsigned long long)hotp_counter, req_proto, req_port_host);

   spa_data_t spa_data;
   unsigned char iv[SPA_IV_LEN];
   unsigned char hmac_result[EVP_MAX_MD_SIZE];
   unsigned int hmac_len = 0;
   int encrypted_len = 0, final_len = 0;
   unsigned char *final_packet = NULL;
   size_t final_packet_len = 0;
   int sockfd = -1;
   struct sockaddr_in server_addr;
   int result = -1; // Default to failure
   uint32_t hotp_code;
   const EVP_CIPHER *cipher = NULL;
   EVP_CIPHER_CTX *ctx = NULL;
   unsigned char *encrypted_data_buf = NULL;
   unsigned char *data_to_hmac = NULL;

   // Allocate buffer for ciphertext (max possible size)
   encrypted_data_buf = malloc(sizeof(spa_data_t) + SPA_IV_LEN);
   if (!encrypted_data_buf) { perror("[SPA_SEND] malloc enc buf"); goto cleanup; }

   // 1. Generate HOTP
   hotp_code = generate_hotp(hotp_secret, hotp_secret_len, hotp_counter, HOTP_CODE_DIGITS);
   if (hotp_code == (uint32_t)-1) { fprintf(stderr, "[SPA_SEND] HOTP generation failed\n"); goto cleanup; }

   // 2. Prepare SPA Data Structure
   memset(&spa_data, 0, sizeof(spa_data));
   spa_data.version = SPA_VERSION;
   spa_data.timestamp = htobe64(time(NULL)); // Use network byte order
   spa_data.source_ip_internal = 0; // Set if needed, network byte order
   spa_data.req_protocol = req_proto;
   spa_data.req_port = htons(req_port_host); // Convert req port to network byte order
   if (RAND_bytes(spa_data.nonce, SPA_NONCE_LEN) != 1) { handle_openssl_error("Nonce Gen"); goto cleanup; }
   spa_data.hotp_counter = htobe64(hotp_counter); // Use network byte order
   spa_data.hotp_code = htonl(hotp_code); // Use network byte order

   // 3. Generate IV
   if (RAND_bytes(iv, SPA_IV_LEN) != 1) { handle_openssl_error("IV Gen"); goto cleanup; }

   // 4. Encrypt SPA Data
   cipher = EVP_get_cipherbyname(SPA_ENCRYPTION_ALGO);
   if (!cipher) { handle_openssl_error("Get Cipher"); goto cleanup; }
   ctx = EVP_CIPHER_CTX_new();
   if (!ctx) { handle_openssl_error("CTX New"); goto cleanup; }

   // Initialize encryption context. Key length is derived from the cipher type.
   if (1 != EVP_EncryptInit_ex(ctx, cipher, NULL, enc_key, iv)) {
       handle_openssl_error("EncryptInit"); goto cleanup_ctx;
   }
   // Provide the plaintext data to be encrypted
   if (1 != EVP_EncryptUpdate(ctx, encrypted_data_buf, &encrypted_len, (const unsigned char*)&spa_data, sizeof(spa_data))) {
       handle_openssl_error("EncryptUpdate"); goto cleanup_ctx;
   }
   // Finalize encryption - handles padding if necessary
   if (1 != EVP_EncryptFinal_ex(ctx, encrypted_data_buf + encrypted_len, &final_len)) {
       handle_openssl_error("EncryptFinal"); goto cleanup_ctx;
   }
   encrypted_len += final_len;
   EVP_CIPHER_CTX_free(ctx); ctx = NULL;

   // 5. Calculate HMAC
   // Data for HMAC is IV + Ciphertext
   size_t data_to_hmac_len = SPA_IV_LEN + encrypted_len;
   data_to_hmac = malloc(data_to_hmac_len);
   if (!data_to_hmac) { perror("[SPA_SEND] malloc hmac buf"); goto cleanup; }
   memcpy(data_to_hmac, iv, SPA_IV_LEN);
   memcpy(data_to_hmac + SPA_IV_LEN, encrypted_data_buf, encrypted_len);

   const EVP_MD *digest = EVP_get_digestbyname(SPA_HMAC_ALGO);
   if (!digest) { handle_openssl_error("Get Digest"); goto cleanup; }

   if (HMAC(digest, hmac_key, hmac_key_len, data_to_hmac, data_to_hmac_len, hmac_result, &hmac_len) == NULL) {
       handle_openssl_error("HMAC Calculation"); goto cleanup;
   }
   free(data_to_hmac); data_to_hmac = NULL; // Free intermediate buffer

   if (hmac_len != SPA_HMAC_LEN) {
       fprintf(stderr,"[SPA_SEND] Error: Unexpected HMAC length %u (expected %d)\n", hmac_len, SPA_HMAC_LEN);
       goto cleanup;
   }

   // 6. Assemble Final Packet (IV + Ciphertext + HMAC)
   final_packet_len = SPA_IV_LEN + encrypted_len + hmac_len;
   final_packet = malloc(final_packet_len);
   if (!final_packet) { perror("[SPA_SEND] Malloc final packet"); goto cleanup; }
   memcpy(final_packet, iv, SPA_IV_LEN);
   memcpy(final_packet + SPA_IV_LEN, encrypted_data_buf, encrypted_len);
   memcpy(final_packet + SPA_IV_LEN + encrypted_len, hmac_result, hmac_len);

   // 7. Send UDP Packet
   sockfd = socket(AF_INET, SOCK_DGRAM, 0);
   if (sockfd < 0) { perror("[SPA_SEND] socket"); goto cleanup; }

   memset(&server_addr, 0, sizeof(server_addr));
   server_addr.sin_family = AF_INET;
   server_addr.sin_port = htons(target_port); // Target port (SPA_LISTENER_PORT)
   if (inet_pton(AF_INET, target_ip, &server_addr.sin_addr) <= 0) {
       fprintf(stderr, "[SPA_SEND] Invalid target server IP: %s\n", target_ip);
       goto cleanup;
   }

   printf("[SPA_SEND] Sending %zu bytes to %s:%u...\n", final_packet_len, target_ip, target_port);
   ssize_t sent = sendto(sockfd, final_packet, final_packet_len, 0,
                         (const struct sockaddr *)&server_addr, sizeof(server_addr));

   if (sent < 0) {
       perror("[SPA_SEND] sendto failed");
   } else if ((size_t)sent != final_packet_len) {
       fprintf(stderr, "[SPA_SEND] Error: sendto sent %zd bytes, expected %zu\n", sent, final_packet_len);
   } else {
       printf("[SPA_SEND] SPA packet sent successfully.\n");
       result = 0; // Success!
   }

cleanup_ctx:
   if(ctx) EVP_CIPHER_CTX_free(ctx);
cleanup:
   if(sockfd >= 0) close(sockfd);
   if(final_packet) free(final_packet);
   if(encrypted_data_buf) free(encrypted_data_buf);
   if(data_to_hmac) free(data_to_hmac); // Should be NULL if freed earlier
   return result;
}