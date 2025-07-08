// spa_common.c (Complete Code with TUN/TAP Helper - Output Commented)
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
// Make sure stdio.h is included
#include <ctype.h> // For isprint


// --- Includes needed for TUN/TAP ---
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <fcntl.h> // For open flags
// ----------------------------------


#include "spa_common.h"


// --- OpenSSL Initialization and Cleanup ---
void initialize_openssl() {
    // Load error strings for libcrypto and libssl
    SSL_load_error_strings();
    // Load algorithms
    OpenSSL_add_ssl_algorithms(); // Or OPENSSL_init_ssl for newer OpenSSL
    // printf("[COMMON] OpenSSL Initialized.\n");
}


void cleanup_openssl() {
    // Free loaded error strings
    ERR_free_strings();
    // Free digests and ciphers
    EVP_cleanup();
    // Optional: Deinitialize library in newer OpenSSL (consult docs)
    // CONF_modules_unload(1);
    // CRYPTO_cleanup_all_ex_data();
    // printf("[COMMON] OpenSSL Cleaned up.\n");
}


// --- OpenSSL Error Handler ---
void handle_openssl_error(const char *msg) {
    // fprintf(stderr, "--> OpenSSL Error Occurred (%s):\n", msg);
    unsigned long err_code;
    while ((err_code = ERR_get_error()) != 0) {
        char err_buf[256];
        ERR_error_string_n(err_code, err_buf, sizeof(err_buf));
        // fprintf(stderr, "  - %s\n", err_buf);
    }
    // fflush(stderr); // No need to flush if nothing is printed
}


// --- HOTP Generation (RFC 4226) ---
uint32_t generate_hotp(const unsigned char *key, size_t key_len, uint64_t counter, int digits) {
    unsigned char hmac_result[EVP_MAX_MD_SIZE];
    unsigned int hmac_len = 0;
    unsigned char counter_bytes[8];
    uint32_t code = (uint32_t)-1; // Indicate error by default
    int offset;


    if (!key || key_len == 0 || digits <= 0 || digits > 9) {
        // fprintf(stderr, "Error: Invalid arguments to generate_hotp\n");
        return code;
    }


    // Convert counter to network byte order (big-endian) byte array
    uint64_t counter_be = htobe64(counter); // Host to Big-Endian
    memcpy(counter_bytes, &counter_be, 8);


    // Calculate HMAC-SHA1 (as specified in RFC 4226 for HOTP)
    if (HMAC(EVP_sha1(), key, key_len, counter_bytes, 8, hmac_result, &hmac_len) == NULL) {
        handle_openssl_error("HMAC calculation in generate_hotp");
        return code;
    }


    if (hmac_len < 20) { // Should be 20 bytes for SHA-1
        // fprintf(stderr, "Error: HMAC-SHA1 result too short (%u bytes)\n", hmac_len);
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
         // fprintf(stderr, "Error: Too many digits requested for HOTP (%d), power overflow.\n", digits);
         return code;
    }
    uint32_t power_of_10 = (uint32_t)power_double;


    code = binary % power_of_10;


    return code;
}


// --- Protocol Converters (Formatted for Readability) ---
const char* protocol_to_string(int proto) {
    static char p_str[16]; // Buffer for numeric representation
    switch(proto) {
        case IPPROTO_TCP: return "tcp";
        case IPPROTO_UDP: return "udp";
        case 132:         return "sctp"; // Standard SCTP Number
        case IPPROTO_ICMP: return "icmp";
        // Add other common protocols if needed
        default:
            // Convert unknown protocol number to string
            snprintf(p_str, sizeof(p_str), "%d", proto);
            return p_str;
    }
}


int string_to_protocol(const char* proto_str) {
    if (!proto_str) { return -1; } // Handle NULL input

    if (strcasecmp(proto_str, "tcp") == 0) { return IPPROTO_TCP; }
    if (strcasecmp(proto_str, "udp") == 0) { return IPPROTO_UDP; }
    if (strcasecmp(proto_str, "sctp") == 0) { return 132; } // Standard SCTP Number
    if (strcasecmp(proto_str, "icmp") == 0) { return IPPROTO_ICMP; }
    // Add other common protocols if needed

    // Try converting numeric string
    char *endptr;
    long num = strtol(proto_str, &endptr, 10);

    // Check if the entire string was a valid number in the protocol range
    if (*endptr == '\0' && num > 0 && num <= 255) {
        return (int)num;
    }

    return -1; // Indicate unknown string or invalid number
}


// --- String/Data Helpers ---
char* trim_whitespace(char *str) {
    if (str == NULL) { return NULL; } // Handle NULL input
    char *end;

    // Trim leading space
    while(isspace((unsigned char)*str)) { str++; }

    if(*str == 0) { // All spaces?
        return str;
    }

    // Trim trailing space
    end = str + strlen(str) - 1;
    while(end > str && isspace((unsigned char)*end)) { end--; }

    // Write new null terminator character
    end[1] = '\0';

    return str;
}

int hex_string_to_bytes(const char *hex_string, unsigned char *byte_array, size_t max_len) {
    if (!hex_string || !byte_array) { return -1; } // Check for NULL pointers

    size_t len = strlen(hex_string);
    // Hex string must have an even number of characters and not be empty
    if (len == 0 || len % 2 != 0) { return -1; }

    size_t byte_len = len / 2;
    // Check if the output buffer is large enough
    if (byte_len > max_len) { return -1; }

    for (size_t i = 0; i < byte_len; i++) {
        // Read two hex characters at a time
        if (sscanf(hex_string + 2 * i, "%2hhx", &byte_array[i]) != 1) {
            // Failed to parse hex characters
            return -1;
        }
    }

    return (int)byte_len; // Return the number of bytes written
}

int constant_time_memcmp(const void *a, const void *b, size_t size) {
     const unsigned char *ap = a;
     const unsigned char *bp = b;
     volatile unsigned char result = 0; // Use volatile to prevent optimizations

     for (size_t i = 0; i < size; ++i) {
         result |= (ap[i] ^ bp[i]); // XOR bytes; result is non-zero if any bytes differ
     }

     // Returns 0 if they are equal, non-zero otherwise (standard memcmp behavior)
     return (result != 0);
}


// --- Basic TCP Socket Helper (Still needed for mTLS) ---
int open_tcp_connection(const char *hostname, int port) {
     int sd = -1;
     struct addrinfo hints, *res = NULL, *rp = NULL;
     char port_str[16];

     snprintf(port_str, sizeof(port_str), "%d", port); // Convert port to string

     memset(&hints, 0, sizeof(hints));
     hints.ai_family = AF_INET;       // Use IPv4 for simplicity here, adjust if needed
     hints.ai_socktype = SOCK_STREAM; // TCP socket

     int status = getaddrinfo(hostname, port_str, &hints, &res);
     if (status != 0) {
         // fprintf(stderr, "[COMMON] getaddrinfo failed for %s:%d : %s\n", hostname, port, gai_strerror(status));
         return -1;
     }

     // Try each address returned by getaddrinfo until we successfully connect
     for (rp = res; rp != NULL; rp = rp->ai_next) {
         sd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
         if (sd == -1) {
             // perror("[COMMON] socket creation failed");
             continue; // Try next address
         }

         if (connect(sd, rp->ai_addr, rp->ai_addrlen) != -1) {
             // printf("[COMMON] TCP Connection established to %s:%d (FD %d)\n", hostname, port, sd); // DEBUG
             break; // Success!
         } else {
             // perror("[COMMON] connect failed");
             close(sd); // Close the failed socket descriptor
             sd = -1;
         }
     }

     freeaddrinfo(res); // Free the linked list allocated by getaddrinfo

     if (sd == -1) {
         // fprintf(stderr, "[COMMON] Failed to connect to %s:%d after trying all addresses\n", hostname, port);
     }

     return sd; // Return socket descriptor on success, -1 on failure
}


// --- Revised mTLS Helper Implementations ---
SSL_CTX* create_ssl_context(int is_server) {
     // Use TLS_method() for compatibility, negotiates highest common version
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

     // Set secure options: disable vulnerable protocols
     // SSL_OP_ALL enables bug workarounds, recommended.
     long options = SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1;
     SSL_CTX_set_options(ctx, options);

     // Explicitly set minimum TLS version to 1.2 for clarity and security
     if (!SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION)) {
         handle_openssl_error("Set Min Proto TLS 1.2 failed");
         // Depending on OpenSSL version, this might not be strictly fatal if TLS_method handles it
         // SSL_CTX_free(ctx); // Decide if this error is critical
         // return NULL;
     }

     // printf("[COMMON] SSL Context created (TLS 1.2+ preferred).\n");
     return ctx;
}

int configure_ssl_context(SSL_CTX *ctx, const char* ca_path, const char* cert_path, const char* key_path, int is_server) {
     if (!ctx || !ca_path || !cert_path || !key_path) return 0;

     // printf("[COMMON] Configuring SSL Context: CA=%s Cert=%s Key=%s ServerMode=%d\n", ca_path, cert_path, key_path, is_server);

     // Load CA certificate for verifying the peer
     if (SSL_CTX_load_verify_locations(ctx, ca_path, NULL) != 1) {
         handle_openssl_error("Load Verify Locations (CA Cert)");
         return 0;
     }

     // Load our own certificate chain
     if (SSL_CTX_use_certificate_chain_file(ctx, cert_path) != 1) {
         handle_openssl_error("Use Certificate Chain File");
         return 0;
     }

     // Load our private key
     if (SSL_CTX_use_PrivateKey_file(ctx, key_path, SSL_FILETYPE_PEM) != 1 ) {
         handle_openssl_error("Use Private Key File");
         return 0;
     }

     // Check if the private key matches the certificate
     if (!SSL_CTX_check_private_key(ctx)) {
         handle_openssl_error("Check Private Key failed (mismatch?)");
         return 0;
     }

     if (is_server) {
         // Server: Require client certificate and verify it against our CA
         SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL /* No verify callback */);

         // Optionally provide a list of CAs we accept client certs from
         // This helps the client choose the right certificate
         STACK_OF(X509_NAME) *ca_list = SSL_load_client_CA_file(ca_path);
         if (ca_list == NULL) {
             // fprintf(stderr, "[COMMON] Warn: Failed load client CA list from %s for server mode.\n", ca_path);
             // This is often not fatal, but good to log if logging is enabled.
         } else {
              SSL_CTX_set_client_CA_list(ctx, ca_list);
         }

     } else {
         // Client: Verify the server's certificate against our CA
         SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL /* No verify callback */);
     }

     // printf("[COMMON] SSL Context configured successfully.\n");
     return 1; // Success
}

void show_peer_certificates(SSL* ssl) {
    X509 *cert = SSL_get_peer_certificate(ssl);
    if (cert != NULL) {
        // printf("Peer Certificates Presented:\n");
        char *line_subj = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        char *line_iss = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        // printf("  Subject: %s\n", line_subj ? line_subj : "<EMPTY>");
        // printf("  Issuer:  %s\n", line_iss ? line_iss : "<EMPTY>");
        OPENSSL_free(line_subj); // Free memory allocated by X509_NAME_oneline
        OPENSSL_free(line_iss);
        X509_free(cert);       // Free the certificate structure
    } else {
        // printf("No peer certificates presented.\n");
    }
}

SSL* establish_mtls_connection(const char* server_ip, uint16_t port, SSL_CTX *ctx) {
     int sock = open_tcp_connection(server_ip, port);
     if (sock < 0) {
         // Error message printed by open_tcp_connection if needed
         return NULL;
     }

     SSL *ssl = SSL_new(ctx);
     if (!ssl) {
         handle_openssl_error("SSL_new");
         close(sock); // Close the underlying socket
         return NULL;
     }

     // Associate the socket with the SSL structure
     if (SSL_set_fd(ssl, sock) == 0) {
         handle_openssl_error("SSL_set_fd");
         SSL_free(ssl); // Frees the SSL struct, does NOT close the fd automatically here
         close(sock);   // We must close the fd manually
         return NULL;
     }

      // Set SNI (Server Name Indication) - Good practice for clients
      // Use server_ip as hostname for SNI - adjust if using DNS names primarily
      if (SSL_set_tlsext_host_name(ssl, server_ip) != 1) {
          // SNI failure is often non-fatal but can cause issues with some server configs
          handle_openssl_error("SSL Set SNI failed (Warning)");
      }

     // printf("[COMMON_mTLS] Performing SSL/TLS handshake with %s:%u (SSL_connect)...\n", server_ip, port);
     // Perform the TLS handshake (client-side)
     int ret = SSL_connect(ssl);
     if (ret <= 0) {
         int err = SSL_get_error(ssl, ret); // Get specific SSL error
         // fprintf(stderr, "[COMMON_mTLS] *** SSL_connect FAILED [Code: %d] ***\n", err);
         handle_openssl_error("SSL_connect stage"); // Log detailed OpenSSL errors
         SSL_free(ssl); // Frees SSL structure, close(sock) happens automatically via SSL_free ONLY if BIO owns fd
         // Since we used SSL_set_fd, we likely need to close sock manually
         // close(sock); // Redundant? Check OpenSSL docs for SSL_free behavior with SSL_set_fd sockets
         // It's safer to close it explicitly if unsure. Let's assume we need to.
         // Note: If SSL_free *does* close the fd, closing it again is harmless (returns -EBADF)
         close(sock);
         return NULL;
     }

     // Handshake successful
     // printf(" --> mTLS Handshake OK. Cipher: %s Version: %s\n", SSL_get_cipher(ssl), SSL_get_version(ssl));

     // Verify the peer's certificate
     // printf(" Verifying peer certificate...\n");
     show_peer_certificates(ssl); // Print details if needed (now commented out)

     long verify_result = SSL_get_verify_result(ssl);
     if (verify_result != X509_V_OK) {
         // fprintf(stderr," Error: Peer certificate verification failed: %s (%ld)\n",
         //         X509_verify_cert_error_string(verify_result), verify_result);
         SSL_shutdown(ssl); // Attempt clean shutdown
         SSL_free(ssl);     // Free SSL structure
         close(sock);       // Close socket
         return NULL;
     }
     // printf(" Peer certificate verification OK (X509_V_OK).\n");

     return ssl; // Return the established SSL connection handle
}

int send_data_over_mtls(SSL *ssl, const char *data) {
    if (!ssl || !data) { return -1; }

    int len = strlen(data);
    int bytes_written = SSL_write(ssl, data, len);

    if (bytes_written <= 0) {
        int ssl_error = SSL_get_error(ssl, bytes_written);
        // Handle specific non-fatal errors or log fatal ones
        if (ssl_error != SSL_ERROR_ZERO_RETURN && // Connection closed cleanly
            ssl_error != SSL_ERROR_WANT_WRITE && // Need to call SSL_write again later
            ssl_error != SSL_ERROR_WANT_READ) {  // Need to call SSL_read then SSL_write again
            // fprintf(stderr, "[COMMON] SSL_write failed: %d - ", ssl_error);
            handle_openssl_error("SSL_write");
        } else if (ssl_error == SSL_ERROR_ZERO_RETURN) {
            // printf("[COMMON] SSL_write: Connection closed by peer.\n");
        }
        return -1; // Indicate failure or closed connection
    }
    // printf("[COMMON] SSL_write: Sent %d bytes.\n", bytes_written); // DEBUG
    return bytes_written; // Return number of bytes written
}


// --- Integrated SPA Packet Sending Function --- (No change needed, internal prints commented)
int send_spa_packet(const char* target_ip, uint16_t target_port,
                const unsigned char* enc_key, /* NO size_t enc_key_len */
                const unsigned char* hmac_key, size_t hmac_key_len,
                const unsigned char* hotp_secret, size_t hotp_secret_len,
                uint64_t hotp_counter,
                uint8_t req_proto, uint16_t req_port_host)
{
    // printf("[SPA_SEND] Prep SPA for %s:%u (Ctr:%llu Req:%u/%u)\n", target_ip, target_port, (unsigned long long)hotp_counter, req_proto, req_port_host);

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
    const EVP_MD *digest = NULL;

    // Allocate buffer large enough for encrypted data + potential padding
    encrypted_data_buf = malloc(sizeof(spa_data_t) + SPA_IV_LEN); // Over-estimate is fine
    if (!encrypted_data_buf) {
        // perror("[SPA_SEND] malloc encrypted_data_buf failed");
        goto cleanup;
    }

    // 1. Generate HOTP Code
    hotp_code = generate_hotp(hotp_secret, hotp_secret_len, hotp_counter, HOTP_CODE_DIGITS);
    if (hotp_code == (uint32_t)-1) {
        // Error logged within generate_hotp
        // fprintf(stderr, "[SPA_SEND] Failed to generate HOTP code.\n");
        goto cleanup;
    }
    // printf("[SPA_SEND] Generated HOTP: %0*u for Counter: %llu\n", HOTP_CODE_DIGITS, hotp_code, (unsigned long long)hotp_counter); // DEBUG

    // 2. Prepare SPA Data Payload (Plaintext)
    memset(&spa_data, 0, sizeof(spa_data));
    spa_data.version = SPA_VERSION;
    spa_data.timestamp = htobe64(time(NULL)); // Use current time, convert to Big Endian
    spa_data.source_ip_internal = 0; // Set to 0 if not using internal IP field
    spa_data.req_protocol = req_proto;
    spa_data.req_port = htons(req_port_host); // Convert requested port to Network Byte Order
    if (RAND_bytes(spa_data.nonce, SPA_NONCE_LEN) != 1) { // Generate cryptographic nonce
        handle_openssl_error("RAND_bytes for nonce failed");
        goto cleanup;
    }
    spa_data.hotp_counter = htobe64(hotp_counter); // Convert counter to Big Endian
    spa_data.hotp_code = htonl(hotp_code);       // Convert HOTP code to Network Byte Order


    // 3. Generate Random IV
    if (RAND_bytes(iv, SPA_IV_LEN) != 1) {
        handle_openssl_error("RAND_bytes for IV failed");
        goto cleanup;
    }

    // 4. Encrypt SPA Data Payload
    cipher = EVP_get_cipherbyname(SPA_ENCRYPTION_ALGO);
    if (!cipher) {
        // fprintf(stderr, "[SPA_SEND] EVP_get_cipherbyname failed for %s\n", SPA_ENCRYPTION_ALGO);
        goto cleanup;
    }
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        handle_openssl_error("EVP_CIPHER_CTX_new failed");
        goto cleanup;
    }

    // Initialize encryption context
    if (1 != EVP_EncryptInit_ex(ctx, cipher, NULL, enc_key, iv)) {
        handle_openssl_error("EVP_EncryptInit_ex failed");
        goto cleanup_ctx;
    }

    // Encrypt the data
    if (1 != EVP_EncryptUpdate(ctx, encrypted_data_buf, &encrypted_len, (const unsigned char*)&spa_data, sizeof(spa_data))) {
        handle_openssl_error("EVP_EncryptUpdate failed");
        goto cleanup_ctx;
    }

    // Finalize encryption (handles padding)
    if (1 != EVP_EncryptFinal_ex(ctx, encrypted_data_buf + encrypted_len, &final_len)) {
        handle_openssl_error("EVP_EncryptFinal_ex failed");
        goto cleanup_ctx;
    }
    encrypted_len += final_len; // Total length of the ciphertext

    EVP_CIPHER_CTX_free(ctx); ctx = NULL; // Clean up context immediately

    // 5. Prepare Data for HMAC (IV + Ciphertext)
    size_t data_to_hmac_len = SPA_IV_LEN + encrypted_len;
    data_to_hmac = malloc(data_to_hmac_len);
    if (!data_to_hmac) {
        // perror("[SPA_SEND] malloc data_to_hmac failed");
        goto cleanup;
    }
    memcpy(data_to_hmac, iv, SPA_IV_LEN);
    memcpy(data_to_hmac + SPA_IV_LEN, encrypted_data_buf, encrypted_len);

    // 6. Calculate HMAC
    digest = EVP_get_digestbyname(SPA_HMAC_ALGO);
    if (!digest) {
        // fprintf(stderr, "[SPA_SEND] EVP_get_digestbyname failed for %s\n", SPA_HMAC_ALGO);
        goto cleanup;
    }
    if (HMAC(digest, hmac_key, hmac_key_len, data_to_hmac, data_to_hmac_len, hmac_result, &hmac_len) == NULL) {
        handle_openssl_error("HMAC calculation failed");
        goto cleanup;
    }
    free(data_to_hmac); data_to_hmac = NULL; // Free intermediate buffer

    // Ensure HMAC length is as expected
    if (hmac_len != SPA_HMAC_LEN) {
        // fprintf(stderr, "[SPA_SEND] Error: Unexpected HMAC length %u (expected %d)\n", hmac_len, SPA_HMAC_LEN);
        goto cleanup;
    }

    // 7. Construct Final UDP Packet (IV + Ciphertext + HMAC)
    final_packet_len = SPA_IV_LEN + encrypted_len + hmac_len;
    final_packet = malloc(final_packet_len);
    if (!final_packet) {
        // perror("[SPA_SEND] malloc final_packet failed");
        goto cleanup;
    }
    memcpy(final_packet, iv, SPA_IV_LEN);                                // Copy IV
    memcpy(final_packet + SPA_IV_LEN, encrypted_data_buf, encrypted_len); // Copy Ciphertext
    memcpy(final_packet + SPA_IV_LEN + encrypted_len, hmac_result, hmac_len); // Copy HMAC

    // 8. Send UDP Packet
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        // perror("[SPA_SEND] socket creation failed");
        goto cleanup;
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(target_port);
    if (inet_pton(AF_INET, target_ip, &server_addr.sin_addr) <= 0) {
        // perror("[SPA_SEND] inet_pton failed");
        // fprintf(stderr, "[SPA_SEND] Invalid target IP address: %s\n", target_ip);
        goto cleanup;
    }

    // printf("[SPA_SEND] Sending %zu bytes to %s:%u...\n", final_packet_len, target_ip, target_port);
    ssize_t sent = sendto(sockfd, final_packet, final_packet_len, 0, (const struct sockaddr *)&server_addr, sizeof(server_addr));

    if (sent < 0) {
        // perror("[SPA_SEND] sendto failed");
    } else if ((size_t)sent != final_packet_len) {
        // fprintf(stderr, "[SPA_SEND] Partial send: sent %zd bytes, expected %zu bytes.\n", sent, final_packet_len);
    } else {
        // printf("[SPA_SEND] SPA packet sent successfully.\n");
        result = 0; // Success!
    }

cleanup_ctx:
    if(ctx) EVP_CIPHER_CTX_free(ctx); // Ensure context is freed if an error occurred mid-encryption
cleanup:
    // Free all allocated resources
    if(sockfd >= 0) close(sockfd);
    if(final_packet) free(final_packet);
    if(encrypted_data_buf) free(encrypted_data_buf);
    if(data_to_hmac) free(data_to_hmac); // Should be NULL unless error occurred before free

    return result; // 0 on success, -1 on failure
}


// --- TUN/TAP Helper ---
/**
* Allocate or reconnect to a TUN/TAP device.
* dev_name: Buffer for the device name (e.g., "tun0", "tun%d"). Updated by ioctl if empty.
* flags:    IFF_TUN or IFF_TAP, plus optional IFF_NO_PI.
* Returns the file descriptor of the new device, or -1 on error.
*/
int tun_alloc(char *dev_name, int flags) {
  struct ifreq ifr;
  int fd, err;
  const char *clonedev = "/dev/net/tun"; // Standard path for the TUN/TAP control device


  // Open the clone device
  if ((fd = open(clonedev, O_RDWR)) < 0) {
      // perror("[COMMON] tun_alloc: Opening /dev/net/tun failed");
      return fd; // Return negative fd on error
  }


  memset(&ifr, 0, sizeof(ifr));
  ifr.ifr_flags = flags; // Set flags (e.g., IFF_TUN | IFF_NO_PI)


  if (dev_name && *dev_name) {
      // If a device name was specified (e.g., "tun0"), pass it in the structure
      strncpy(ifr.ifr_name, dev_name, IFNAMSIZ - 1);
      ifr.ifr_name[IFNAMSIZ - 1] = '\0'; // Ensure null termination
  }
  // If dev_name is empty or like "tun%d", kernel will assign a name


  // Try to create the device interface using ioctl
  if ((err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0) {
      // perror("[COMMON] tun_alloc: ioctl(TUNSETIFF) failed");
      close(fd);
      return err; // Return negative error code
  }


  // If the device name was potentially assigned by the kernel, copy it back
  if (dev_name) {
       strcpy(dev_name, ifr.ifr_name);
  }


  // printf("[COMMON] tun_alloc: Tunnel device %s created/attached (FD %d).\n", ifr.ifr_name, fd);
  return fd; // Return the positive file descriptor on success
}


// --- Add Helper: Print Hex Dump ---
/**
* Prints the first 'len' bytes of a buffer in hex and ASCII.
* title: A string to print before the dump.
* buf:   Pointer to the data buffer.
* len:   Number of bytes to print.
* max_print: Maximum number of bytes to actually dump (to avoid huge logs).
*/
void print_hex(const char *title, const unsigned char *buf, size_t len, size_t max_print) {
   // printf("[HEX DUMP] %s (%zu bytes):\n", title, len);
   size_t print_len = (len < max_print) ? len : max_print;
   if (print_len == 0) {
       // printf("  (Buffer Empty)\n");
       return;
   }


   const int bytes_per_line = 16;
   char hex_line[bytes_per_line * 3 + 1]; // 2 hex chars + space per byte
   char ascii_line[bytes_per_line + 1];


   for (size_t i = 0; i < print_len; ++i) {
       size_t line_offset = i % bytes_per_line;


       // Add hex representation
       sprintf(hex_line + line_offset * 3, "%02x ", buf[i]);


       // Add ASCII representation (or '.' for non-printable)
       ascii_line[line_offset] = isprint(buf[i]) ? buf[i] : '.';


       // Print line if complete or if it's the last byte
       if (line_offset == bytes_per_line - 1 || i == print_len - 1) {
           // Null-terminate ASCII line
           ascii_line[line_offset + 1] = '\0';
           // Pad hex line if incomplete
           for (size_t j = line_offset + 1; j < bytes_per_line; ++j) {
               strcat(hex_line, "   "); // 3 spaces for padding
           }
           // Print offset, hex, and ASCII
           // printf("  %04lx: %s |%s|\n", i - line_offset, hex_line, ascii_line);
           // Reset for next line
           memset(hex_line, 0, sizeof(hex_line));
           memset(ascii_line, 0, sizeof(ascii_line));
       }
   }
   if (print_len < len) {
       // printf("  (... %zu more bytes ...)\n", len - print_len);
   }
   // printf("[HEX DUMP END] %s\n", title);
}

