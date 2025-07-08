// handle_connections_controller.c (REVISED for NULL checks)
#define _GNU_SOURCE // For asprintf
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <time.h>
#include <ctype.h> // For isspace in trim_whitespace


#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/rand.h>


#include "spa_common.h"
#include "controller_structs.h"


// --- Assumed External Functions (Prototypes needed if not in headers) ---
// Defined in controller.c
extern int check_policy(const char* ih_ip, uint8_t service_proto, uint16_t service_port, const char* ah_ip);
extern int add_connected_ah(const char* ah_ip, SSL* ssl_conn);
extern int remove_connected_ah(const char* ah_ip);
extern int generate_ephemeral_creds(const char* entity_cn, char** cert_pem, char** key_pem);
extern int notify_ah_with_creds(const char* ah_ip, const char* ih_ip, uint8_t service_proto, uint16_t service_port,
                               const char* ih_eph_cert_pem, const char* ah_eph_cert_pem,
                               const char* ah_eph_key_pem, // AH Key PEM
                               const unsigned char* eph_spa_enc_key, size_t eph_spa_enc_key_len,
                               const unsigned char* eph_spa_hmac_key, size_t eph_spa_hmac_key_len,
                               const unsigned char* eph_hotp_secret, size_t eph_hotp_secret_len);
extern int load_policy_rules(const char *filename); // For main()
extern void free_policy_rules(policy_rule_t *head); // For main()


// Defined in spa_common.c (Ensure prototypes are in spa_common.h)
extern int send_data_over_mtls(SSL *ssl, const char *data);
extern void handle_openssl_error(const char *msg);
extern const char* protocol_to_string(int proto);
extern int string_to_protocol(const char* proto_str);
extern char* trim_whitespace(char *str);
extern SSL_CTX* create_ssl_context(int is_server);
extern int configure_ssl_context(SSL_CTX *ctx, const char* ca_path, const char* cert_path, const char* key_path, int is_server);
extern void initialize_openssl();
extern void cleanup_openssl();


// --- Configuration ---
#define CA_CERT_PATH "controller_ca.crt"
#define CTRL_CERT_PATH "controller_10.9.70.137.crt" // Use correct Controller Cert path
#define CTRL_KEY_PATH  "controller_10.9.70.137.key"  // Use correct Controller Key path
#define POLICY_CONFIG_FILE "controller_policy.conf"


// --- Globals ---
int g_listen_sock_ctrl_mtls = -1;
volatile sig_atomic_t g_shutdown_flag_ctrl_mtls = 0;
// Assumes g_policy_rules, g_ah_list_lock, g_connected_ahs defined/locked in controller.c
extern policy_rule_t *g_policy_rules;
extern pthread_mutex_t g_policy_lock; // Assume initialized
extern pthread_mutex_t g_ah_list_lock; // Assume initialized
extern connected_ah_t *g_connected_ahs;


// --- Forward Declarations ---
void* handle_connection_thread_ctrl(void *arg);
SSL_CTX* create_controller_ssl_context();
void cleanup_controller_mtls_listener();
void standalone_listener_cleanup_ctrl(int signo);


// --- SSL Context Setup ---
SSL_CTX* create_controller_ssl_context() {
   SSL_CTX *ctx = create_ssl_context(1); // 1 = Server mode
   if (!ctx) return NULL;
   if (!configure_ssl_context(ctx, CA_CERT_PATH, CTRL_CERT_PATH, CTRL_KEY_PATH, 1)) {
       SSL_CTX_free(ctx);
       return NULL;
   }
   // Optional: Set session ID context for session resumption (if desired)
   // SSL_CTX_set_session_id_context(ctx, (const unsigned char*)"SDP_CTRL", strlen("SDP_CTRL"));
   return ctx;
}


// --- Connection Handling Thread (REVISED with NULL checks) ---
void* handle_connection_thread_ctrl(void *arg) {
    connection_thread_data_t *data = (connection_thread_data_t*)arg;
    SSL *ssl = data->ssl;
    char peer_ip[INET_ADDRSTRLEN];
    strcpy(peer_ip, data->peer_ip); // Copy peer IP locally
    int is_ah_registered = 0;       // Flag if this connection is a registered AH
    int ssl_fd = SSL_get_fd(ssl);   // Get underlying socket FD

    printf("[CTRL_MTLS_Thread %s] Handling connection...\n", peer_ip);
    printf("[CTRL_MTLS_Thread %s] Performing SSL/TLS handshake (SSL_accept)...\n", peer_ip);

    // Perform the TLS/SSL handshake explicitly within the thread
    int ret = SSL_accept(ssl);
    if (ret <= 0) {
        int ssl_error = SSL_get_error(ssl, ret);
        fprintf(stderr, "[CTRL_MTLS_Thread %s] *** SSL_accept FAILED [Code: %d] ***\n", peer_ip, ssl_error);
        handle_openssl_error("SSL_accept stage");
        goto thread_cleanup_ctrl;
    }
    printf("[CTRL_MTLS_Thread %s] SSL handshake successful. Version: %s Cipher: %s\n", peer_ip, SSL_get_version(ssl), SSL_get_cipher(ssl));

    // Verify Peer Certificate CN matches Source IP
    X509 *peer_cert = SSL_get_peer_certificate(ssl);
    int cert_ip_match = 0;
    if (peer_cert) {
        char cn_buf[256] = {0};
        X509_NAME *subj = X509_get_subject_name(peer_cert);
        if (X509_NAME_get_text_by_NID(subj, NID_commonName, cn_buf, sizeof(cn_buf) - 1) > 0) {
            if (strcmp(cn_buf, peer_ip) == 0) {
                cert_ip_match = 1;
                printf("[CTRL_MTLS_Thread %s] Peer CN '%s' matches source IP.\n", peer_ip, cn_buf);
            } else {
                fprintf(stderr, "[CTRL_MTLS_Thread %s] WARNING: Peer CN '%s' does NOT match source IP %s!\n", peer_ip, cn_buf, peer_ip);
            }
        } else {
            fprintf(stderr, "[CTRL_MTLS_Thread %s] Could not get CN from peer cert.\n", peer_ip);
        }
        X509_free(peer_cert);
    } else {
        fprintf(stderr, "[CTRL_MTLS_Thread %s] No peer certificate received.\n", peer_ip);
    }

    if (!cert_ip_match) {
        fprintf(stderr, "[CTRL_MTLS_Thread %s] Rejecting connection: Peer cert validation failed (CN/IP mismatch or missing cert).\n", peer_ip);
        goto thread_cleanup_ctrl;
    }

    // Read Initial Message (with timeout)
    char buffer[4096];
    int bytes_read;
    struct timeval tv; tv.tv_sec = 30; tv.tv_usec = 0; // 30 second read timeout for initial message
    setsockopt(ssl_fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);
    bytes_read = SSL_read(ssl, buffer, sizeof(buffer) - 1);
    tv.tv_sec = 0; tv.tv_usec = 0; // Remove timeout for subsequent operations
    setsockopt(ssl_fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);

    if (bytes_read <= 0) {
        int ssl_error = SSL_get_error(ssl, bytes_read);
        fprintf(stderr, "[CTRL_MTLS_Thread %s] Initial SSL_read failed or timeout: %d\n", peer_ip, ssl_error);
        if (ssl_error != SSL_ERROR_ZERO_RETURN) { // Don't call handler on clean close
             handle_openssl_error("Initial SSL_read");
        }
        goto thread_cleanup_ctrl;
    }
    buffer[bytes_read] = '\0';
    printf("[CTRL_MTLS_Thread %s] Received initial message (%d bytes): %s", peer_ip, bytes_read, buffer); // Log received data

    // --- Process Message ---
    if (strncmp(buffer, "AH_REGISTER", 11) == 0) {
        // --- Handle AH Registration ---
        printf("[CTRL_MTLS_Thread %s] Identified as AH registration.\n", peer_ip);
        if (add_connected_ah(peer_ip, ssl)) {
            is_ah_registered = 1;
            printf("[CTRL_MTLS_Thread %s] AH registered successfully. Monitoring connection...\n", peer_ip);

            // Keepalive/Monitoring loop for AH
            while (!g_shutdown_flag_ctrl_mtls && is_ah_registered) {
                fd_set read_fds; FD_ZERO(&read_fds); FD_SET(ssl_fd, &read_fds);
                struct timeval timeout; timeout.tv_sec = 5; timeout.tv_usec = 0; // Check every 5s

                int activity = select(ssl_fd + 1, &read_fds, NULL, NULL, &timeout);

                if (g_shutdown_flag_ctrl_mtls) {
                    printf("[CTRL_MTLS_Thread %s] Shutdown signaled, closing monitored AH connection.\n", peer_ip);
                    break;
                }
                if (activity < 0) {
                    if (errno == EINTR) continue;
                    perror("[CTRL_MTLS select AH]");
                    is_ah_registered = 0; break; // Treat error as disconnect
                }
                if (activity == 0) continue; // Timeout, loop again

                // Data available or connection closed/error
                if (FD_ISSET(ssl_fd, &read_fds)) {
                    // Use SSL_peek first to differentiate data from closure
                    char peek_buf[10]; // Small buffer for peek
                    int peek_ret = SSL_peek(ssl, peek_buf, sizeof(peek_buf));
                    int ssl_err_peek = SSL_get_error(ssl, peek_ret);

                    if (peek_ret > 0) {
                        // Data available, try a blocking read (but it might still return <= 0)
                        bytes_read = SSL_read(ssl, buffer, sizeof(buffer) - 1);
                        if (bytes_read <= 0) {
                            int ssl_err = SSL_get_error(ssl, bytes_read);
                            printf("[CTRL_MTLS_Thread %s] AH connection SSL_read error after peek (%d).\n", peer_ip, ssl_err);
                            if (ssl_err != SSL_ERROR_ZERO_RETURN && ssl_err != SSL_ERROR_SYSCALL) { handle_openssl_error("AH SSL_read loop"); }
                            is_ah_registered = 0; break;
                        }
                        // Ignore unexpected data received from AH in this simple model
                        buffer[bytes_read] = '\0';
                        printf("[CTRL_MTLS_Thread %s] Rcvd %d bytes from AH (ignored): %.*s...\n", peer_ip, bytes_read, (bytes_read > 50 ? 50 : bytes_read), buffer);
                    } else if (ssl_err_peek == SSL_ERROR_ZERO_RETURN || peek_ret == 0) {
                        // Clean shutdown detected by peek or read returning 0 after select
                        printf("[CTRL_MTLS_Thread %s] AH connection closed cleanly by peer.\n", peer_ip);
                        is_ah_registered = 0; break;
                    } else if (ssl_err_peek == SSL_ERROR_WANT_READ || ssl_err_peek == SSL_ERROR_WANT_WRITE) {
                        // Select indicated readability, but SSL layer wasn't ready? Loop.
                        continue;
                    } else {
                        // Other SSL error detected by peek
                        fprintf(stderr, "[CTRL_MTLS_Thread %s] AH connection SSL error detected by peek (%d).\n", peer_ip, ssl_err_peek);
                        handle_openssl_error("AH SSL_peek loop");
                        is_ah_registered = 0; break;
                    }
                }
            } // end while monitoring AH

            // If loop exited because AH disconnected or error occurred
            if (!is_ah_registered) {
                 printf("[CTRL_MTLS_Thread %s] AH connection terminated or error occurred.\n", peer_ip);
                 // Removal from list happens in cleanup section
            }

        } else { // add_connected_ah failed
            fprintf(stderr, "[CTRL_MTLS_Thread %s] Failed add AH to connected list.\n", peer_ip);
            goto thread_cleanup_ctrl; // Close connection if registration fails
        }
        // AH thread stays alive in monitoring loop until disconnect or shutdown

    } else if (strncmp(buffer, "AUTH_REQ:", 9) == 0) {
        // --- Handle IH Authorization Request ---
        printf("[CTRL_MTLS_Thread %s] Identified as IH authorization request.\n", peer_ip);
        char target_ah_ip[INET_ADDRSTRLEN]={0}; uint8_t req_proto=0; uint16_t req_port=0; char req_svc_str[100]={0};

        // Parse the request string (simple example, make more robust if needed)
        char *current_pos = buffer + strlen("AUTH_REQ:"); char *next_field;
        while(current_pos && *current_pos!='\0' && *current_pos!='\n'){
            next_field=strchr(current_pos,':');
            char *key_part=current_pos;
            char *value_part=strchr(key_part,'=');
            if(value_part){
                 *value_part='\0'; value_part++;
                 char end_char='\0';
                 if(next_field){end_char=*next_field; *next_field='\0';} // Temporarily terminate value
                 key_part=trim_whitespace(key_part);
                 value_part=trim_whitespace(value_part);
                 if(key_part && value_part && *key_part!='\0' && *value_part!='\0'){
                     if(strcasecmp(key_part,"TARGET_IP")==0){strncpy(target_ah_ip,value_part,sizeof(target_ah_ip)-1);}
                     else if(strcasecmp(key_part,"SERVICE")==0){strncpy(req_svc_str,value_part,sizeof(req_svc_str)-1);}
                 }
                 if(next_field)*next_field=end_char; // Restore char
            } else { break; } // Malformed pair
            current_pos = next_field ? (next_field+1) : NULL;
        }
        // Parse service string
        if (strlen(req_svc_str) > 0) {
            char *proto_p=strtok(req_svc_str,"/"); char *port_p=strtok(NULL,"/");
            if(proto_p&&port_p){
                 req_proto=string_to_protocol(proto_p);
                 if(req_proto<=0)req_proto=atoi(proto_p);
                 if(strcasecmp(port_p,"any")==0)req_port=0; else req_port=atoi(port_p);
            }
        }

        // Validate parsed request components
        if (strlen(target_ah_ip) > 0 && req_proto > 0 /* && req_port > 0 -- Allow 0 for 'any' */) {
            printf("[CTRL_MTLS_Thread %s] Parsed AUTH_REQ: TargetAH=%s Service=%s/%u\n", peer_ip, target_ah_ip, protocol_to_string(req_proto), req_port);
            // Check policy
            if (check_policy(peer_ip, req_proto, req_port, target_ah_ip)) {
                printf("[CTRL_MTLS_Thread %s] Policy check PASSED. Generating ephemeral credentials...\n", peer_ip);
                char *ih_c=NULL,*ih_k=NULL,*ah_c=NULL,*ah_k=NULL;
                unsigned char enc[MAX_KEY_LEN],hmac[MAX_KEY_LEN],hotp[MAX_KEY_LEN];
                size_t el=32,hl=32,sl=20; // Standard lengths for AES256, SHA256, SHA1
                int ok=1;

                // Generate Credentials
                if (!generate_ephemeral_creds(peer_ip, &ih_c, &ih_k)) ok=0; // IH creds
                if (ok && !generate_ephemeral_creds(target_ah_ip, &ah_c, &ah_k)) ok=0; // AH creds
                if (ok && RAND_bytes(enc, el) <= 0) ok=0; // SPA Enc Key
                if (ok && RAND_bytes(hmac, hl) <= 0) ok=0; // SPA HMAC Key
                if (ok && RAND_bytes(hotp, sl) <= 0) ok=0; // HOTP Secret

                // *** Add NULL checks before proceeding ***
                if (ok && (!ih_c || !ih_k || !ah_c || !ah_k)) {
                     fprintf(stderr, "[CTRL_MTLS_Thread %s] Error: generate_ephemeral_creds reported success but returned NULL PEM!\n", peer_ip);
                     ok = 0;
                }

                if (ok) {
                    // Notify AH first
                    if (notify_ah_with_creds(target_ah_ip, peer_ip, req_proto, req_port,
                                             ih_c, ah_c, ah_k, // Pass PEM strings
                                             enc, el, hmac, hl, hotp, sl))
                    {
                        // AH notified, now send response to IH
                        printf("[CTRL_MTLS_Thread %s] AH notified. Sending credentials response to IH...\n", peer_ip);
                        char *resp = NULL;
                        char hex_enc[MAX_KEY_LEN*2+1], hex_hmac[MAX_KEY_LEN*2+1], hex_hotp[MAX_KEY_LEN*2+1];
                        // Convert SPA keys to hex for IH response
                        memset(hex_enc,0,sizeof(hex_enc)); memset(hex_hmac,0,sizeof(hex_hmac)); memset(hex_hotp,0,sizeof(hex_hotp));
                        for(size_t i=0; i<el; ++i) sprintf(hex_enc+i*2, "%02x", enc[i]);
                        for(size_t i=0; i<hl; ++i) sprintf(hex_hmac+i*2, "%02x", hmac[i]);
                        for(size_t i=0; i<sl; ++i) sprintf(hex_hotp+i*2, "%02x", hotp[i]);

                        uint16_t ah_listen_port = AH_MTLS_PORT_DEFAULT; // Port AH listens on for clients

                        // Construct IH response message
                         int resp_len = asprintf(&resp, "RESPONSE:ALLOWED\nAH_IP:%s\nAH_MTLS_PORT:%u\n"
                                         "EPH_SPA_ENC_KEY:%s\nEPH_SPA_HMAC_KEY:%s\nEPH_HOTP_SECRET:%s\n"
                                         "IH_EPH_CERT:%s\nIH_EPH_KEY:%s\nAH_EPH_CERT:%s\nEND_RESPONSE\n",
                                         target_ah_ip, ah_listen_port,
                                         hex_enc, hex_hmac, hex_hotp,
                                         ih_c, ih_k, ah_c); // Pass correct PEMs

                        if (resp_len > 0 && resp) {
                            if (send_data_over_mtls(ssl, resp) <= 0) {
                                fprintf(stderr, "[CTRL_MTLS_Thread %s] Failed to send credentials response to IH.\n", peer_ip);
                                // Error already logged by send_data_over_mtls
                            } else {
                                printf("[CTRL_MTLS_Thread %s] Credentials response sent to IH (%d bytes).\n", peer_ip, resp_len);
                            }
                            free(resp);
                        } else {
                            perror("[CTRL_MTLS_Thread %s] asprintf failed for IH response");
                            send_data_over_mtls(ssl, "RESPONSE:ERROR:Internal error (response generation)\n");
                        }
                    } else {
                        // Failed to notify AH
                        fprintf(stderr, "[CTRL_MTLS_Thread %s] Failed to notify AH %s.\n", peer_ip, target_ah_ip);
                        send_data_over_mtls(ssl, "RESPONSE:ERROR:Gateway notification failed\n");
                    }
                } else {
                    // Failed to generate credentials
                    fprintf(stderr, "[CTRL_MTLS_Thread %s] Failed to generate credentials.\n", peer_ip);
                    send_data_over_mtls(ssl, "RESPONSE:ERROR:Credential generation failed\n");
                }
                // Free generated PEM strings
                if(ih_c) free(ih_c); if(ih_k) free(ih_k); if(ah_c) free(ah_c); if(ah_k) free(ah_k);

            } else { // Policy check failed
                printf("[CTRL_MTLS_Thread %s] Policy check FAILED.\n", peer_ip);
                send_data_over_mtls(ssl, "RESPONSE:DENIED:Policy violation\n");
            }
        } else { // Failed to parse AUTH_REQ
            fprintf(stderr, "[CTRL_MTLS_Thread %s] Failed to parse AUTH_REQ.\n", peer_ip);
            send_data_over_mtls(ssl, "RESPONSE:DENIED:Bad request format\n");
        }
        // Close IH connection immediately after sending response/denial
        goto thread_cleanup_ctrl;

    } else {
        // Unknown initial message type
        fprintf(stderr, "[CTRL_MTLS_Thread %s] Unknown initial message type received.\n", peer_ip);
        goto thread_cleanup_ctrl; // Close unknown connections immediately
    }


thread_cleanup_ctrl:
    // If this thread was handling a registered AH connection that terminated
    if (is_ah_registered) {
        printf("[CTRL_MTLS_Thread %s] AH connection ended. Removing from active list.\n", peer_ip);
        remove_connected_ah(peer_ip); // Ensure removal from list
    }

    printf("[CTRL_MTLS_Thread %s] Shutting down handler thread.\n", peer_ip);
    if (ssl) {
        SSL_shutdown(ssl); // Attempt clean TLS shutdown
        SSL_free(ssl);     // Frees SSL structure and underlying socket FD
    }
    free(data); // Free the thread data structure passed via arg
    pthread_detach(pthread_self()); // Detach the thread (no need to join)
    return NULL;
}


// --- Main Listener Function ---
int run_controller_mtls_listener() {
    SSL_CTX *ctx = NULL;
    int sock = -1;
    struct sockaddr_in addr;

    ctx = create_controller_ssl_context();
    if (!ctx) return -1;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) { perror("Socket"); SSL_CTX_free(ctx); return -1; }
    int reuse = 1; setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(CONTROLLER_MTLS_PORT);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
         fprintf(stderr,"[CTRL_MTLS] Error binding listener port %d: %s\n", CONTROLLER_MTLS_PORT, strerror(errno));
         close(sock); SSL_CTX_free(ctx); return -1;
    }
    if (listen(sock, SOMAXCONN) < 0) { perror("Listen"); close(sock); SSL_CTX_free(ctx); return -1; }

    g_listen_sock_ctrl_mtls = sock;
    printf("[CTRL_MTLS] Server listening on port %d...\n", CONTROLLER_MTLS_PORT);

    while (!g_shutdown_flag_ctrl_mtls) {
        struct sockaddr_in peer_addr;
        socklen_t peer_len = sizeof(peer_addr);
        int client_sock = -1;
        SSL *ssl = NULL;

        // Use select for interruptible accept
        fd_set listen_fds; FD_ZERO(&listen_fds); FD_SET(g_listen_sock_ctrl_mtls, &listen_fds);
        struct timeval listen_timeout; listen_timeout.tv_sec = 1; listen_timeout.tv_usec = 0;

        int select_ret = select(g_listen_sock_ctrl_mtls + 1, &listen_fds, NULL, NULL, &listen_timeout);

        if (g_shutdown_flag_ctrl_mtls) break; // Check flag after select
        if (select_ret < 0) {
            if (errno == EINTR) continue; // Interrupted by signal
             if (errno == EBADF) break; // Socket closed by cleanup handler
            perror("Accept Select"); break; // Exit on other errors
        }
        if (select_ret == 0) continue; // Timeout

        // Accept connection if select indicated readiness
        client_sock = accept(g_listen_sock_ctrl_mtls, (struct sockaddr*)&peer_addr, &peer_len);

        if (g_shutdown_flag_ctrl_mtls) { if(client_sock>=0) close(client_sock); break; } // Check again after blocking accept
        if (client_sock < 0) {
             if (errno == EINTR || errno == EBADF || errno == EINVAL || errno == ECONNABORTED) continue; // Ignore transient or shutdown-related errors
            perror("Accept");
            continue;
        }

        char peer_ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &peer_addr.sin_addr, peer_ip_str, sizeof(peer_ip_str));
        printf("[CTRL_MTLS] Accepted connection from %s:%u (FD %d)\n", peer_ip_str, ntohs(peer_addr.sin_port), client_sock);

        // Create SSL object for the new connection
        ssl = SSL_new(ctx);
        if (!ssl) {
            fprintf(stderr, "[CTRL_MTLS] SSL_new failed for incoming connection.\n");
            handle_openssl_error("SSL_new accept");
            close(client_sock);
            continue;
        }
        // Associate SSL object with the client socket FD
        SSL_set_fd(ssl, client_sock);

        // Prepare data for the handler thread
        connection_thread_data_t *thread_data = malloc(sizeof(connection_thread_data_t));
        if (!thread_data) {
            perror("[CTRL_MTLS] malloc for thread data failed");
            SSL_free(ssl); // Frees underlying socket too
            continue;
        }
        thread_data->ssl = ssl;
        strcpy(thread_data->peer_ip, peer_ip_str);

        // Create and detach the handler thread
        pthread_t tid;
        if (pthread_create(&tid, NULL, handle_connection_thread_ctrl, (void*)thread_data) != 0) {
            perror("[CTRL_MTLS] pthread_create failed");
            free(thread_data);
            SSL_free(ssl); // Frees underlying socket
        } else {
            pthread_detach(tid); // No need to join handler threads
        }
    }

    printf("[CTRL_MTLS] Listener loop finished.\n");
    cleanup_controller_mtls_listener(); // Close listening socket
    SSL_CTX_free(ctx);                  // Free SSL context
    printf("[CTRL_MTLS] Listener fully shut down.\n");
    return 0;
}


// --- Cleanup Listener ---
void cleanup_controller_mtls_listener() {
    printf("[CTRL_MTLS] Cleaning up listener socket...\n");
    if (g_listen_sock_ctrl_mtls >= 0) {
        shutdown(g_listen_sock_ctrl_mtls, SHUT_RDWR); // Stop further connections
        close(g_listen_sock_ctrl_mtls);             // Close the socket
        g_listen_sock_ctrl_mtls = -1;               // Mark as closed
    }
}


// --- Main Function (For Standalone mTLS Listener Process) ---
void standalone_listener_cleanup_ctrl(int signo) {
    if (g_shutdown_flag_ctrl_mtls == 0) {
         printf("\n[CTRL_MTLS_MAIN] Signal %d caught, initiating shutdown...\n", signo);
         g_shutdown_flag_ctrl_mtls = 1;
         // Closing the listener socket here helps interrupt the accept loop/select
         cleanup_controller_mtls_listener();
    }
}

int main(int argc, char *argv[]) {
    (void)argc; (void)argv; // Unused parameters
    printf("[CTRL_MTLS_MAIN] Starting Controller mTLS Listener Process...\n");

    // Setup signal handlers for graceful shutdown
    signal(SIGINT, standalone_listener_cleanup_ctrl);
    signal(SIGTERM, standalone_listener_cleanup_ctrl);

    // Initialize OpenSSL
    initialize_openssl();

    // Initialize mutexes (should ideally be done once if multiple processes use them,
    // but PTHREAD_MUTEX_INITIALIZER is static)
    // pthread_mutex_init(&g_policy_lock, NULL); // Not needed if using static initializer
    // pthread_mutex_init(&g_ah_list_lock, NULL); // Not needed if using static initializer

    // Load policy configuration
    if (!load_policy_rules(POLICY_CONFIG_FILE)) {
        fprintf(stderr, "[CTRL_MTLS_MAIN] Warning: Failed to load policy rules from %s. Continuing...\n", POLICY_CONFIG_FILE);
        // Decide if this is fatal or not. Let's assume non-fatal for now.
    }

    // Start the main listener loop (this function blocks until shutdown)
    int ret = run_controller_mtls_listener();

    printf("[CTRL_MTLS_MAIN] Listener returned %d. Final cleanup...\n", ret);

    // Clean up global resources
    free_policy_rules(g_policy_rules); g_policy_rules = NULL; // Free policy list

    // TODO: Proper cleanup of connected AH list requires signaling handler threads
    // For simplicity now, we might leak ah_conn nodes if AHs are still connected on exit.
    // A robust solution involves iterating g_connected_ahs, signaling each thread, joining, etc.
    // Or just let the OS clean up on process exit.

    // Destroy mutexes
    pthread_mutex_destroy(&g_policy_lock);
    pthread_mutex_destroy(&g_ah_list_lock);

    // Cleanup OpenSSL library state
    cleanup_openssl();

    printf("[CTRL_MTLS_MAIN] Exiting.\n");
    return (ret == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}


