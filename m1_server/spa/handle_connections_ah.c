// handle_connections_ah.c (AH / Gateway mTLS Listener & Proxy - FINAL CORRECTED SELECT)
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
#include <poll.h>       // Include for poll() and related constants/structs
#include <signal.h>
#include <sys/select.h> // Include for select() in listener loop
#include <sys/stat.h>
#include <time.h>
#include <fcntl.h>      // Include for access()

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>

#include "spa_common.h" // Include spa_common.h first
#include "ah_structs.h" // Include AH-specific structs

// --- Assumed External Functions ---
// Defined in spa_server_ah.c (Requires linking spa_server_ah.o)
extern ephemeral_policy_t* find_ephemeral_policy(const char *ip_str);
// Defined in spa_common.c
extern void handle_openssl_error(const char *msg);
extern const char* protocol_to_string(int proto);
extern SSL_CTX* create_ssl_context(int is_server);
extern int configure_ssl_context(SSL_CTX *ctx, const char* ca_path, const char* cert_path, const char* key_path, int is_server);
extern void initialize_openssl();
extern void cleanup_openssl();
extern int open_tcp_listener(int port);
extern void show_peer_certificates(SSL* ssl);

// --- Configuration ---
#define AH_BACKEND_SERVICE_IP "127.0.0.1"
#define CA_CERT_PATH "controller_ca.crt"
// FIXME: Placeholder paths - need proper dynamic mechanism from ah.c/controller
#define AH_EPH_CERT_PATH_TMPL "/tmp/ah_eph.crt"
#define AH_EPH_KEY_PATH_TMPL  "/tmp/ah_eph.key"

// --- Forward Declarations ---
void* handle_ah_connection_thread(void *arg);
SSL_CTX* create_ah_ssl_context(const char* ah_eph_cert_path, const char* ah_eph_key_path);
void cleanup_ah_listener();
int connect_to_backend(const char* backend_ip, uint16_t backend_port, uint8_t protocol);
int relay_data(int backend_sock, SSL* ssl_conn);
void standalone_ah_listener_cleanup(int signo);

// --- Global for Listener Socket ---
int g_ah_listen_sock = -1;
volatile sig_atomic_t g_ah_shutdown_flag = 0;
// Global defined in spa_server_ah.c, declared extern here
extern pthread_mutex_t g_eph_policy_lock;


// --- SSL Context Setup (Using Ephemeral Credentials) ---
SSL_CTX* create_ah_ssl_context(const char* ah_eph_cert_path, const char* ah_eph_key_path) {
    SSL_CTX *ctx;
    if (access(ah_eph_cert_path, F_OK) != 0 || access(ah_eph_key_path, F_OK) != 0) { fprintf(stderr, "[AH_MTLS] Ephemeral cert/key missing (%s, %s).\n", ah_eph_cert_path, ah_eph_key_path); return NULL; }
    ctx = create_ssl_context(1); if (!ctx) return NULL;
    if (!configure_ssl_context(ctx, CA_CERT_PATH, ah_eph_cert_path, ah_eph_key_path, 1)) { SSL_CTX_free(ctx); return NULL; }
    printf("[AH_MTLS] Ephemeral SSL Context configured using %s / %s.\n", ah_eph_cert_path, ah_eph_key_path); return ctx;
}

// --- Backend Connection ---
int connect_to_backend(const char* backend_ip, uint16_t backend_port, uint8_t protocol) {
    int sock = -1; struct sockaddr_in backend_addr; int sock_type = -1; int ip_proto = protocol;
    printf("[AH_Backend] Connecting to %s:%u (Proto:%u)\n", backend_ip, backend_port, protocol);
    if (protocol == IPPROTO_TCP) { sock_type = SOCK_STREAM; } else if (protocol == IPPROTO_UDP) { sock_type = SOCK_DGRAM; } else if (protocol == 132) { ip_proto = IPPROTO_SCTP; #ifdef SOCK_SEQPACKET sock_type = SOCK_SEQPACKET; printf("[AH_Backend] Using SOCK_SEQPACKET for SCTP.\n"); #else sock_type = SOCK_STREAM; printf("[AH_Backend] Warning: SOCK_STREAM fallback for SCTP.\n"); #endif } else { fprintf(stderr, "[AH_Backend] Unsupported proto %u\n", protocol); return -1; }
    sock = socket(AF_INET, sock_type, ip_proto); if (sock < 0) { perror("[AH_Backend] Socket create"); return -1; }
    memset(&backend_addr, 0, sizeof(backend_addr)); backend_addr.sin_family = AF_INET; backend_addr.sin_port = htons(backend_port); if (inet_pton(AF_INET, backend_ip, &backend_addr.sin_addr) <= 0) { fprintf(stderr, "[AH_Backend] Invalid backend IP %s\n", backend_ip); close(sock); return -1; }
    if (sock_type != SOCK_DGRAM) { if (connect(sock, (struct sockaddr*)&backend_addr, sizeof(backend_addr)) < 0) { fprintf(stderr, "[AH_Backend] Failed connect to %s:%u - %s\n", backend_ip, backend_port, strerror(errno)); close(sock); return -1; } } else { if (connect(sock, (struct sockaddr*)&backend_addr, sizeof(backend_addr)) < 0) { fprintf(stderr, "[AH_Backend] Failed UDP connect() to %s:%u - %s\n", backend_ip, backend_port, strerror(errno)); close(sock); return -1; } printf("[AH_Backend] UDP dest set.\n");}
    printf("[AH_Backend] Connected OK (FD %d).\n", sock); return sock;
}

// --- Data Relay Function (Uses poll) ---
int relay_data(int backend_sock, SSL* ssl_conn) {
    struct pollfd fds[2]; char b[8192]; int run=1, ret; int ssl_fd=SSL_get_fd(ssl_conn); if(ssl_fd < 0){ fprintf(stderr, "Invalid SSL FD in relay\n"); return -1; } fds[0].fd=backend_sock; fds[0].events=POLLIN; fds[1].fd=ssl_fd; fds[1].events=POLLIN; printf("[AH_Relay] Start relay backend=%d ssl=%d...\n", backend_sock, ssl_fd);
    while(run && !g_ah_shutdown_flag){ fds[0].revents=0; fds[1].revents=0; ret=poll(fds, 2, 2000); if (g_ah_shutdown_flag) break; if (ret<0){ if(errno==EINTR) continue; perror("poll"); run=0; break; } if (ret==0) continue;
    if (fds[0].revents & (POLLIN|POLLERR|POLLHUP)){ ssize_t br=recv(backend_sock,b,sizeof(b),0); if(br<=0){ if(br<0)perror("recv backend"); else printf("[AH_Relay] Backend closed.\n"); run=0; SSL_shutdown(ssl_conn); } else { int bw=SSL_write(ssl_conn,b,br); if(bw<=0){fprintf(stderr,"[AH_Relay] SSL_write err:%d\n",SSL_get_error(ssl_conn,bw)); run=0; shutdown(backend_sock,SHUT_RD);} } }
    if (fds[1].revents & (POLLIN|POLLERR|POLLHUP)){ ssize_t br=SSL_read(ssl_conn,b,sizeof(b)); if(br<=0){ int err=SSL_get_error(ssl_conn,br); if(err==SSL_ERROR_ZERO_RETURN || err==SSL_ERROR_SYSCALL){ printf("[AH_Relay] IH closed(%d)\n",err); } else { fprintf(stderr,"[AH_Relay] SSL_read err %d\n",err); handle_openssl_error("Relay SSL_read");} run=0; shutdown(backend_sock,SHUT_WR);} else { ssize_t bw=send(backend_sock,b,br,0); if(bw<0){perror("send backend");run=0;} else if(bw<br){fprintf(stderr,"[AH_Relay] Partial send backend\n");run=0;} } } }
    printf("[AH_Relay] Finished.\n"); return (errno == 0) ? 0 : -1;
}

// --- Connection Handling Thread ---
void* handle_ah_connection_thread(void *arg) {
     ah_thread_data_t *data = (ah_thread_data_t*)arg; SSL *ssl = data->ssl; char peer_ip[INET_ADDRSTRLEN]; strcpy(peer_ip, data->peer_ip); int backend_sock = -1;
     printf("[AH_MTLS_Thread %s] Handling eph conn...\n", peer_ip); printf(" Target: %s:%u (Proto %u)\n", data->target_service_ip, data->target_service_port, data->target_service_proto);
     backend_sock = connect_to_backend(data->target_service_ip, data->target_service_port, data->target_service_proto); if (backend_sock < 0) { goto ah_thread_cleanup; }
     relay_data(backend_sock, ssl);
 ah_thread_cleanup:
     printf("[AH_MTLS_Thread %s] Shutting down.\n", peer_ip); if (backend_sock >= 0) close(backend_sock); if (ssl) { SSL_shutdown(ssl); SSL_free(ssl); } free(data); pthread_detach(pthread_self()); return NULL;
}

// --- Main Listener Function (AH mTLS) ---
int run_ah_mtls_listener(uint16_t listen_port) {
    SSL_CTX *ctx = NULL; int sock = -1;
    char ah_eph_cert_path[256]; char ah_eph_key_path[256]; snprintf(ah_eph_cert_path, sizeof(ah_eph_cert_path), AH_EPH_CERT_PATH_TMPL); snprintf(ah_eph_key_path, sizeof(ah_eph_key_path), AH_EPH_KEY_PATH_TMPL);

    ctx = create_ah_ssl_context(ah_eph_cert_path, ah_eph_key_path); if (!ctx) { fprintf(stderr, "[AH_MTLS] Cannot start without SSL Context.\n"); return -1; }
    sock = open_tcp_listener(listen_port); if (sock < 0) { SSL_CTX_free(ctx); return -1; }
    g_ah_listen_sock = sock; printf("[AH_MTLS] Ephemeral listener started on port %u...\n", listen_port);

    // --- Accept Loop using select ---
    fd_set listen_fds;
    struct timeval ltv; // Declare timeval structure OUTSIDE loop

    while (!g_ah_shutdown_flag) {
        struct sockaddr_in peer_addr; socklen_t peer_len = sizeof(peer_addr); int client_sock = -1; SSL *ssl = NULL;

        FD_ZERO(&listen_fds);
        if (g_ah_listen_sock < 0) { printf("[AH_MTLS] Listener socket closed, exiting loop.\n"); break; }
        FD_SET(g_ah_listen_sock, &listen_fds);

        // Set timeout each time before select
        ltv.tv_sec = 1;
        ltv.tv_usec = 0;

        // *** THE CORRECT select() CALL ***
        int sret = select(g_ah_listen_sock + 1, &listen_fds, NULL, NULL, TLS1_2_VERSION);
        // *** END OF CORRECT select() CALL ***

        if (g_ah_shutdown_flag) break;
        if (sret < 0) { if (errno == EINTR) continue; perror("Accept Select"); break; }
        if (sret == 0) continue; // Timeout

        if (FD_ISSET(g_ah_listen_sock, &listen_fds)) {
            client_sock = accept(g_ah_listen_sock, (struct sockaddr*)&peer_addr, &peer_len);
            if (g_ah_shutdown_flag) { if(client_sock>=0) close(client_sock); break; }
            if (client_sock < 0) { if (errno == EINTR || errno == EBADF || errno == EINVAL) break; perror("Accept"); continue; }

            char peer_ip_str[INET_ADDRSTRLEN]; inet_ntop(AF_INET, &peer_addr.sin_addr, peer_ip_str, sizeof(peer_ip_str));
            printf("Accepted eph conn from %s:%u\n", peer_ip_str, ntohs(peer_addr.sin_port));

            ephemeral_policy_t *policy = find_ephemeral_policy(peer_ip_str); // find locks/unlocks
            if (!policy) { fprintf(stderr, "Reject %s: No policy.\n", peer_ip_str); close(client_sock); continue; }
            printf(" Policy OK.\n");
            uint8_t target_proto = policy->allowed_proto; uint16_t target_port = policy->allowed_port;
            pthread_mutex_unlock(&g_eph_policy_lock); // Unlock policy list

            ssl = SSL_new(ctx); if (!ssl) { fprintf(stderr,"SSL_new fail\n"); close(client_sock); continue; }
            SSL_set_fd(ssl, client_sock);
            int accept_ret = SSL_accept(ssl);
            if (accept_ret <= 0) { fprintf(stderr, "SSL_accept failed for %s [%d]\n", peer_ip_str, SSL_get_error(ssl, accept_ret)); handle_openssl_error("SSL_accept AH"); SSL_free(ssl); }
            else {
                 printf(" Eph Handshake OK with %s. Ver: %s\n", peer_ip_str, SSL_get_version(ssl));
                 X509*c=SSL_get_peer_certificate(ssl); int cok=0; if(c){char cn[256]={0};if(X509_NAME_get_text_by_NID(X509_get_subject_name(c),NID_commonName,cn,sizeof(cn)-1)>0&&strcmp(cn,peer_ip_str)==0){cok=1;}X509_free(c);} if(!cok){fprintf(stderr,"Reject Eph: CN bad (%s)\n",peer_ip_str);SSL_shutdown(ssl);SSL_free(ssl);continue;} printf(" Eph Peer CN OK.\n");
                 ah_thread_data_t *td=malloc(sizeof(ah_thread_data_t)); if(!td){perror("malloc"); SSL_shutdown(ssl);SSL_free(ssl);continue;}
                 td->ssl=ssl;strcpy(td->peer_ip,peer_ip_str);td->target_service_proto=target_proto;td->target_service_port=target_port;strncpy(td->target_service_ip,AH_BACKEND_SERVICE_IP,sizeof(td->target_service_ip)-1); td->target_service_ip[sizeof(td->target_service_ip)-1] = '\0';
                 pthread_t tid; if(pthread_create(&tid,NULL,handle_ah_connection_thread,(void*)td)!=0){perror("pthread");free(td);SSL_shutdown(ssl);SSL_free(ssl);}
                 // Detach happens in thread
            }
        }
    } // End Accept Loop

    printf("[AH_MTLS] Listener loop finished.\n");
    cleanup_ah_listener(); // Close listener socket
    SSL_CTX_free(ctx);     // Free SSL context
    printf("[AH_MTLS] Listener shutdown complete.\n");
    return 0;
}

// --- Cleanup Listener ---
void cleanup_ah_listener() {
    printf("[AH_MTLS] Cleaning up listener...\n");
    // g_ah_shutdown_flag=1; // Set flag just in case
    if(g_ah_listen_sock>=0){
        shutdown(g_ah_listen_sock, SHUT_RDWR); // Stop reads/writes
        close(g_ah_listen_sock);
        g_ah_listen_sock=-1;
    }
}

// --- Standalone Main Function ---
void standalone_ah_listener_cleanup(int signo){
    printf("\nAH_MTLS Signal %d, setting shutdown flag...\n",signo);
    g_ah_shutdown_flag=1;
    // Don't call cleanup_ah_listener directly from handler
}
int main(int argc,char*argv[]){
    (void)argc;(void)argv;
    printf("Starting AH Eph mTLS Listener...\n");
    signal(SIGINT,standalone_ah_listener_cleanup); signal(SIGTERM,standalone_ah_listener_cleanup);
    initialize_openssl();
    uint16_t port=AH_MTLS_PORT_DEFAULT;
    printf("WARNING: Using default port %u & placeholder cert paths (%s, %s)\n", port, AH_EPH_CERT_PATH_TMPL, AH_EPH_KEY_PATH_TMPL);
    int ret=run_ah_mtls_listener(port);
    printf("Listener return %d. Cleanup.\n",ret);
    cleanup_openssl();
    printf("Exiting.\n");
    return ret==0?EXIT_SUCCESS:EXIT_FAILURE;
}