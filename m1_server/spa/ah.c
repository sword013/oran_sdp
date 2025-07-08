// ah.c - Accepting Host / Gateway Orchestrator (Complete - Self-Pipe Shutdown)
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
#include <time.h>
#include <sys/file.h> // For flock
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/select.h> // For select()
#include <fcntl.h>      // For fcntl with pipe

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "spa_common.h"
#include "ah_structs.h" // Include AH-specific structs

// --- Configuration ---
#define AH_ONBOARD_CONFIG "ah_onboard.conf"
#define AH_ACCESS_CONFIG "access_ah.conf" // File for ephemeral policies
#define AH_STATE_FILE "ah_state.dat"      // Store AH's counter state

// --- Structs ---
// Structure for AH's view of its onboarding credentials
typedef struct {
    char controller_ip[INET_ADDRSTRLEN];
    unsigned char enc_key[MAX_KEY_LEN]; size_t enc_key_len;
    unsigned char hmac_key[MAX_KEY_LEN]; size_t hmac_key_len;
    unsigned char hotp_secret[MAX_KEY_LEN]; size_t hotp_secret_len;
    char ca_cert_path[256]; char client_cert_path[256]; char client_key_path[256];
    int has_enc, has_hmac, has_hotp, has_ca, has_cert, has_key;
} ah_full_onboard_config_t;

// Structure for AH's persistent state (HOTP counter for Controller)
typedef struct {
     uint64_t controller_hotp_counter;
} ah_state_t;

// --- Globals DEFINITIONS (for ah_app executable) ---
ephemeral_policy_t *g_ephemeral_policies = NULL; // This list is primarily managed by spa_srv_ah
pthread_mutex_t g_eph_policy_lock = PTHREAD_MUTEX_INITIALIZER;
SSL_CTX *g_controller_ssl_ctx = NULL;
SSL *g_controller_ssl_conn = NULL;
pthread_mutex_t g_ctrl_conn_lock = PTHREAD_MUTEX_INITIALIZER;
volatile sig_atomic_t g_main_shutdown_flag = 0;
ah_full_onboard_config_t g_ah_onboard_conf; // Defined globally here
ah_state_t g_ah_state;                      // Defined globally here
pthread_t g_listener_tid = 0;
int g_shutdown_pipe_fds[2] = {-1, -1};

// --- Function Prototypes ---
void ah_main_cleanup(int signo);
int load_ah_full_onboard_config(const char* filename, ah_full_onboard_config_t *conf);
int load_ah_state(const char* filename, ah_state_t *state);
int save_ah_state(const char* filename, const ah_state_t *state);
int connect_to_controller(ah_full_onboard_config_t *conf);
void* controller_listener_thread(void *arg);
int update_ephemeral_policy_file(const char* filename, const char* ih_ip, uint8_t proto, uint16_t port,
                                const char* enc_hex, const char* hmac_hex, const char* hotp_hex,
                                time_t expiry);
pid_t find_process_pid(const char* process_name_fragment); // For signalling reload
// Assumed external from spa_common.c: create_ssl_context, configure_ssl_context, etc.


// --- Implementations ---

// Configuration Loading
int load_ah_full_onboard_config(const char* filename, ah_full_onboard_config_t *conf) {
    FILE *fp = fopen(filename, "r"); if (!fp) { perror("[AH_MAIN] Error opening AH onboard config"); return 0; } printf("[AH_MAIN] Loading AH onboard: %s\n", filename); memset(conf, 0, sizeof(ah_full_onboard_config_t)); char line[1024]; int ln=0, in_s=0;
    while(fgets(line,sizeof(line),fp)){ ln++; char*t=trim_whitespace(line); if(!t||t[0]=='\0'||t[0]=='#')continue; if(t[0]=='['&&t[strlen(t)-1]==']'){ size_t il=strlen(t)-2; if(il>0&&il<INET_ADDRSTRLEN){strncpy(conf->controller_ip,t+1,il);conf->controller_ip[il]='\0';struct sockaddr_in sa;if(inet_pton(AF_INET,conf->controller_ip,&sa.sin_addr)!=1){fclose(fp);return 0;}in_s=1;printf(" Ctrl IP: %s\n",conf->controller_ip);}else{fclose(fp);return 0;}} else if(in_s){char*k=t,*v=NULL;for(char*p=k;*p!='\0';++p){if(isspace((unsigned char)*p)||*p=='='){*p='\0';v=p+1;while(*v!='\0'&&(isspace((unsigned char)*v)||*v=='=')){v++;}break;}} if(v&&*v!='\0'){k=trim_whitespace(k);char*c=strchr(v,'#');if(c)*c='\0';v=trim_whitespace(v);if(strlen(k)==0||strlen(v)==0)continue; if(strcasecmp(k,"ENCRYPTION_KEY")==0){int l=hex_string_to_bytes(v,conf->enc_key,MAX_KEY_LEN);if(l>0){conf->enc_key_len=l;conf->has_enc=1;}else{fclose(fp);return 0;}} else if(strcasecmp(k,"HMAC_KEY")==0){int l=hex_string_to_bytes(v,conf->hmac_key,MAX_KEY_LEN);if(l>0){conf->hmac_key_len=l;conf->has_hmac=1;}else{fclose(fp);return 0;}} else if(strcasecmp(k,"HOTP_SECRET")==0){int l=hex_string_to_bytes(v,conf->hotp_secret,MAX_KEY_LEN);if(l>0){conf->hotp_secret_len=l;conf->has_hotp=1;}else{fclose(fp);return 0;}} else if(strcasecmp(k,"CA_CERT_PATH")==0){strncpy(conf->ca_cert_path,v,sizeof(conf->ca_cert_path)-1);conf->has_ca=1;} else if(strcasecmp(k,"CLIENT_CERT_PATH")==0){strncpy(conf->client_cert_path,v,sizeof(conf->client_cert_path)-1);conf->has_cert=1;} else if(strcasecmp(k,"CLIENT_KEY_PATH")==0){strncpy(conf->client_key_path,v,sizeof(conf->client_key_path)-1);conf->has_key=1;} else {fprintf(stderr,"Warn: Unknown key %s L%d\n",k,ln);}}}}
    fclose(fp); if(!conf->has_enc||!conf->has_hmac||!conf->has_hotp||!conf->has_ca||!conf->has_cert||!conf->has_key||strlen(conf->controller_ip)==0){fprintf(stderr,"Missing fields in %s\n",filename);return 0;} printf("AH Onboard loaded OK.\n"); return 1;
}

// State Load/Save
int load_ah_state(const char* fn, ah_state_t *s){ FILE *fp=fopen(fn,"rb"); if(!fp){s->controller_hotp_counter=0;return 1;} if(fread(s,sizeof(ah_state_t),1,fp)!=1){fclose(fp);s->controller_hotp_counter=0;return 0;} fclose(fp);printf("Loaded AH state Ctr=%llu\n",(unsigned long long)s->controller_hotp_counter);return 1;}
int save_ah_state(const char* fn, const ah_state_t *s){ FILE *fp=fopen(fn,"wb"); if(!fp){perror("save AH state");return 0;} if(fwrite(s,sizeof(ah_state_t),1,fp)!=1){perror("write AH state");fclose(fp);return 0;} fclose(fp);printf("Saved AH state Ctr=%llu\n",(unsigned long long)s->controller_hotp_counter);return 1;}

// Helper to find PID
pid_t find_process_pid(const char* process_name_fragment) {
    char cmd[256]; snprintf(cmd, sizeof(cmd), "pgrep -f -o %s", process_name_fragment); FILE *fp = popen(cmd, "r"); if (!fp) return -1; char pid_str[32]; pid_t pid = -1; if (fgets(pid_str, sizeof(pid_str), fp) != NULL) { pid = atoi(pid_str); } pclose(fp); return (pid > 0) ? pid : -1;
}

// Update Ephemeral Policy File & Signal
int update_ephemeral_policy_file(const char* filename, const char* ih_ip, uint8_t proto, uint16_t port, const char* enc_hex, const char* hmac_hex, const char* hotp_hex, time_t expiry) {
    printf("[AH_MAIN] Appending policy file %s for IH %s\n", filename, ih_ip);
    // --- TODO: Implement robust read-modify-write ---
    FILE* fp = fopen(filename, "a"); if (!fp) { perror("eph policy open"); return 0; } if (flock(fileno(fp), LOCK_EX) == -1) { perror("eph policy lock"); fclose(fp); return 0; }
    fprintf(fp, "\n[%s]\n  ENCRYPTION_KEY %s\n  HMAC_KEY %s\n  HOTP_SECRET %s\n  HOTP_NEXT_COUNTER 0\n  ALLOWED_PROTO %u\n  ALLOWED_PORT %u\n  EXPIRY_TIMESTAMP %lu\n", ih_ip, enc_hex, hmac_hex, hotp_hex, proto, port, (unsigned long)expiry);
    fflush(fp); flock(fileno(fp), LOCK_UN); fclose(fp); printf(" Policy appended.\n");
    // Signal spa_server_ah to reload
    pid_t spa_pid = find_process_pid("spa_srv_ah"); // Match executable name
    if (spa_pid > 0) { printf(" Sending SIGHUP to spa_srv_ah (PID %d)\n", spa_pid); if (kill(spa_pid, SIGHUP) == -1) { perror("Failed send SIGHUP"); }} else { fprintf(stderr, " Warn: Could not find spa_srv_ah PID\n"); }
    return 1;
}

// Connect to Controller (Uses integrated send_spa_packet)
int connect_to_controller(ah_full_onboard_config_t *conf) {
    printf("[AH_MAIN] Attempting connect sequence to Controller %s...\n", conf->controller_ip);
    g_ah_state.controller_hotp_counter++; printf(" Sending SPA knock (Ctr:%llu)...\n",(unsigned long long)g_ah_state.controller_hotp_counter);
    int spa_ret = send_spa_packet( conf->controller_ip, SPA_LISTENER_PORT, conf->enc_key, conf->hmac_key, conf->hmac_key_len, conf->hotp_secret, conf->hotp_secret_len, g_ah_state.controller_hotp_counter, 0, 0);
    if (spa_ret != 0) { fprintf(stderr, " Failed SPA send (%d).\n", spa_ret); g_ah_state.controller_hotp_counter--; return 0; }
    if (!save_ah_state(AH_STATE_FILE, &g_ah_state)) { fprintf(stderr, " Warn: Failed save state.\n"); } sleep(0.1);
    printf(" Attempting mTLS to %s:%d...\n", conf->controller_ip, CONTROLLER_MTLS_PORT);
    pthread_mutex_lock(&g_ctrl_conn_lock);
    if (!g_controller_ssl_ctx) { g_controller_ssl_ctx=create_ssl_context(0); if (!g_controller_ssl_ctx || !configure_ssl_context(g_controller_ssl_ctx, conf->ca_cert_path, conf->client_cert_path, conf->client_key_path, 0)) { if(g_controller_ssl_ctx)SSL_CTX_free(g_controller_ssl_ctx); g_controller_ssl_ctx=NULL; pthread_mutex_unlock(&g_ctrl_conn_lock); return 0; } }
    if (g_controller_ssl_conn) { SSL_shutdown(g_controller_ssl_conn); SSL_free(g_controller_ssl_conn); g_controller_ssl_conn = NULL; }
    g_controller_ssl_conn = establish_mtls_connection(conf->controller_ip, CONTROLLER_MTLS_PORT, g_controller_ssl_ctx);
    if (g_controller_ssl_conn) { printf(" mTLS OK.\n"); if(send_data_over_mtls(g_controller_ssl_conn,"AH_REGISTER\n") <= 0){ fprintf(stderr,"Failed send AH_REGISTER\n"); SSL_shutdown(g_controller_ssl_conn); SSL_free(g_controller_ssl_conn); g_controller_ssl_conn=NULL; pthread_mutex_unlock(&g_ctrl_conn_lock); return 0;} pthread_mutex_unlock(&g_ctrl_conn_lock); return 1;}
    else { fprintf(stderr," Failed mTLS connect.\n"); pthread_mutex_unlock(&g_ctrl_conn_lock); return 0; }
}

// Controller Listener Thread (Uses select for shutdown)
void* controller_listener_thread(void *arg) {
    (void)arg; char buffer[4096]; int bytes_read; int reconnect_delay = 5; SSL *conn = NULL;
    printf("[AH_CTRL_Listen] Thread started.\n");
    while (!g_main_shutdown_flag) {
        pthread_mutex_lock(&g_ctrl_conn_lock); conn = g_controller_ssl_conn; pthread_mutex_unlock(&g_ctrl_conn_lock);
        if (!conn) { if(g_main_shutdown_flag) break; printf("No ctrl conn. Retrying in %ds...\n", reconnect_delay); sleep(reconnect_delay); if(g_main_shutdown_flag) break; connect_to_controller(&g_ah_onboard_conf); continue; }
        int ssl_fd = SSL_get_fd(conn); if (ssl_fd < 0) { goto handle_disconnect_ah_listen_pipe; }
        fd_set read_fds; FD_ZERO(&read_fds); FD_SET(ssl_fd, &read_fds); FD_SET(g_shutdown_pipe_fds[0], &read_fds); int max_fd = (ssl_fd > g_shutdown_pipe_fds[0]) ? ssl_fd : g_shutdown_pipe_fds[0];
        int activity = select(max_fd + 1, &read_fds, NULL, NULL, NULL);
        if (g_main_shutdown_flag) { printf("Shutdown detected post-select.\n"); break; }
        if (activity < 0) { if (errno == EINTR) continue; perror("select ctrl"); goto handle_disconnect_ah_listen_pipe; }
        if (FD_ISSET(g_shutdown_pipe_fds[0], &read_fds)) { char dummy; read(g_shutdown_pipe_fds[0], &dummy, 1); printf("Shutdown pipe signaled.\n"); break; }
        if (FD_ISSET(ssl_fd, &read_fds)) {
             bytes_read = SSL_read(conn, buffer, sizeof(buffer) - 1); if (g_main_shutdown_flag) break;
             if (bytes_read <= 0) { int err = SSL_get_error(conn,bytes_read); fprintf(stderr,"SSL_read ctrl fail/closed (%d)\n",err); if(err!=SSL_ERROR_ZERO_RETURN&&err!=SSL_ERROR_SYSCALL)handle_openssl_error("AH SSL_read");
handle_disconnect_ah_listen_pipe: pthread_mutex_lock(&g_ctrl_conn_lock); if(g_controller_ssl_conn==conn){SSL_shutdown(g_controller_ssl_conn);SSL_free(g_controller_ssl_conn);g_controller_ssl_conn=NULL;printf("Cleaned ctrl conn.\n");} pthread_mutex_unlock(&g_ctrl_conn_lock); continue; }
             buffer[bytes_read]='\0'; printf("Rcvd %d bytes:\n%s",bytes_read,buffer);
             if (strncmp(buffer, "NEW_SESSION", 11) == 0) { /*...Parse/update...*/ char ih_ip[INET_ADDRSTRLEN]={0};uint8_t p=0;uint16_t po=0; char e[MAX_KEY_LEN*2+1]={0},h[MAX_KEY_LEN*2+1]={0},o[MAX_KEY_LEN*2+1]={0}; char* line = strtok(buffer, "\n"); while(line) { char *k=line, *v=strchr(line,':'); if(v){*v='\0';v++;k=trim_whitespace(k);v=trim_whitespace(v); if(k&&v){ if(!strcasecmp(k,"IH_IP"))strncpy(ih_ip,v,sizeof(ih_ip)-1); else if(!strcasecmp(k,"SERVICE_PROTO"))p=atoi(v); else if(!strcasecmp(k,"SERVICE_PORT"))po=atoi(v); else if(!strcasecmp(k,"SPA_ENC_KEY"))strncpy(e,v,sizeof(e)-1); else if(!strcasecmp(k,"SPA_HMAC_KEY"))strncpy(h,v,sizeof(h)-1); else if(!strcasecmp(k,"HOTP_SECRET"))strncpy(o,v,sizeof(o)-1); /* TODO: Parse/Save Certs */} } line = strtok(NULL, "\n"); } if(strlen(ih_ip)>0 && p > 0 && strlen(e)>0 && strlen(h)>0 && strlen(o)>0){ time_t ex=time(NULL)+SPA_DEFAULT_DURATION_SECONDS+10; update_ephemeral_policy_file(AH_ACCESS_CONFIG, ih_ip, p, po, e, h, o, ex);} else {fprintf(stderr, "Failed parse NEW_SESSION\n");}} else { printf("Unknown msg\n"); }
        }
    }
    printf("[AH_CTRL_Listen] Thread exiting cleanly.\n"); return NULL;
}

// --- Signal Handler ---
void ah_main_cleanup(int signo) {
    if (g_main_shutdown_flag == 0) { g_main_shutdown_flag = 1; printf("\n[AH_MAIN] Signal %d, setting flag & writing pipe...\n", signo); if (g_shutdown_pipe_fds[1] != -1) { char d='X'; write(g_shutdown_pipe_fds[1],&d,1); } } signal(signo, SIG_DFL); // Prevent potential infinite loop on error
}

// --- Main AH Function ---
int main(int argc, char *argv[]) {
    pthread_t listener_tid = 0; int main_ret = EXIT_FAILURE; (void)argc; (void)argv;
    if (pipe(g_shutdown_pipe_fds) == -1) { perror("pipe"); return EXIT_FAILURE; }
    signal(SIGINT, ah_main_cleanup); signal(SIGTERM, ah_main_cleanup);
    printf("[AH_MAIN] Starting AH Orchestrator...\n"); initialize_openssl();
    if (!load_ah_full_onboard_config(AH_ONBOARD_CONFIG, &g_ah_onboard_conf)) goto main_exit; if (!load_ah_state(AH_STATE_FILE, &g_ah_state)) goto main_exit;
    printf("[AH_MAIN] NOTE: Start other AH listeners separately.\n");
    if (connect_to_controller(&g_ah_onboard_conf)) { if (pthread_create(&listener_tid, NULL, controller_listener_thread, NULL) != 0) { perror("pthread create"); listener_tid=0; /* cleanup SSL */} else { g_listener_tid = listener_tid; printf("Ctrl listener thread started (%lu).\n",(unsigned long)listener_tid);}} else {fprintf(stderr, "Initial controller connection failed.\n");}
    printf("[AH_MAIN] Running. Waiting for signal...\n"); while (!g_main_shutdown_flag) { pause(); } main_ret = EXIT_SUCCESS;
main_exit:
    printf("[AH_MAIN] Shutdown initiated or startup failed.\n"); if (listener_tid != 0) { printf("Waiting for listener thread...\n"); pthread_join(listener_tid, NULL); printf("Joined.\n"); }
    pthread_mutex_lock(&g_ctrl_conn_lock); if (g_controller_ssl_conn) { printf("Closing controller conn...\n"); SSL_shutdown(g_controller_ssl_conn); SSL_free(g_controller_ssl_conn); g_controller_ssl_conn = NULL; } if (g_controller_ssl_ctx) { printf("Freeing controller SSL ctx...\n"); SSL_CTX_free(g_controller_ssl_ctx); g_controller_ssl_ctx = NULL; } pthread_mutex_unlock(&g_ctrl_conn_lock);
    pthread_mutex_destroy(&g_eph_policy_lock); pthread_mutex_destroy(&g_ctrl_conn_lock);
    if (g_shutdown_pipe_fds[0] != -1) close(g_shutdown_pipe_fds[0]); if (g_shutdown_pipe_fds[1] != -1) close(g_shutdown_pipe_fds[1]);
    cleanup_openssl(); printf("[AH_MAIN] Finished.\n"); return main_ret;
}