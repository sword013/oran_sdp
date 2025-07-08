// ah.c - Accepting Host (Server) Orchestrator (TUN/TAP Version - Route Test)
#define _GNU_SOURCE // For asprintf
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <time.h>
#include <poll.h>   	// For relay loop
#include <fcntl.h>  	// For file flags
#include <pcap.h>   	// For SPA Listener
#include <netinet/ip.h> // For IP header
#include <netinet/udp.h> // For UDP header
#include <ctype.h>       // For isspace
#include <stdarg.h>      // For va_list etc.
#include <endian.h>      // For htobe64 etc.

// --- Includes needed for TUN/TAP ---
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h> // Include for ioctl needed by tun_alloc
// ----------------------------------

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/rand.h>

#include "spa_common.h" // Needs latest version with TUN prototype
#include "ah_structs.h" // Contains policy structures etc.

// --- Configuration & State Files ---
#define AH_STATE_FILE "ah_state.dat"
#define AH_ONBOARD_CONFIG "ah_onboard.conf"
#define EPH_CERT_DIR "/tmp/ah_eph_certs"

// --- Default Service Info ---
#define SESSION_POLICY_TIMEOUT_SECONDS (SPA_DEFAULT_DURATION_SECONDS * 2)
#define CLEANUP_INTERVAL_SECONDS 10

// --- TUNNEL Configuration ---
#define IH_TUN_IP "10.10.0.1"
#define AH_TUN_IP "10.10.0.2"
#define TUN_PREFIX_LEN "24"
#define TUN_BUFFER_SIZE 2000

// --- Globals ---
volatile sig_atomic_t g_terminate_ah = 0;
ah_onboard_config_t g_ah_onboard_conf;
ah_state_t g_ah_state;
ah_session_policy_t *g_session_policies = NULL;
pthread_mutex_t g_policy_list_lock = PTHREAD_MUTEX_INITIALIZER;
SSL_CTX *g_controller_mtls_ctx = NULL;
SSL *g_controller_ssl = NULL;
pthread_mutex_t g_controller_ssl_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_t g_controller_listener_tid = 0;
pcap_t *g_spa_pcap_handle = NULL;
pthread_t g_spa_listener_tid = 0;
int g_client_mtls_listen_sock = -1;
SSL_CTX *g_client_mtls_ctx = NULL;
pthread_t g_client_mtls_listener_tid = 0;
pthread_t g_policy_cleanup_tid = 0;
int g_ah_tun_fd = -1;
char g_ah_tun_name[IFNAMSIZ] = "tun0";

// --- Forward Declarations ---
void sigint_handler_ah(int signo);
int load_ah_onboard_config(const char* filename, ah_onboard_config_t *conf);
int load_ah_state(const char* filename, ah_state_t *state);
int save_ah_state(const char* filename, const ah_state_t *state);
int execute_command_ah(const char* command_format, ...);
const char* find_pem_start_ah(const char* line_buffer, const char* key_marker);
int save_pem_to_file_ah(const char* pem_start, const char* end_marker, const char* filename, mode_t mode);
void* controller_listener_thread(void* arg);
int process_controller_message(char *message_orig);
int add_session_policy(const char* ih_ip, uint8_t proto, uint16_t port, uint16_t ah_listen_port, const unsigned char* enc, size_t el, const unsigned char* hmac, size_t hl, const unsigned char* hotp, size_t sl, uint64_t start_ctr, const char* ih_cert_pem_start, const char* ah_cert_pem_start, const char* ah_key_pem_start);
ah_session_policy_t* find_session_policy(const char* ih_ip);
void remove_policy_struct(ah_session_policy_t *policy_to_remove);
void cleanup_policy_resources(ah_session_policy_t *policy);
void free_all_session_policies();
void* policy_cleanup_thread(void* arg);
int run_ah_spa_listener();
void spa_ah_packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet);
int run_iptables_rule_ah(const char* action, const char* source_ip, uint16_t target_port, const char* comment_tag);
int run_client_mtls_listener();
SSL_CTX* create_ah_client_ssl_context();
void* client_listener_thread_func(void* arg);
void* handle_client_connection_thread(void* arg);
int setup_remote_tunnel();
void cleanup_remote_tunnel();
// void cleanup_remote_tunnel_route_only(const char* client_ih_ip); // No longer needed if route not added in handler
void cleanup_ah_resources();

// --- Assumed external from spa_common.c ---
extern void initialize_openssl();
extern void cleanup_openssl();
extern int send_spa_packet(const char*, uint16_t, const unsigned char*, const unsigned char*, size_t, const unsigned char*, size_t, uint64_t, uint8_t, uint16_t);
extern SSL_CTX* create_ssl_context(int);
extern int configure_ssl_context(SSL_CTX*, const char*, const char*, const char*, int);
extern SSL* establish_mtls_connection(const char*, uint16_t, SSL_CTX*);
extern int send_data_over_mtls(SSL*, const char*);
extern void handle_openssl_error(const char*);
extern const char* protocol_to_string(int);
extern int string_to_protocol(const char*);
extern char* trim_whitespace(char *str);
extern int hex_string_to_bytes(const char*, unsigned char*, size_t);
extern int constant_time_memcmp(const void*, const void*, size_t);
extern uint32_t generate_hotp(const unsigned char*, size_t, uint64_t, int);
extern int tun_alloc(char *dev_name, int flags);
extern void print_hex(const char *title, const unsigned char *buf, size_t len, size_t max_print);


// --- Implementations ---

void sigint_handler_ah(int signo) {
	if (g_terminate_ah == 0) { g_terminate_ah = 1; printf("\n[AH] Signal %d received, initiating shutdown...\n", signo); if (g_spa_pcap_handle) { pcap_breakloop(g_spa_pcap_handle); } if (g_client_mtls_listen_sock >= 0) { printf("[AH] Shutting down client listener socket...\n"); shutdown(g_client_mtls_listen_sock, SHUT_RDWR); close(g_client_mtls_listen_sock); g_client_mtls_listen_sock = -1; } }
}
int load_ah_onboard_config(const char* filename, ah_onboard_config_t *conf) {
    FILE *fp = fopen(filename, "r"); if (!fp) { perror("[AH] Open AH onboard"); return 0; } printf("[AH] Loading onboard: %s\n", filename); memset(conf, 0, sizeof(ah_onboard_config_t)); char line[1024]; int ln=0, in_s=0; char controller_ip_from_file[INET_ADDRSTRLEN]={0};
    while(fgets(line,sizeof(line),fp)){ ln++; char*t=trim_whitespace(line); if(!t||t[0]=='\0'||t[0]=='#')continue; if(t[0]=='['&&t[strlen(t)-1]==']'){ size_t il=strlen(t)-2; if(il>0&&il<INET_ADDRSTRLEN){strncpy(controller_ip_from_file,t+1,il);controller_ip_from_file[il]='\0';struct sockaddr_in sa;if(inet_pton(AF_INET,controller_ip_from_file,&sa.sin_addr)!=1){fclose(fp);return 0;} strncpy(conf->controller_ip, controller_ip_from_file, sizeof(conf->controller_ip)-1); conf->controller_ip[sizeof(conf->controller_ip)-1]='\0'; in_s=1;printf("[AH] Config for Controller IP: %s\n",conf->controller_ip);}else{fclose(fp);return 0;}} else if(in_s){char*k=t,*v=NULL;for(char*p=k;*p!='\0';++p){if(isspace((unsigned char)*p)||*p=='='){*p='\0';v=p+1;while(*v!='\0'&&(isspace((unsigned char)*v)||*v=='=')){v++;}break;}} if(v&&*v!='\0'){k=trim_whitespace(k);char*c=strchr(v,'#');if(c)*c='\0';v=trim_whitespace(v);if(strlen(k)==0||strlen(v)==0)continue; if(strcasecmp(k,"ENCRYPTION_KEY")==0){int l=hex_string_to_bytes(v,conf->enc_key,MAX_KEY_LEN);if(l>0){conf->enc_key_len=l;conf->has_enc=1;}else{fclose(fp);return 0;}} else if(strcasecmp(k,"HMAC_KEY")==0){int l=hex_string_to_bytes(v,conf->hmac_key,MAX_KEY_LEN);if(l>0){conf->hmac_key_len=l;conf->has_hmac=1;}else{fclose(fp);return 0;}} else if(strcasecmp(k,"HOTP_SECRET")==0){int l=hex_string_to_bytes(v,conf->hotp_secret,MAX_KEY_LEN);if(l>0){conf->hotp_secret_len=l;conf->has_hotp=1;}else{fclose(fp);return 0;}} else if(strcasecmp(k,"CA_CERT_PATH")==0){strncpy(conf->ca_cert_path,v,sizeof(conf->ca_cert_path)-1);conf->has_ca=1;} else if(strcasecmp(k,"CLIENT_CERT_PATH")==0){strncpy(conf->client_cert_path,v,sizeof(conf->client_cert_path)-1);conf->has_cert=1;} else if(strcasecmp(k,"CLIENT_KEY_PATH")==0){strncpy(conf->client_key_path,v,sizeof(conf->client_key_path)-1);conf->has_key=1;} else if(strcasecmp(k,"MY_IP")==0){strncpy(conf->my_ip,v,sizeof(conf->my_ip)-1);conf->has_my_ip=1;} else {fprintf(stderr,"[AH] Warn: Unknown key %s L%d\n",k,ln);}}}}
    fclose(fp); if(!conf->has_enc||!conf->has_hmac||!conf->has_hotp||!conf->has_ca||!conf->has_cert||!conf->has_key||!conf->has_my_ip||strlen(conf->controller_ip)==0){fprintf(stderr,"[AH] Missing fields in %s\n",filename);return 0;} printf("[AH] AH Onboard loaded OK.\n"); return 1;
}
int load_ah_state(const char* fn, ah_state_t *s){
    FILE *fp=fopen(fn,"rb"); if(!fp){ printf("[AH] State file '%s' not found, initializing counters to 0.\n", fn); s->controller_hotp_counter=0;return 1;} if(fread(s,sizeof(ah_state_t),1,fp)!=1){ perror("[AH] Error reading state file"); fclose(fp);s->controller_hotp_counter=0;return 0;} fclose(fp);printf("[AH] Loaded AH state CtrlCtr=%llu\n",(unsigned long long)s->controller_hotp_counter);return 1;
}
int save_ah_state(const char* fn, const ah_state_t *s){
    FILE *fp=fopen(fn,"wb"); if(!fp){perror("[AH] Error opening state file for writing"); return 0;} if(fwrite(s,sizeof(ah_state_t),1,fp)!=1){perror("[AH] Error writing state file"); fclose(fp);return 0;} fclose(fp);printf("[AH] Saved AH state CtrlCtr=%llu\n",(unsigned long long)s->controller_hotp_counter);return 1;
}
int execute_command_ah(const char* command_format, ...) {
   va_list args; char *command = NULL; int sys_ret = -1, exit_status = -1; va_start(args, command_format); if (vasprintf(&command, command_format, args) == -1) { perror("[AH] vasprintf"); va_end(args); return -1; } va_end(args); printf("[AH] Executing: %s\n", command); sys_ret = system(command); if (sys_ret == -1) { perror("[AH] system() failed"); exit_status = -1;} else { if (WIFEXITED(sys_ret)) { exit_status = WEXITSTATUS(sys_ret); } else if (WIFSIGNALED(sys_ret)) { fprintf(stderr, "[AH] Command killed signal: %d\n", WTERMSIG(sys_ret)); exit_status = -2; } else { exit_status = -3; } } free(command); return exit_status;
}

// --- PEM Parsing Helpers ---
const char* find_pem_start_ah(const char* line_buffer, const char* key_marker) {
    if (!line_buffer || !key_marker) return NULL; const char* value_start = strchr(line_buffer, ':'); if (!value_start) return NULL; value_start++; return strstr(value_start, "-----BEGIN");
}
int save_pem_to_file_ah(const char* pem_start, const char* end_marker, const char* filename, mode_t mode) {
   if (!pem_start || !end_marker || !filename) return 0; const char* pem_end = strstr(pem_start, end_marker); if (!pem_end) { fprintf(stderr, "[AH] Error: PEM end marker '%s' not found for %s\n", end_marker, filename); return 0; } pem_end += strlen(end_marker); while (*pem_end == '\r' || *pem_end == '\n' || isspace((unsigned char)*pem_end)) { pem_end++; } size_t pem_len = pem_end - pem_start; if (pem_len <= 0) { return 0; }
   char *dir_sep = strrchr(filename, '/'); if (dir_sep) { char dir_path[256]; size_t dir_len = dir_sep - filename; if (dir_len >= sizeof(dir_path)) { return 0; } strncpy(dir_path, filename, dir_len); dir_path[dir_len] = '\0'; struct stat st = {0}; if (stat(dir_path, &st) == -1) { if (mkdir(dir_path, 0700) == -1 && errno != EEXIST) { perror("[AH] mkdir"); return 0; } } }
   FILE* fp = fopen(filename, "w"); if (!fp) { perror("[AH] fopen PEM"); return 0; } if (fwrite(pem_start, 1, pem_len, fp) != pem_len) { perror("[AH] fwrite PEM"); fclose(fp); remove(filename); return 0; } fclose(fp); if (chmod(filename, mode) == -1) { perror("[AH] chmod PEM"); } printf("[AH]   Saved PEM data to %s (%zu bytes)\n", filename, pem_len); return 1;
}

// --- Controller Connection and Listener ---
void* controller_listener_thread(void* arg) {
	(void)arg; char buffer[8192]; int read_len; fd_set read_fds; struct timeval timeout;
	printf("[AH_CtrlComm] Controller listener thread started.\n"); while (!g_terminate_ah) { pthread_mutex_lock(&g_controller_ssl_lock); if (!g_controller_ssl) { pthread_mutex_unlock(&g_controller_ssl_lock); sleep(5); continue; } SSL *current_ssl = g_controller_ssl; int current_fd = SSL_get_fd(current_ssl); pthread_mutex_unlock(&g_controller_ssl_lock); if (current_fd < 0) { sleep(5); continue; } FD_ZERO(&read_fds); FD_SET(current_fd, &read_fds); timeout.tv_sec = 2; timeout.tv_usec = 0; int activity = select(current_fd + 1, &read_fds, NULL, NULL, &timeout); if (g_terminate_ah) break; if (activity < 0) { if (errno == EINTR) continue; if (errno == EBADF) { pthread_mutex_lock(&g_controller_ssl_lock); if (g_controller_ssl == current_ssl) g_controller_ssl = NULL; pthread_mutex_unlock(&g_controller_ssl_lock); continue; } perror("[AH_CtrlComm] select error"); pthread_mutex_lock(&g_controller_ssl_lock); if (g_controller_ssl == current_ssl) { SSL_free(g_controller_ssl); g_controller_ssl = NULL; } pthread_mutex_unlock(&g_controller_ssl_lock); continue; } if (activity == 0) continue; if (FD_ISSET(current_fd, &read_fds)) { pthread_mutex_lock(&g_controller_ssl_lock); if (g_controller_ssl != current_ssl || g_controller_ssl == NULL) { pthread_mutex_unlock(&g_controller_ssl_lock); continue; } read_len = SSL_read(g_controller_ssl, buffer, sizeof(buffer) - 1); if (read_len > 0) { buffer[read_len] = '\0'; printf("[AH_CtrlComm] Received %d bytes from Controller:\n---\n%s\n---\n", read_len, buffer); process_controller_message(buffer); } else { int ssl_err = SSL_get_error(g_controller_ssl, read_len); if (ssl_err == SSL_ERROR_ZERO_RETURN || (ssl_err == SSL_ERROR_SYSCALL && read_len == 0)) printf("[AH_CtrlComm] Controller closed connection cleanly.\n"); else { fprintf(stderr, "[AH_CtrlComm] Controller connection SSL_read error: %d\n", ssl_err); handle_openssl_error("Controller SSL_read"); } SSL_free(g_controller_ssl); g_controller_ssl = NULL; } pthread_mutex_unlock(&g_controller_ssl_lock); } } printf("[AH_CtrlComm] Controller listener thread exiting.\n"); return NULL;
}
int process_controller_message(char *message_orig) {
    if (strncmp(message_orig, "NEW_SESSION", 11) != 0) { return 0; } printf("[AH] Processing NEW_SESSION directive from Controller.\n"); char ih_ip[INET_ADDRSTRLEN] = {0}; uint8_t service_proto = 0; uint16_t service_port = 0; unsigned char spa_enc[MAX_KEY_LEN] = {0}; size_t el = 0; unsigned char spa_hmac[MAX_KEY_LEN] = {0}; size_t hl = 0; unsigned char hotp_sec[MAX_KEY_LEN] = {0}; size_t sl = 0; uint64_t start_ctr = 0; const char *ih_cert_pem_start_in_orig = NULL; const char *ah_cert_pem_start_in_orig = NULL; const char *ah_key_pem_start_in_orig = NULL; char *current_line = message_orig; char *next_line = NULL; current_line = strchr(message_orig, '\n'); if (!current_line) return 0; current_line++;
    while (current_line != NULL && *current_line != '\0') { next_line = strchr(current_line, '\n'); size_t line_len; if (next_line) { line_len = next_line - current_line; *next_line = '\0'; } else { line_len = strlen(current_line); } if (line_len == 0 || *current_line == '\r') { if (next_line) { *next_line = '\n'; current_line = next_line + 1; } else { current_line = NULL;} continue; } char *line_copy = strndup(current_line, line_len); if (!line_copy) { perror("strndup"); if(next_line) *next_line = '\n'; return 0; } if (strncmp(line_copy, "END_SESSION", 11) == 0) { free(line_copy); if (next_line) *next_line = '\n'; break; } char *key = line_copy; char *value = strchr(key, ':'); if (value) { *value = '\0'; value++; key = trim_whitespace(key); value = trim_whitespace(value); if (strcasecmp(key, "IH_IP") == 0) { strncpy(ih_ip, value, sizeof(ih_ip)-1); } else if (strcasecmp(key, "SERVICE_PROTO") == 0) { service_proto = (uint8_t)atoi(value); } else if (strcasecmp(key, "SERVICE_PORT") == 0) { service_port = (uint16_t)atoi(value); } else if (strcasecmp(key, "SPA_ENC_KEY") == 0) { el = hex_string_to_bytes(value, spa_enc, MAX_KEY_LEN); } else if (strcasecmp(key, "SPA_HMAC_KEY") == 0) { hl = hex_string_to_bytes(value, spa_hmac, MAX_KEY_LEN); } else if (strcasecmp(key, "HOTP_SECRET") == 0) { sl = hex_string_to_bytes(value, hotp_sec, MAX_KEY_LEN); } else if (strcasecmp(key, "HOTP_COUNTER") == 0) { start_ctr = strtoull(value, NULL, 10); } else if (strcasecmp(key, "IH_EPH_CERT") == 0) { ih_cert_pem_start_in_orig = find_pem_start_ah(current_line, "IH_EPH_CERT:"); } else if (strcasecmp(key, "AH_EPH_CERT") == 0) { ah_cert_pem_start_in_orig = find_pem_start_ah(current_line, "AH_EPH_CERT:"); } else if (strcasecmp(key, "AH_EPH_KEY") == 0)  { ah_key_pem_start_in_orig = find_pem_start_ah(current_line, "AH_EPH_KEY:"); } } free(line_copy); if (next_line) { *next_line = '\n'; current_line = next_line + 1; } else { current_line = NULL; } }
    int parse_ok = (strlen(ih_ip) > 0 && service_proto > 0 && el > 0 && hl > 0 && sl > 0 && ih_cert_pem_start_in_orig != NULL && ah_cert_pem_start_in_orig != NULL && ah_key_pem_start_in_orig != NULL); printf("[AH] Parse results: IH_IP=%d SP=%d EL=%d HL=%d SL=%d IHC=%d AHC=%d AHK=%d\n", strlen(ih_ip)>0, service_proto>0, el>0, hl>0, sl>0, ih_cert_pem_start_in_orig != NULL, ah_cert_pem_start_in_orig != NULL, ah_key_pem_start_in_orig != NULL); if (!parse_ok) { fprintf(stderr, "[AH] Error: Incomplete NEW_SESSION directive.\n"); return 0; } if (!add_session_policy(ih_ip, service_proto, service_port, AH_MTLS_PORT_DEFAULT, spa_enc, el, spa_hmac, hl, hotp_sec, sl, start_ctr, ih_cert_pem_start_in_orig, ah_cert_pem_start_in_orig, ah_key_pem_start_in_orig)) { fprintf(stderr, "[AH] Failed to add session policy for IH %s\n", ih_ip); return 0; } printf("[AH] Successfully processed NEW_SESSION for IH %s targeting %s/%u\n", ih_ip, protocol_to_string(service_proto), service_port); return 1;
}

// --- Policy Management ---
int add_session_policy(const char* ih_ip, uint8_t proto, uint16_t port, uint16_t ah_listen_port, const unsigned char* enc, size_t el, const unsigned char* hmac, size_t hl, const unsigned char* hotp, size_t sl, uint64_t start_ctr, const char* ih_cert_pem_start, const char* ah_cert_pem_start, const char* ah_key_pem_start) {
	printf("[AH_Policy] Adding policy for IH: %s (Service: %u/%u, Listen Port: %u)\n", ih_ip, proto, port, ah_listen_port); ah_session_policy_t *new_policy = malloc(sizeof(ah_session_policy_t)); if (!new_policy) { return 0; } memset(new_policy, 0, sizeof(ah_session_policy_t)); strncpy(new_policy->ih_ip, ih_ip, sizeof(new_policy->ih_ip)-1); new_policy->service_proto = proto; new_policy->service_port = port; new_policy->ah_mtls_listen_port = ah_listen_port; memcpy(new_policy->spa_enc_key, enc, el); new_policy->spa_enc_key_len = el; memcpy(new_policy->spa_hmac_key, hmac, hl); new_policy->spa_hmac_key_len = hl; memcpy(new_policy->hotp_secret, hotp, sl); new_policy->hotp_secret_len = sl; new_policy->hotp_next_counter = start_ctr; new_policy->expiry_time = time(NULL) + SESSION_POLICY_TIMEOUT_SECONDS; new_policy->active = 0; snprintf(new_policy->ih_eph_cert_path, sizeof(new_policy->ih_eph_cert_path), "%s/ih_eph_%s.crt", EPH_CERT_DIR, ih_ip); snprintf(new_policy->ah_eph_cert_path, sizeof(new_policy->ah_eph_cert_path), "%s/ah_eph_%s_for_ih_%s.crt", EPH_CERT_DIR, g_ah_onboard_conf.my_ip, ih_ip); snprintf(new_policy->ah_eph_key_path, sizeof(new_policy->ah_eph_key_path), "%s/ah_eph_%s_for_ih_%s.key", EPH_CERT_DIR, g_ah_onboard_conf.my_ip, ih_ip); int ok = 1; if (!save_pem_to_file_ah(ih_cert_pem_start, "-----END CERTIFICATE-----", new_policy->ih_eph_cert_path, 0644)) ok = 0; if (ok && !save_pem_to_file_ah(ah_cert_pem_start, "-----END CERTIFICATE-----", new_policy->ah_eph_cert_path, 0644)) ok = 0; if (ok && !save_pem_to_file_ah(ah_key_pem_start, "-----END PRIVATE KEY-----", new_policy->ah_eph_key_path, 0600)) ok = 0; if (!ok) { remove(new_policy->ih_eph_cert_path); remove(new_policy->ah_eph_cert_path); remove(new_policy->ah_eph_key_path); free(new_policy); return 0; } pthread_mutex_lock(&g_policy_list_lock); ah_session_policy_t *existing = NULL, *prev = NULL; for(existing = g_session_policies; existing != NULL; prev = existing, existing = existing->next) { if (strcmp(existing->ih_ip, ih_ip) == 0) { printf("[AH_Policy] Replacing existing policy for IH %s\n", ih_ip); if (prev) prev->next = existing->next; else g_session_policies = existing->next; cleanup_policy_resources(existing); remove_policy_struct(existing); break; } } new_policy->next = g_session_policies; g_session_policies = new_policy; pthread_mutex_unlock(&g_policy_list_lock); printf("[AH_Policy] Policy added successfully for IH %s.\n", ih_ip); return 1;
}
ah_session_policy_t* find_session_policy(const char* ih_ip) {
    ah_session_policy_t *current = g_session_policies; while (current != NULL) { if (strcmp(current->ih_ip, ih_ip) == 0) { return current; } current = current->next; } return NULL;
}
void remove_policy_struct(ah_session_policy_t *policy_to_remove) {
    if (!policy_to_remove) return; printf("[AH_Policy] Freeing policy struct memory for IH %s\n", policy_to_remove->ih_ip); free(policy_to_remove);
}
void cleanup_policy_resources(ah_session_policy_t *policy) {
    if (!policy) return; printf("[AH_Policy] Cleaning up policy resources for %s...\n", policy->ih_ip); remove(policy->ih_eph_cert_path); remove(policy->ah_eph_cert_path); remove(policy->ah_eph_key_path); run_iptables_rule_ah("-D", policy->ih_ip, policy->ah_mtls_listen_port, policy->ih_ip);
}
void free_all_session_policies() {
	pthread_mutex_lock(&g_policy_list_lock); ah_session_policy_t *current = g_session_policies, *next; printf("[AH_Policy] Clearing all session policies...\n"); while (current != NULL) { next = current->next; cleanup_policy_resources(current); remove_policy_struct(current); current = next; } g_session_policies = NULL; pthread_mutex_unlock(&g_policy_list_lock); printf("[AH_Policy] All session policies cleared.\n");
}
void* policy_cleanup_thread(void* arg) {
	(void)arg; printf("[AH_PolicyCleanup] Policy cleanup thread started.\n"); while (!g_terminate_ah) { sleep(CLEANUP_INTERVAL_SECONDS); if (g_terminate_ah) break; time_t now = time(NULL); pthread_mutex_lock(&g_policy_list_lock); ah_session_policy_t *current = g_session_policies, *prev = NULL; while (current != NULL) { if (now >= current->expiry_time && !current->active) { printf("[AH_PolicyCleanup] Expiring inactive policy for IH %s\n", current->ih_ip); ah_session_policy_t *to_remove = current; if (prev) { prev->next = current->next; current = current->next; } else { g_session_policies = current->next; current = current->next; } cleanup_policy_resources(to_remove); remove_policy_struct(to_remove); } else { prev = current; current = current->next; } } pthread_mutex_unlock(&g_policy_list_lock); } printf("[AH_PolicyCleanup] Policy cleanup thread exiting.\n"); return NULL;
}

// --- SPA Listener Setup and Handler ---
void* pcap_thread_func(void* arg) {
	(void)arg; printf("[AH_SPA_Thread] pcap_loop starting...\n"); int ret = pcap_loop(g_spa_pcap_handle, -1, spa_ah_packet_handler, NULL); printf("[AH_SPA_Thread] pcap_loop exited with code %d ", ret); if(ret == -1) { fprintf(stderr,"(%s)", pcap_geterr(g_spa_pcap_handle)); } else if (ret == -2) { fprintf(stderr,"(interrupted by pcap_breakloop)"); } fprintf(stderr,"\n"); if (g_spa_pcap_handle) { pcap_close(g_spa_pcap_handle); g_spa_pcap_handle = NULL; printf("[AH_SPA_Thread] pcap handle closed.\n"); } return NULL;
}
int run_ah_spa_listener() {
	char errbuf[PCAP_ERRBUF_SIZE]; char *dev = strdup(SPA_INTERFACE); if (!dev) { return 0; } printf("[AH_SPA] Using interface: %s for SPA listener\n", dev); bpf_u_int32 net, mask; struct bpf_program fp; if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) { net = 0; mask = 0; } g_spa_pcap_handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf); if (!g_spa_pcap_handle) { free(dev); return 0; } free(dev); if (pcap_datalink(g_spa_pcap_handle) != DLT_EN10MB) { fprintf(stderr, "[AH_SPA] Warning: Non-Ethernet interface (%d)\n", pcap_datalink(g_spa_pcap_handle)); } char filter_exp[100]; snprintf(filter_exp, sizeof(filter_exp), "udp dst port %d", SPA_LISTENER_PORT); printf("[AH_SPA] Compiling filter: '%s'\n", filter_exp); if (pcap_compile(g_spa_pcap_handle, &fp, filter_exp, 0, net) == -1) { pcap_close(g_spa_pcap_handle); g_spa_pcap_handle = NULL; return 0; } printf("[AH_SPA] Setting filter...\n"); if (pcap_setfilter(g_spa_pcap_handle, &fp) == -1) { pcap_freecode(&fp); pcap_close(g_spa_pcap_handle); g_spa_pcap_handle = NULL; return 0; } pcap_freecode(&fp); printf("[AH_SPA] SPA Server listening on UDP port %d (for Client Access)...\n", SPA_LISTENER_PORT); if (pthread_create(&g_spa_listener_tid, NULL, pcap_thread_func, NULL) != 0) { perror("pthread_create"); if(g_spa_pcap_handle) pcap_close(g_spa_pcap_handle); g_spa_pcap_handle = NULL; return 0; } return 1;
}
void spa_ah_packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
	const int ETH_HDR_LEN = 14; char source_ip_str[INET_ADDRSTRLEN]; struct tm *tm_info; time_t now; char time_buf[30]; (void)user_data; now = time(NULL); tm_info = localtime(&now); strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", tm_info); if (pkthdr->caplen < (unsigned int)ETH_HDR_LEN) return; const struct ip *ip_header = (struct ip *)(packet + ETH_HDR_LEN); int ip_hdr_len = ip_header->ip_hl * 4; if (ip_hdr_len < 20 || pkthdr->caplen < (unsigned int)(ETH_HDR_LEN + ip_hdr_len) || ip_header->ip_p != IPPROTO_UDP) return; const struct udphdr *udp_header = (struct udphdr *)((u_char *)ip_header + ip_hdr_len); int udp_hdr_len = sizeof(struct udphdr); if (pkthdr->caplen < (unsigned int)(ETH_HDR_LEN + ip_hdr_len + udp_hdr_len)) return; inet_ntop(AF_INET, &(ip_header->ip_src), source_ip_str, INET_ADDRSTRLEN); pthread_mutex_lock(&g_policy_list_lock); ah_session_policy_t *policy = find_session_policy(source_ip_str); if (!policy || time(NULL) >= policy->expiry_time) { if (policy) printf("[AH_SPA] Discarding SPA from %s: Policy expired.\n", source_ip_str); pthread_mutex_unlock(&g_policy_list_lock); return; } printf("[%s] AH_SPA: Active policy found for IH %s. Validating SPA...\n", time_buf, source_ip_str); const u_char *payload = (u_char *)udp_header + udp_hdr_len; int payload_len = pkthdr->caplen - (ETH_HDR_LEN + ip_hdr_len + udp_hdr_len); if ((size_t)payload_len < SPA_PACKET_MIN_LEN || (size_t)payload_len > SPA_PACKET_MAX_LEN) { pthread_mutex_unlock(&g_policy_list_lock); return; } const unsigned char *iv = payload; const unsigned char *encrypted_data = payload + SPA_IV_LEN; int encrypted_len = payload_len - SPA_IV_LEN - SPA_HMAC_LEN; const unsigned char *received_hmac = payload + SPA_IV_LEN + encrypted_len; if (encrypted_len <= 0) { pthread_mutex_unlock(&g_policy_list_lock); return; } unsigned char calculated_hmac[EVP_MAX_MD_SIZE]; unsigned int calc_hmac_len = 0; const EVP_MD *digest = EVP_get_digestbyname(SPA_HMAC_ALGO); if (!digest) {pthread_mutex_unlock(&g_policy_list_lock); return; } unsigned char *data_to_hmac = malloc(SPA_IV_LEN + encrypted_len); if (!data_to_hmac) { pthread_mutex_unlock(&g_policy_list_lock); return; } memcpy(data_to_hmac, iv, SPA_IV_LEN); memcpy(data_to_hmac + SPA_IV_LEN, encrypted_data, encrypted_len); HMAC(digest, policy->spa_hmac_key, policy->spa_hmac_key_len, data_to_hmac, SPA_IV_LEN + encrypted_len, calculated_hmac, &calc_hmac_len); free(data_to_hmac); if (calc_hmac_len != SPA_HMAC_LEN || constant_time_memcmp(received_hmac, calculated_hmac, SPA_HMAC_LEN) != 0) { printf("[AH_SPA] Discarding SPA from %s: Invalid HMAC.\n", source_ip_str); pthread_mutex_unlock(&g_policy_list_lock); return; } unsigned char decrypted_data[sizeof(spa_data_t)]; int decrypted_len = 0, final_len = 0; int decrypt_ok = 1; const EVP_CIPHER *cipher = EVP_get_cipherbyname(SPA_ENCRYPTION_ALGO); if (!cipher) {pthread_mutex_unlock(&g_policy_list_lock); return;} EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new(); if (!ctx) { pthread_mutex_unlock(&g_policy_list_lock); return; } if (1!=EVP_DecryptInit_ex(ctx, cipher, NULL, policy->spa_enc_key, iv)) { decrypt_ok = 0; } if (decrypt_ok && 1!=EVP_DecryptUpdate(ctx, decrypted_data, &decrypted_len, encrypted_data, encrypted_len)) { ERR_clear_error(); decrypt_ok = 0; } if (decrypt_ok && 1!=EVP_DecryptFinal_ex(ctx, decrypted_data + decrypted_len, &final_len)) { ERR_clear_error(); decrypt_ok = 0; } EVP_CIPHER_CTX_free(ctx); if (!decrypt_ok) { printf("[AH_SPA] Discarding SPA from %s: Decryption failed.\n", source_ip_str); pthread_mutex_unlock(&g_policy_list_lock); return; } decrypted_len += final_len; if ((size_t)decrypted_len != sizeof(spa_data_t)) { pthread_mutex_unlock(&g_policy_list_lock); return; } spa_data_t *spa_info = (spa_data_t *)decrypted_data; uint64_t received_timestamp = be64toh(spa_info->timestamp); uint64_t received_hotp_counter = be64toh(spa_info->hotp_counter); uint32_t received_hotp_code = ntohl(spa_info->hotp_code); uint8_t received_req_proto = spa_info->req_protocol; uint16_t received_req_port = ntohs(spa_info->req_port); if (spa_info->version != SPA_VERSION) { pthread_mutex_unlock(&g_policy_list_lock); return; } time_t current_time = time(NULL); if (llabs((int64_t)current_time - (int64_t)received_timestamp) > SPA_TIMESTAMP_WINDOW_SECONDS) { pthread_mutex_unlock(&g_policy_list_lock); return; } if (received_req_proto != policy->service_proto || received_req_port != policy->service_port) { fprintf(stderr, "[AH_SPA] Warn: SPA req %u/%u differs from policy %u/%u for IH %s.\n", received_req_proto, received_req_port, policy->service_proto, policy->service_port, source_ip_str); } uint64_t expected_counter = policy->hotp_next_counter; int hotp_match = 0; if (received_hotp_counter >= expected_counter && received_hotp_counter <= expected_counter + HOTP_COUNTER_SYNC_WINDOW) { uint32_t calculated_code = generate_hotp(policy->hotp_secret, policy->hotp_secret_len, received_hotp_counter, HOTP_CODE_DIGITS); if (calculated_code == received_hotp_code) { hotp_match = 1; policy->hotp_next_counter = received_hotp_counter + 1; printf("[AH_SPA]	HOTP MATCH FOUND at counter %llu! Updated policy next counter to %llu for %s.\n", (unsigned long long)received_hotp_counter, (unsigned long long)policy->hotp_next_counter, source_ip_str); } } pthread_mutex_unlock(&g_policy_list_lock); if (!hotp_match) { fprintf(stderr, "[AH_SPA]	HOTP Validation FAILED for %s.\n", source_ip_str); return; } printf("[AH_SPA] VALID Ephemeral SPA Packet from %s. Authorizing mTLS access to port %u...\n", source_ip_str, policy->ah_mtls_listen_port); if (run_iptables_rule_ah("-I", source_ip_str, policy->ah_mtls_listen_port, source_ip_str) == 0) { char *remove_cmd = NULL; if (asprintf(&remove_cmd, "sh -c 'sleep %d && sudo iptables -D INPUT -s %s -p tcp --dport %u -m comment --comment \"SPA_ALLOW_%s\" -j ACCEPT > /dev/null 2>&1' &", SPA_DEFAULT_DURATION_SECONDS, source_ip_str, policy->ah_mtls_listen_port, source_ip_str) != -1) { printf("[AH_SPA]  Scheduling iptables cleanup: %s\n", remove_cmd); system(remove_cmd); free(remove_cmd); } } else { fprintf(stderr, "[AH_SPA] Failed iptables rule for %s -> port %u\n", source_ip_str, policy->ah_mtls_listen_port); }
}
int run_iptables_rule_ah(const char* action, const char* source_ip, uint16_t target_port, const char* comment_tag) {
	char *command = NULL; int ret; if (asprintf(&command, "sudo iptables %s INPUT -s %s -p tcp --dport %u -m comment --comment \"SPA_ALLOW_%s\" -j ACCEPT", action, source_ip, target_port, comment_tag) == -1) { return -1; } printf("[AH_IPT] Executing: %s\n", command); ret = execute_command_ah(command); free(command); if (ret == 0) { return 0; } else { fprintf(stderr, "[AH_IPT] iptables %s rule for %s -> port %u failed (status: %d)\n", action, source_ip, target_port, ret); return -1; }
}

// --- Client mTLS Listener Setup ---
SSL_CTX* create_ah_client_ssl_context() {
	SSL_CTX *ctx = create_ssl_context(1); if (!ctx) return NULL; if (SSL_CTX_load_verify_locations(ctx, g_ah_onboard_conf.ca_cert_path, NULL) != 1) { handle_openssl_error("Load Verify"); SSL_CTX_free(ctx); return NULL; } SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL); STACK_OF(X509_NAME) *ca_list = SSL_load_client_CA_file(g_ah_onboard_conf.ca_cert_path); if (ca_list == NULL) { fprintf(stderr, "[AH_mTLS] Warn: Failed load client CA list\n"); } SSL_CTX_set_client_CA_list(ctx, ca_list); printf("[AH_mTLS] Base SSL Context for Client Connections created.\n"); return ctx;
}
int run_client_mtls_listener() {
	struct sockaddr_in addr; g_client_mtls_ctx = create_ah_client_ssl_context(); if (!g_client_mtls_ctx) { return 0; } g_client_mtls_listen_sock = socket(AF_INET, SOCK_STREAM, 0); if (g_client_mtls_listen_sock < 0) { perror("Socket"); SSL_CTX_free(g_client_mtls_ctx); g_client_mtls_ctx=NULL; return 0; } int reuse = 1; setsockopt(g_client_mtls_listen_sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)); memset(&addr, 0, sizeof(addr)); addr.sin_family = AF_INET; addr.sin_port = htons(AH_MTLS_PORT_DEFAULT); addr.sin_addr.s_addr = htonl(INADDR_ANY); if (bind(g_client_mtls_listen_sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) { fprintf(stderr, "[AH_mTLS] Bind %d: %s\n", AH_MTLS_PORT_DEFAULT, strerror(errno)); close(g_client_mtls_listen_sock); g_client_mtls_listen_sock = -1; SSL_CTX_free(g_client_mtls_ctx); g_client_mtls_ctx=NULL; return 0; } if (listen(g_client_mtls_listen_sock, SOMAXCONN) < 0) { perror("Listen"); close(g_client_mtls_listen_sock); g_client_mtls_listen_sock = -1; SSL_CTX_free(g_client_mtls_ctx); g_client_mtls_ctx=NULL; return 0; } printf("[AH_mTLS] Server listening for Client mTLS on port %d...\n", AH_MTLS_PORT_DEFAULT); if (pthread_create(&g_client_mtls_listener_tid, NULL, client_listener_thread_func, NULL) != 0) { perror("pthread_create"); if (g_client_mtls_listen_sock >= 0) close(g_client_mtls_listen_sock); if (g_client_mtls_ctx) SSL_CTX_free(g_client_mtls_ctx); g_client_mtls_listen_sock=-1; g_client_mtls_ctx=NULL; return 0; } return 1;
}

// --- Wrapper function for the client listener thread ---
void* client_listener_thread_func(void* arg) {
    (void)arg; printf("[AH_mTLS_Thread] Client listener thread started.\n"); while (!g_terminate_ah) { struct sockaddr_in peer_addr; socklen_t peer_len = sizeof(peer_addr); int client_sock = -1; fd_set read_fds; FD_ZERO(&read_fds); if(g_client_mtls_listen_sock < 0) { break; } FD_SET(g_client_mtls_listen_sock, &read_fds); struct timeval timeout; timeout.tv_sec = 1; timeout.tv_usec = 0; int activity = select(g_client_mtls_listen_sock + 1, &read_fds, NULL, NULL, &timeout); if (g_terminate_ah) break; if (activity < 0) { if (errno == EINTR) continue; if (errno == EBADF) break; perror("select accept"); break; } if (activity == 0) continue; client_sock = accept(g_client_mtls_listen_sock, (struct sockaddr*)&peer_addr, &peer_len); if (g_terminate_ah) { if(client_sock >= 0) close(client_sock); break;} if (client_sock < 0) { if (errno == EINTR || errno == EBADF || errno == EINVAL || errno == ECONNABORTED) continue; perror("Accept"); continue; } char peer_ip_str[INET_ADDRSTRLEN]; inet_ntop(AF_INET, &peer_addr.sin_addr, peer_ip_str, sizeof(peer_ip_str)); printf("[AH_mTLS_Thread] Accepted client connection from %s:%u (FD %d)\n", peer_ip_str, ntohs(peer_addr.sin_port), client_sock); pthread_mutex_lock(&g_policy_list_lock); ah_session_policy_t *policy = find_session_policy(peer_ip_str); if (!policy || time(NULL) >= policy->expiry_time) { fprintf(stderr, "[AH_mTLS_Thread] No valid policy for %s. Closing.\n", peer_ip_str); pthread_mutex_unlock(&g_policy_list_lock); close(client_sock); continue; } SSL *ssl = SSL_new(g_client_mtls_ctx); if (!ssl) { handle_openssl_error("SSL_new"); close(client_sock); pthread_mutex_unlock(&g_policy_list_lock); continue; } printf("[AH_mTLS_Thread] Configuring SSL for %s with cert %s\n", peer_ip_str, policy->ah_eph_cert_path); if (SSL_use_certificate_file(ssl, policy->ah_eph_cert_path, SSL_FILETYPE_PEM) <= 0) { handle_openssl_error("Use Cert"); SSL_free(ssl); pthread_mutex_unlock(&g_policy_list_lock); continue; } if (SSL_use_PrivateKey_file(ssl, policy->ah_eph_key_path, SSL_FILETYPE_PEM) <= 0) { handle_openssl_error("Use Key"); SSL_free(ssl); pthread_mutex_unlock(&g_policy_list_lock); continue; } if (!SSL_check_private_key(ssl)) { handle_openssl_error("Check Key"); SSL_free(ssl); pthread_mutex_unlock(&g_policy_list_lock); continue; } SSL_set_fd(ssl, client_sock); ah_client_conn_data_t *thread_data = malloc(sizeof(ah_client_conn_data_t)); if (!thread_data) { perror("malloc"); SSL_free(ssl); pthread_mutex_unlock(&g_policy_list_lock); continue; } thread_data->ssl = ssl; strcpy(thread_data->peer_ip, peer_ip_str); thread_data->policy = policy; policy->active = 1; printf("[AH_mTLS_Thread] Policy for %s marked as active.\n", peer_ip_str); pthread_mutex_unlock(&g_policy_list_lock); pthread_t tid; if (pthread_create(&tid, NULL, handle_client_connection_thread, (void*)thread_data) != 0) { perror("pthread_create"); pthread_mutex_lock(&g_policy_list_lock); policy->active = 0; pthread_mutex_unlock(&g_policy_list_lock); free(thread_data); SSL_free(ssl); } else { pthread_detach(tid); } } printf("[AH_mTLS_Thread] Client listener thread exiting.\n"); if (g_client_mtls_listen_sock >= 0) { close(g_client_mtls_listen_sock); g_client_mtls_listen_sock = -1; } return NULL;
}

// --- Client mTLS Handler Thread (Modified for TUN Relay WITH ENHANCED DEBUG) ---
void* handle_client_connection_thread(void* arg) {
    ah_client_conn_data_t *data = (ah_client_conn_data_t*)arg;
    SSL *ssl = data->ssl;
    ah_session_policy_t *policy = data->policy;
    int client_ssl_fd = SSL_get_fd(ssl);
    int route_added = 0; // Flag to track if route was added

    printf("[AH_ClientHandler %s] Handling connection...\n", data->peer_ip);

    // --- 1. Perform SSL Handshake ---
    printf("[AH_ClientHandler %s] Performing SSL_accept...\n", data->peer_ip);
	int ret = SSL_accept(ssl);
	if (ret <= 0) { int err = SSL_get_error(ssl, ret); fprintf(stderr, "[AH_ClientHandler %s] SSL_accept FAILED [Code: %d]\n", data->peer_ip, err); handle_openssl_error("SSL_accept client conn"); goto handler_cleanup; }
	printf("[AH_ClientHandler %s] SSL handshake successful. Version: %s Cipher: %s\n", data->peer_ip, SSL_get_version(ssl), SSL_get_cipher(ssl));

	// --- 2. Verify Peer Certificate ---
	X509 *peer_cert = SSL_get_peer_certificate(ssl); int cert_ok = 0;
	if (peer_cert) { char cn_buf[256]={0}; X509_NAME *subj = X509_get_subject_name(peer_cert); if (X509_NAME_get_text_by_NID(subj, NID_commonName, cn_buf, sizeof(cn_buf)-1)>0) { if (strcmp(cn_buf, policy->ih_ip)==0 && strcmp(cn_buf, data->peer_ip)==0) { printf("[AH_ClientHandler %s] Peer CN '%s' matches policy and source IP.\n", data->peer_ip, cn_buf); cert_ok=1; } else { fprintf(stderr, "[AH_ClientHandler %s] Peer CN '%s' mismatch! Policy IH: %s, Src IP: %s\n", data->peer_ip, cn_buf, policy->ih_ip, data->peer_ip); } } X509_free(peer_cert);
	} else { fprintf(stderr, "[AH_ClientHandler %s] No peer certificate!\n", data->peer_ip); }
	if (!cert_ok) { fprintf(stderr, "[AH_ClientHandler %s] Rejecting: cert validation failure.\n", data->peer_ip); goto handler_cleanup; }
	printf("[AH_ClientHandler %s] Peer certificate validated successfully.\n", data->peer_ip);

    // --- 3. Add Route for this client ---
    printf("[AH_ClientHandler %s] Adding route for client...\n", data->peer_ip);
    char cmd[256]; snprintf(cmd, sizeof(cmd), "sudo ip route add %s/32 via %s dev %s", data->peer_ip, IH_TUN_IP, g_ah_tun_name);
    if (execute_command_ah(cmd) != 0) { fprintf(stderr, "[AH_ClientHandler %s] Failed to add route. Aborting.\n", data->peer_ip); goto handler_cleanup; }
    route_added = 1;

	// --- 4. Start Tunnel Relay Loop ---
    printf("[AH_ClientHandler %s] Starting mTLS <-> TUN Relay Loop...\n", data->peer_ip);
    struct pollfd fds[2]; unsigned char buffer[TUN_BUFFER_SIZE]; int running = 1; int poll_ret;
    if (g_ah_tun_fd < 0) { fprintf(stderr, "[AH Relay %s] Error: Invalid TUN FD (%d)\n", data->peer_ip, g_ah_tun_fd); goto handler_cleanup_with_route; }
    fcntl(client_ssl_fd, F_SETFL, O_NONBLOCK); // Ensure non-blocking for SSL reads/checks

    while (running && !g_terminate_ah) {
        fds[0].fd = client_ssl_fd; fds[0].events = POLLIN; fds[0].revents = 0;
        fds[1].fd = g_ah_tun_fd;    fds[1].events = POLLIN; fds[1].revents = 0;

        poll_ret = poll(fds, 2, 1000); // Use 1-second timeout

        if (g_terminate_ah) break;
        if (poll_ret < 0) { if (errno == EINTR) continue; perror("[AH Relay] poll failed"); break; }
        if (poll_ret == 0) continue; // Timeout

        // --- TUN -> mTLS --- (Process replies first?)
        if (fds[1].revents & POLLIN) {
             printf("[AH Relay DEBUG %s] POLLIN event on TUN FD %d\n", data->peer_ip, g_ah_tun_fd);
             while (running) { // Loop read
                 errno = 0; ssize_t len = read(g_ah_tun_fd, buffer, sizeof(buffer)); int read_errno = errno;
                 printf("[AH Relay DEBUG %s] read() from TUN FD returned %zd (errno=%d)\n", data->peer_ip, len, (len<0?read_errno:0));
                 if (len > 0) {
                      printf("[AH Relay] Read %zd bytes from TUN (reply to %s?)\n", len, data->peer_ip);
                      print_hex("TUN->mTLS", buffer, len, 64); // PRINT PACKET CONTENT
                      ssize_t total_written_ssl = 0;
                      while(running && total_written_ssl < len) {
                          errno = 0; int written = SSL_write(ssl, buffer + total_written_ssl, len - total_written_ssl); int write_errno = errno;
                          printf("[AH Relay DEBUG %s] SSL_write() to IH returned %d\n", data->peer_ip, written);
                          if (written <= 0) {
                              int ssl_err = SSL_get_error(ssl, written);
                              if (ssl_err == SSL_ERROR_WANT_WRITE || ssl_err == SSL_ERROR_WANT_READ) { printf("[AH Relay DEBUG %s] SSL_write wants retry, looping poll...\n", data->peer_ip); goto next_poll_iteration_ah; }
                              fprintf(stderr, "[AH Relay] SSL_write to IH %s failed: %d", data->peer_ip, ssl_err);
                              if (ssl_err == SSL_ERROR_SYSCALL) fprintf(stderr," (errno=%d: %s)", write_errno, strerror(write_errno));
                              fprintf(stderr,"\n"); handle_openssl_error("Relay SSL_write");
                              running = 0; break;
                          }
                          total_written_ssl += written;
                      }
                      if (!running) break;
                 } else if (len == 0) { fprintf(stderr, "[AH Relay] Read 0 bytes from TUN?\n"); break; }
                 else { // len < 0
                     if (read_errno == EAGAIN || read_errno == EWOULDBLOCK) { printf("[AH Relay DEBUG %s] read() from TUN returned EAGAIN\n", data->peer_ip); break; } // Done reading for now if non-blocking
                     perror("[AH Relay] read from TUN failed"); running = 0; break;
                 }
                 // If TUN is blocking, one successful read processes the available data for this POLLIN event
                 break; // Exit inner loop after one read, rely on poll() again
             } // end inner TUN read loop
        }
        if (!running) break;

        // --- mTLS -> TUN ---
        if (fds[0].revents & POLLIN) {
            printf("[AH Relay DEBUG %s] POLLIN event on SSL FD %d\n", data->peer_ip, client_ssl_fd);
             while (running) { // Loop SSL_read until WANT_READ or error
                errno = 0; // Reset errno before syscall
                ssize_t len = SSL_read(ssl, buffer, sizeof(buffer));
                int read_errno = errno; // Capture errno immediately
                printf("[AH Relay DEBUG %s] SSL_read() returned %zd\n", data->peer_ip, len);

                if (len > 0) {
                    printf("[AH Relay] Read %zd bytes from mTLS (IH %s)\n", len, data->peer_ip);
                    print_hex("mTLS->TUN", buffer, len, 64); // PRINT PACKET CONTENT
                    // Write to TUN (assuming blocking write for simplicity now)
                    errno = 0; // Reset errno
                    ssize_t written = write(g_ah_tun_fd, buffer, len);
                    int write_errno = errno; // Capture errno
                    printf("[AH Relay DEBUG %s] write() to TUN FD returned %zd (errno=%d)\n", data->peer_ip, written, (written<0?write_errno:0));
                    if (written < 0) { perror("[AH Relay] write to TUN failed"); running = 0; break; } // Break inner loop on error
                    else if (written < len) { fprintf(stderr, "[AH Relay] Partial write to TUN\n"); running = 0; break; } // Break inner loop on partial write
                    // Successfully wrote full packet
                } else { // len <= 0
                    int ssl_err = SSL_get_error(ssl, len);
                    if (ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE) { printf("[AH Relay DEBUG %s] SSL_read returned WANT_READ/WRITE\n", data->peer_ip); break; } // Done reading for this poll cycle
                    // --- Enhanced SYSCALL Check ---
                    if (ssl_err == SSL_ERROR_SYSCALL) {
                        if (len == 0) { fprintf(stderr, "[AH Relay] SSL_read SYSCALL error, underlying read likely returned 0 (EOF).\n"); }
                        else { fprintf(stderr, "[AH Relay] SSL_read SYSCALL error, errno = %d (%s)\n", read_errno, strerror(read_errno)); } // Use captured errno
                    }
                    // -----------------------------
                    else if (ssl_err == SSL_ERROR_ZERO_RETURN) { printf("[AH Relay] IH %s closed mTLS connection cleanly (ZERO_RETURN).\n", data->peer_ip); }
                    else { fprintf(stderr, "[AH Relay] SSL_read from IH %s failed: %d\n", data->peer_ip, ssl_err); handle_openssl_error("Relay SSL_read"); }
                    running = 0; // Stop relay on error or close
                    break; // Break inner read loop
                }
             } // end inner SSL read loop
        }

        if (fds[0].revents & (POLLERR | POLLHUP | POLLNVAL)) { fprintf(stderr,"[AH Relay] Error/Hangup on SSL FD for %s\n", data->peer_ip); running = 0; }
        if (fds[1].revents & (POLLERR | POLLHUP | POLLNVAL)) { fprintf(stderr,"[AH Relay] Error/Hangup on TUN FD\n"); running = 0; }

    next_poll_iteration_ah:; // Label for goto
    } // end while poll loop
    printf("[AH_ClientHandler %s] Relay loop terminated.\n", data->peer_ip);

handler_cleanup_with_route: if(route_added) { cleanup_remote_tunnel_route_only(data->peer_ip); }
handler_cleanup:
	printf("[AH_ClientHandler %s] Cleaning up handler thread...\n", data->peer_ip);
	pthread_mutex_lock(&g_policy_list_lock); if (policy) { ah_session_policy_t *p = find_session_policy(policy->ih_ip); if (p == policy) { printf("[AH_ClientHandler %s] Marking policy as inactive.\n", data->peer_ip); p->active = 0; } } pthread_mutex_unlock(&g_policy_list_lock);
	if (ssl) { SSL_shutdown(ssl); SSL_free(ssl); } free(data);
	return NULL;
}


// --- TUN Setup / Cleanup ---
int setup_remote_tunnel() {
     printf("[AH] Setting up remote TUN device %s...\n", g_ah_tun_name); g_ah_tun_fd = tun_alloc(g_ah_tun_name, IFF_TUN | IFF_NO_PI); if (g_ah_tun_fd < 0) { return 0; } char cmd[256]; snprintf(cmd, sizeof(cmd), "sudo ip addr add %s/%s dev %s", AH_TUN_IP, TUN_PREFIX_LEN, g_ah_tun_name); if (execute_command_ah(cmd) != 0) { close(g_ah_tun_fd); g_ah_tun_fd = -1; return 0; } snprintf(cmd, sizeof(cmd), "sudo ip link set %s up", g_ah_tun_name); if (execute_command_ah(cmd) != 0) { snprintf(cmd, sizeof(cmd), "sudo ip addr del %s/%s dev %s > /dev/null 2>&1", AH_TUN_IP, TUN_PREFIX_LEN, g_ah_tun_name); execute_command_ah(cmd); close(g_ah_tun_fd); g_ah_tun_fd = -1; return 0; }
     // Route added per-client now
     printf("[AH] Remote tunnel %s setup complete (FD %d).\n", g_ah_tun_name, g_ah_tun_fd); return 1;
}
void cleanup_remote_tunnel_route_only(const char* client_ih_ip) {
     // Only remove route if client_ih_ip is valid
     if (client_ih_ip && strlen(client_ih_ip) > 0) {
        printf("[AH] Removing route for %s via %s dev %s...\n", client_ih_ip, IH_TUN_IP, g_ah_tun_name); char cmd[256]; snprintf(cmd, sizeof(cmd), "sudo ip route del %s/32 via %s dev %s > /dev/null 2>&1", client_ih_ip, IH_TUN_IP, g_ah_tun_name); execute_command_ah(cmd);
     } else {
        printf("[AH] Skipping route removal (invalid client IP provided).\n");
     }
}
void cleanup_remote_tunnel() {
      printf("[AH] Cleaning up remote tunnel interface %s...\n", g_ah_tun_name); char cmd[256]; if (g_ah_tun_fd < 0) return;
      // Attempt to remove common stale routes if needed, handle errors gracefully
      cleanup_remote_tunnel_route_only("10.9.70.136"); // Example cleanup
      snprintf(cmd, sizeof(cmd), "sudo ip link set %s down > /dev/null 2>&1", g_ah_tun_name); execute_command_ah(cmd);
      close(g_ah_tun_fd); g_ah_tun_fd = -1; printf("[AH] TUN device %s FD closed.\n", g_ah_tun_name);
}

// --- Main Orchestration ---
int main(int argc, char *argv[]) {
	(void)argc; (void)argv; printf("[AH] Starting SDP Accepting Host (TUN/TAP Version)...\n"); if (geteuid() != 0) { return EXIT_FAILURE; }
	initialize_openssl(); struct sigaction sa; memset(&sa, 0, sizeof(sa)); sa.sa_handler = sigint_handler_ah; sigaction(SIGINT, &sa, NULL); sigaction(SIGTERM, &sa, NULL);
	if (!load_ah_onboard_config(AH_ONBOARD_CONFIG, &g_ah_onboard_conf)) { cleanup_openssl(); return EXIT_FAILURE; } if (!load_ah_state(AH_STATE_FILE, &g_ah_state)) { g_ah_state.controller_hotp_counter = 0; }
    if (!setup_remote_tunnel()) { fprintf(stderr, "[AH] Fatal: Failed setup remote tunnel interface.\n"); cleanup_openssl(); return EXIT_FAILURE; }
	// --- Onboarding Steps 1-3 ---
	printf("[AH] --- 1: SPA -> Controller ---\n"); g_ah_state.controller_hotp_counter++; int spa_r1 = send_spa_packet(g_ah_onboard_conf.controller_ip, SPA_LISTENER_PORT, g_ah_onboard_conf.enc_key, g_ah_onboard_conf.hmac_key, g_ah_onboard_conf.hmac_key_len, g_ah_onboard_conf.hotp_secret, g_ah_onboard_conf.hotp_secret_len, g_ah_state.controller_hotp_counter, 0, 0); if (spa_r1 != 0) { g_ah_state.controller_hotp_counter--; goto main_cleanup; } save_ah_state(AH_STATE_FILE, &g_ah_state); sleep(1);
	printf("[AH] --- 2: mTLS -> Controller ---\n"); g_controller_mtls_ctx = create_ssl_context(0); if (!g_controller_mtls_ctx) { goto main_cleanup; } if (!configure_ssl_context(g_controller_mtls_ctx, g_ah_onboard_conf.ca_cert_path, g_ah_onboard_conf.client_cert_path, g_ah_onboard_conf.client_key_path, 0)) { goto main_cleanup; } pthread_mutex_lock(&g_controller_ssl_lock); g_controller_ssl = establish_mtls_connection(g_ah_onboard_conf.controller_ip, CONTROLLER_MTLS_PORT, g_controller_mtls_ctx); pthread_mutex_unlock(&g_controller_ssl_lock); if (!g_controller_ssl) { goto main_cleanup; } printf("[AH] mTLS connection to Controller established.\n");
	printf("[AH] --- 3: Sending AH_REGISTER -> Controller ---\n"); const char* register_msg = "AH_REGISTER\n"; pthread_mutex_lock(&g_controller_ssl_lock); int sent = send_data_over_mtls(g_controller_ssl, register_msg); pthread_mutex_unlock(&g_controller_ssl_lock); if (sent <= 0) { goto main_cleanup; }
	// --- Start Listener Threads ---
	printf("[AH] --- 4: Starting Listener Threads ---\n"); if (pthread_create(&g_controller_listener_tid, NULL, controller_listener_thread, NULL) != 0) { goto main_cleanup; } if (pthread_create(&g_policy_cleanup_tid, NULL, policy_cleanup_thread, NULL) != 0) { goto main_cleanup; } if (!run_ah_spa_listener()) { goto main_cleanup; } if (!run_client_mtls_listener()) { goto main_cleanup; }
	// --- Main Loop ---
	printf("[AH] AH Initialization Complete. Running... (Press Ctrl+C to exit)\n"); while (!g_terminate_ah) { pause(); }
main_cleanup: printf("[AH] Shutdown initiated. Cleaning up...\n"); cleanup_remote_tunnel(); cleanup_ah_resources(); printf("[AH] AH Exiting.\n"); return (g_terminate_ah ? EXIT_SUCCESS : EXIT_FAILURE);
}

// --- Main Cleanup Function ---
void cleanup_ah_resources() {
	printf("[AH] Cleaning up AH resources...\n"); g_terminate_ah = 1;
	if (g_spa_pcap_handle) { pcap_breakloop(g_spa_pcap_handle); } if (g_client_mtls_listen_sock >= 0) { shutdown(g_client_mtls_listen_sock, SHUT_RDWR); close(g_client_mtls_listen_sock); g_client_mtls_listen_sock = -1;}
    if (g_spa_listener_tid) { pthread_join(g_spa_listener_tid, NULL); printf("[AH] SPA listener thread joined.\n"); } if (g_client_mtls_listener_tid) { pthread_join(g_client_mtls_listener_tid, NULL); printf("[AH] Client mTLS listener thread joined.\n"); }
	pthread_mutex_lock(&g_controller_ssl_lock); if (g_controller_ssl) { SSL_free(g_controller_ssl); g_controller_ssl = NULL; } pthread_mutex_unlock(&g_controller_ssl_lock); if (g_controller_listener_tid) { pthread_join(g_controller_listener_tid, NULL); printf("[AH] Controller listener thread joined.\n"); } if (g_policy_cleanup_tid) { pthread_join(g_policy_cleanup_tid, NULL); printf("[AH] Policy cleanup thread joined.\n"); }
 	if (g_client_mtls_ctx) { SSL_CTX_free(g_client_mtls_ctx); g_client_mtls_ctx = NULL; } if (g_controller_mtls_ctx) { SSL_CTX_free(g_controller_mtls_ctx); g_controller_mtls_ctx = NULL; }
	free_all_session_policies(); pthread_mutex_destroy(&g_policy_list_lock); pthread_mutex_destroy(&g_controller_ssl_lock);
    // TUN FD closed in cleanup_remote_tunnel
	cleanup_openssl(); printf("[AH] AH Cleanup complete.\n");
}


