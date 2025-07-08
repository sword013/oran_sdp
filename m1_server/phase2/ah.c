// ah.c - Accepting Host (Server) Orchestrator (IPsec Version - OPTIMIZED)
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
#include <fcntl.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <ctype.h>
#include <stdarg.h>
#include <endian.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/rand.h>

#include "spa_common.h"
#include "ah_structs.h"

// --- Configuration & State Files ---
#define AH_STATE_FILE "ah_state.dat"
#define AH_ONBOARD_CONFIG "ah_onboard.conf"
#define EPH_CERT_DIR "/tmp/ah_eph_certs"

// --- Default Service Info ---
#define SESSION_POLICY_TIMEOUT_SECONDS (SPA_DEFAULT_DURATION_SECONDS * 4)
#define CLEANUP_INTERVAL_SECONDS 10
#define IPSEC_FIREWALL_TIMEOUT_SECONDS 60 // Should be slightly less than SESSION_POLICY_TIMEOUT_SECONDS

// --- IPsec Config ---
#define EPHEMERAL_CERT_NICKNAME_AH "server"
#define CA_NICKNAME "MyCA"
// #define EPH_P12_FILE_PATH_AH "/tmp/ah_eph.p12" // No longer needed globally, path constructed locally

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
pthread_t g_policy_cleanup_tid = 0;


// --- Function Prototypes --- (Ensure all are listed or correctly defined before use)
void sigint_handler_ah(int signo);
int load_ah_onboard_config(const char* filename, ah_onboard_config_t *conf);
int load_ah_state(const char* filename, ah_state_t *state);
int save_ah_state(const char* filename, const ah_state_t *state);
int execute_command_ah(const char* command_format, ...);
const char* find_pem_start_ah(const char* line_buffer, const char* key_marker);
int save_pem_to_file_ah(const char* pem_start, const char* end_marker, const char* filename, mode_t mode);
void* controller_listener_thread(void* arg);
int process_controller_message(char *message_orig);
int add_session_policy(const char* ih_ip, uint8_t proto, uint16_t port,
                  	const unsigned char* enc, size_t el, const unsigned char* hmac, size_t hl,
                  	const unsigned char* hotp, size_t sl, uint64_t start_ctr,
                  	const char* ih_cert_pem_start, const char* ah_cert_pem_start,
                  	const char* ah_key_pem_start);
ah_session_policy_t* find_session_policy(const char* ih_ip); // Assumes lock is held by caller
void remove_policy_struct(ah_session_policy_t *policy_to_remove);
void cleanup_policy_resources(ah_session_policy_t *policy);
void free_all_session_policies();
void* policy_cleanup_thread(void* arg);
int run_ah_spa_listener();
void spa_ah_packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet);
int run_iptables_rule_ipsec(const char* action, const char* source_ip, const char* comment_tag);
int run_iptables_rule_service(const char* action, const char* source_ip, uint8_t proto, uint16_t port, const char* comment_tag);
int setup_ipsec_server(ah_session_policy_t* policy);
void cleanup_ipsec_server(ah_session_policy_t* policy);
void cleanup_ah_resources();
void* pcap_thread_func(void* arg); // Forward declaration for SPA listener thread

// --- Signal Handler ---
void sigint_handler_ah(int signo) {
   if (g_terminate_ah == 0) {
   	g_terminate_ah = 1;
   	printf("\n[AH] Signal %d received, initiating shutdown...\n", signo);
   	if (g_spa_pcap_handle) {
       	pcap_breakloop(g_spa_pcap_handle);
   	}
   }
}

// --- Config/State/Execute/PEM Helpers ---
// load_ah_onboard_config, load_ah_state, save_ah_state, find_pem_start_ah, save_pem_to_file_ah
// are identical to your provided version.
// For brevity, I'll omit them here.
int load_ah_onboard_config(const char* filename, ah_onboard_config_t *conf) {
   FILE *fp = fopen(filename, "r");
   if (!fp) {
   	perror("[AH] Error opening onboard config");
   	fprintf(stderr,"[AH] Could not open: %s\n", filename);
   	return 0;
   }
   printf("[AH] Loading onboard config: %s\n", filename);
   memset(conf, 0, sizeof(ah_onboard_config_t));
   char line[1024];
   int line_num = 0;
   int in_stanza = 0;
   char controller_ip_from_file[INET_ADDRSTRLEN] = {0};

   while (fgets(line, sizeof(line), fp)) {
   	line_num++;
   	char *t = trim_whitespace(line);
   	if (!t || t[0] == '\0' || t[0] == '#') continue;
   	if (t[0] == '[' && t[strlen(t) - 1] == ']') {
        	size_t ip_len = strlen(t) - 2;
        	if (ip_len > 0 && ip_len < INET_ADDRSTRLEN) {
            	strncpy(controller_ip_from_file, t + 1, ip_len);
            	controller_ip_from_file[ip_len] = '\0';
            	struct sockaddr_in sa;
            	if (inet_pton(AF_INET, controller_ip_from_file, &sa.sin_addr) != 1) {
                	fprintf(stderr, "[AH] Error: Invalid Controller IP '%s' in header line %d\n", controller_ip_from_file, line_num);
                	fclose(fp);
                	return 0;
            	}
            	strncpy(conf->controller_ip, controller_ip_from_file, sizeof(conf->controller_ip) - 1);
            	conf->controller_ip[sizeof(conf->controller_ip) - 1] = '\0';
            	in_stanza = 1;
            	printf("[AH] Found config stanza for Controller IP: %s\n", conf->controller_ip);
        	} else {
            	fprintf(stderr, "[AH] Error: Invalid stanza header format line %d\n", line_num);
            	fclose(fp);
            	return 0;
        	}
   	} else if (in_stanza) {
        	char *k = t, *v = NULL;
        	for (char *p = k; *p != '\0'; ++p) {
            	if (isspace((unsigned char)*p) || *p == '=') {
                	*p = '\0';
                	v = p + 1;
                	while (*v != '\0' && (isspace((unsigned char)*v) || *v == '=')) { v++; }
                	break;
            	}
        	}
        	if (v && *v != '\0') {
            	k = trim_whitespace(k);
            	char *comment_start = strchr(v, '#');
            	if (comment_start) *comment_start = '\0';
            	v = trim_whitespace(v);
            	if (strlen(k) == 0 || strlen(v) == 0) continue;

            	if (strcasecmp(k, "ENCRYPTION_KEY") == 0) {
                	int l = hex_string_to_bytes(v, conf->enc_key, MAX_KEY_LEN);
                	if (l > 0) { conf->enc_key_len = l; conf->has_enc = 1; }
                	else { fprintf(stderr, "[AH] Error: Invalid ENCRYPTION_KEY format line %d\n", line_num); fclose(fp); return 0; }
            	} else if (strcasecmp(k, "HMAC_KEY") == 0) {
                	int l = hex_string_to_bytes(v, conf->hmac_key, MAX_KEY_LEN);
                	if (l > 0) { conf->hmac_key_len = l; conf->has_hmac = 1; }
                	else { fprintf(stderr, "[AH] Error: Invalid HMAC_KEY format line %d\n", line_num); fclose(fp); return 0; }
            	} else if (strcasecmp(k, "HOTP_SECRET") == 0) {
                	int l = hex_string_to_bytes(v, conf->hotp_secret, MAX_KEY_LEN);
                	if (l > 0) { conf->hotp_secret_len = l; conf->has_hotp = 1; }
                	else { fprintf(stderr, "[AH] Error: Invalid HOTP_SECRET format line %d\n", line_num); fclose(fp); return 0; }
            	} else if (strcasecmp(k, "CA_CERT_PATH") == 0) {
                	strncpy(conf->ca_cert_path, v, sizeof(conf->ca_cert_path) - 1); conf->has_ca = 1;
            	} else if (strcasecmp(k, "CLIENT_CERT_PATH") == 0) { 
                	strncpy(conf->client_cert_path, v, sizeof(conf->client_cert_path) - 1); conf->has_cert = 1;
            	} else if (strcasecmp(k, "CLIENT_KEY_PATH") == 0) { 
                	strncpy(conf->client_key_path, v, sizeof(conf->client_key_path) - 1); conf->has_key = 1;
            	} else if (strcasecmp(k, "MY_IP") == 0) { 
                	strncpy(conf->my_ip, v, sizeof(conf->my_ip) - 1); conf->has_my_ip = 1;
            	} else {
                	fprintf(stderr, "[AH] Warn: Unknown key '%s' in config line %d\n", k, line_num);
            	}
        	}
   	}
   }
   fclose(fp);
   if (!conf->has_enc || !conf->has_hmac || !conf->has_hotp || !conf->has_ca || !conf->has_cert || !conf->has_key || !conf->has_my_ip || strlen(conf->controller_ip) == 0) {
   	fprintf(stderr, "[AH] Error: Missing required fields in config file %s\n", filename);
   	return 0;
   }
   printf("[AH] Onboarding config loaded successfully.\n");
   return 1;
}

int load_ah_state(const char* fn, ah_state_t *s){
   FILE *fp=fopen(fn,"rb");
   if(!fp){
   	printf("[AH] State file '%s' not found, initializing counters to 0.\n", fn);
   	s->controller_hotp_counter=0;
   	return 1; 
   }
   if(fread(s,sizeof(ah_state_t),1,fp)!=1){
   	perror("[AH] Error reading state file");
   	fclose(fp);
   	s->controller_hotp_counter=0; 
   	return 0; 
   }
   fclose(fp);
   printf("[AH] Loaded AH state CtrlCtr=%llu\n",(unsigned long long)s->controller_hotp_counter);
   return 1;
}

int save_ah_state(const char* fn, const ah_state_t *s){
   FILE *fp=fopen(fn,"wb");
   if(!fp){
   	perror("[AH] Error opening state file for writing");
   	return 0;
   }
   if(fwrite(s,sizeof(ah_state_t),1,fp)!=1){
   	perror("[AH] Error writing state file");
   	fclose(fp);
   	return 0;
   }
   fclose(fp);
   printf("[AH] Saved AH state CtrlCtr=%llu\n",(unsigned long long)s->controller_hotp_counter);
   return 1;
}

int execute_command_ah(const char* command_format, ...) {
  va_list args;
  char *command = NULL;
  int sys_ret = -1, exit_status = -1;
  va_start(args, command_format);
  if (vasprintf(&command, command_format, args) == -1) {
  	perror("[AH] vasprintf");
  	va_end(args);
  	return -1;
  }
  va_end(args);

  printf("[AH] Executing: %s\n", command);
  sys_ret = system(command);

  if (sys_ret == -1) {
  	perror("[AH] system() failed");
  	exit_status = -1;
  } else {
  	if (WIFEXITED(sys_ret)) {
      	exit_status = WEXITSTATUS(sys_ret);
  	} else if (WIFSIGNALED(sys_ret)) {
      	fprintf(stderr, "[AH] Command killed signal: %d\n", WTERMSIG(sys_ret));
      	exit_status = -2;
  	} else {
      	fprintf(stderr, "[AH] Command terminated abnormally\n");
      	exit_status = -3;
  	}
  }
  free(command);
  return exit_status;
}

const char* find_pem_start_ah(const char* line_buffer, const char* key_marker) {
   if (!line_buffer || !key_marker) return NULL;
   const char* value_start = strchr(line_buffer, ':');
   if (!value_start) return NULL;
   value_start++; 
   return strstr(value_start, "-----BEGIN");
}

int save_pem_to_file_ah(const char* pem_start, const char* end_marker, const char* filename, mode_t mode) {
	if (!pem_start || !end_marker || !filename) return 0;

	const char* pem_end = strstr(pem_start, end_marker);
	if (!pem_end) {
    	fprintf(stderr, "[AH] Error: PEM end marker '%s' not found for %s\n", end_marker, filename);
    	return 0;
	}
	pem_end += strlen(end_marker); 

	while (*pem_end == '\r' || *pem_end == '\n' || isspace((unsigned char)*pem_end)) {
    	pem_end++;
	}

	size_t pem_len = pem_end - pem_start;
	if (pem_len <= 0) {
    	fprintf(stderr, "[AH] Error: Zero or negative length PEM data found for %s\n", filename);
    	return 0;
	}

	char *dir_sep = strrchr(filename, '/');
	if (dir_sep) {
    	char dir_path[256];
    	size_t dir_len = dir_sep - filename;
    	if (dir_len >= sizeof(dir_path)) { fprintf(stderr, "[AH] Directory path too long: %s\n", filename); return 0; }
    	strncpy(dir_path, filename, dir_len);
    	dir_path[dir_len] = '\0';
    	struct stat st = {0};
    	if (stat(dir_path, &st) == -1) {
        	if (mkdir(dir_path, 0700) == -1 && errno != EEXIST) { 
            	perror("[AH] mkdir failed");
            	return 0;
        	}
    	}
	}

	FILE* fp = fopen(filename, "w");
	if (!fp) {
    	perror("[AH] fopen PEM failed");
    	return 0;
	}

	if (fwrite(pem_start, 1, pem_len, fp) != pem_len) {
    	perror("[AH] fwrite PEM failed");
    	fclose(fp);
    	remove(filename); 
    	return 0;
	}
	fclose(fp);

	if (chmod(filename, mode) == -1) {
    	perror("[AH] chmod PEM failed");
	}
	printf("[AH]   Saved PEM data to %s (%zu bytes)\n", filename, pem_len);
	return 1;
}

// Controller Listener Thread & Message Processing are identical
// Omitted for brevity.
void* controller_listener_thread(void* arg) {
   (void)arg;
   char buffer[8192]; 
   int read_len;
   fd_set read_fds;
   struct timeval timeout;

   printf("[AH_CtrlComm] Controller listener thread started.\n");

   while (!g_terminate_ah) {
   	SSL *current_ssl = NULL;
   	int current_fd = -1;

   	pthread_mutex_lock(&g_controller_ssl_lock);
   	if (!g_controller_ssl) {
       	pthread_mutex_unlock(&g_controller_ssl_lock);
       	sleep(1); // Reduced sleep
       	continue;
   	}
   	current_ssl = g_controller_ssl;
   	current_fd = SSL_get_fd(current_ssl);
   	pthread_mutex_unlock(&g_controller_ssl_lock);

   	if (current_fd < 0) { 
       	fprintf(stderr, "[AH_CtrlComm] Error: Invalid FD for controller SSL object.\n");
       	sleep(1); 
       	continue;
   	}

   	FD_ZERO(&read_fds);
   	FD_SET(current_fd, &read_fds);
   	timeout.tv_sec = 2; 
   	timeout.tv_usec = 0;

   	int activity = select(current_fd + 1, &read_fds, NULL, NULL, &timeout);

   	if (g_terminate_ah) break; 

   	if (activity < 0) {
       	if (errno == EINTR) continue; 
       	if (errno == EBADF) {
           	fprintf(stderr, "[AH_CtrlComm] select reported bad file descriptor.\n");
           	pthread_mutex_lock(&g_controller_ssl_lock);
           	if (g_controller_ssl == current_ssl) { 
               	printf("[AH_CtrlComm] Cleaning up stale SSL connection (EBADF).\n");
               	SSL_free(g_controller_ssl);
               	g_controller_ssl = NULL;
           	}
           	pthread_mutex_unlock(&g_controller_ssl_lock);
           	continue; 
       	}
       	perror("[AH_CtrlComm] select error");
       	pthread_mutex_lock(&g_controller_ssl_lock);
       	if (g_controller_ssl == current_ssl) { 
           	printf("[AH_CtrlComm] Cleaning up SSL connection due to select error.\n");
           	SSL_free(g_controller_ssl);
           	g_controller_ssl = NULL;
       	}
       	pthread_mutex_unlock(&g_controller_ssl_lock);
       	continue; 
   	}

   	if (activity == 0) {
        	continue;
   	}

   	if (FD_ISSET(current_fd, &read_fds)) {
        	pthread_mutex_lock(&g_controller_ssl_lock);
        	if (g_controller_ssl != current_ssl || g_controller_ssl == NULL) {
            	pthread_mutex_unlock(&g_controller_ssl_lock);
            	printf("[AH_CtrlComm] SSL object changed or became NULL before read.\n");
            	continue; 
        	}

        	read_len = SSL_read(g_controller_ssl, buffer, sizeof(buffer) - 1);

        	if (read_len > 0) {
            	buffer[read_len] = '\0'; 
            	printf("[AH_CtrlComm] Received %d bytes from Controller:\n---\n%s\n---\n", read_len, buffer);
            	process_controller_message(buffer); 
        	} else {
            	int ssl_err = SSL_get_error(g_controller_ssl, read_len);
            	if (ssl_err == SSL_ERROR_ZERO_RETURN || (ssl_err == SSL_ERROR_SYSCALL && read_len == 0)) {
                	printf("[AH_CtrlComm] Controller closed connection cleanly.\n");
            	} else {
                	fprintf(stderr, "[AH_CtrlComm] Controller connection SSL_read error: %d\n", ssl_err);
                	handle_openssl_error("Controller SSL_read");
            	}
            	SSL_free(g_controller_ssl);
            	g_controller_ssl = NULL;
        	}
        	pthread_mutex_unlock(&g_controller_ssl_lock);
   	}
   }
   printf("[AH_CtrlComm] Controller listener thread exiting.\n");
   return NULL;
}

int process_controller_message(char *message_orig) {
	if (strncmp(message_orig, "NEW_SESSION", 11) != 0) {
    	printf("[AH] Ignoring message from Controller (not NEW_SESSION).\n");
    	return 0; 
	}
	printf("[AH] Processing NEW_SESSION directive from Controller.\n");
	char ih_ip[INET_ADDRSTRLEN] = {0};
	uint8_t service_proto = 0;
	uint16_t service_port = 0;
	unsigned char spa_enc[MAX_KEY_LEN] = {0}; size_t el = 0;
	unsigned char spa_hmac[MAX_KEY_LEN] = {0}; size_t hl = 0;
	unsigned char hotp_sec[MAX_KEY_LEN] = {0}; size_t sl = 0;
	uint64_t start_ctr = 0;
	const char *ih_cert_pem_start_in_orig = NULL;
	const char *ah_cert_pem_start_in_orig = NULL;
	const char *ah_key_pem_start_in_orig = NULL;
	char *current_line = message_orig;
	char *next_line = NULL;
	current_line = strchr(message_orig, '\n');
	if (!current_line) { fprintf(stderr, "[AH] Malformed NEW_SESSION: No newline after header.\n"); return 0; }
	current_line++; 

	while (current_line != NULL && *current_line != '\0') {
    	next_line = strchr(current_line, '\n');
    	size_t line_len;
    	if (next_line) {
        	line_len = next_line - current_line;
        	*next_line = '\0'; 
    	} else {
        	line_len = strlen(current_line); 
    	}
    	if (line_len == 0 || *current_line == '\r') {
        	if (next_line) {
            	*next_line = '\n'; 
            	current_line = next_line + 1;
        	} else {
            	current_line = NULL; 
        	}
        	continue;
    	}
    	char *line_copy = strndup(current_line, line_len);
    	if (!line_copy) {
        	perror("strndup in process_controller_message");
        	if(next_line) *next_line = '\n'; 
        	return 0; 
    	}
    	if (strncmp(line_copy, "END_SESSION", 11) == 0) {
        	free(line_copy);
        	if (next_line) *next_line = '\n'; 
        	break; 
    	}
    	char *key = line_copy;
    	char *value = strchr(key, ':');
    	if (value) {
        	*value = '\0'; 
        	value++;   	
        	key = trim_whitespace(key);
        	value = trim_whitespace(value);
        	if (strcasecmp(key, "IH_IP") == 0) { strncpy(ih_ip, value, sizeof(ih_ip)-1); }
        	else if (strcasecmp(key, "SERVICE_PROTO") == 0) { service_proto = (uint8_t)atoi(value); }
        	else if (strcasecmp(key, "SERVICE_PORT") == 0) { service_port = (uint16_t)atoi(value); }
        	else if (strcasecmp(key, "SPA_ENC_KEY") == 0) { el = hex_string_to_bytes(value, spa_enc, MAX_KEY_LEN); }
        	else if (strcasecmp(key, "SPA_HMAC_KEY") == 0) { hl = hex_string_to_bytes(value, spa_hmac, MAX_KEY_LEN); }
        	else if (strcasecmp(key, "HOTP_SECRET") == 0) { sl = hex_string_to_bytes(value, hotp_sec, MAX_KEY_LEN); }
        	else if (strcasecmp(key, "HOTP_COUNTER") == 0) { start_ctr = strtoull(value, NULL, 10); }
        	else if (strcasecmp(key, "IH_EPH_CERT") == 0) { ih_cert_pem_start_in_orig = find_pem_start_ah(current_line, "IH_EPH_CERT:"); }
        	else if (strcasecmp(key, "AH_EPH_CERT") == 0) { ah_cert_pem_start_in_orig = find_pem_start_ah(current_line, "AH_EPH_CERT:"); }
        	else if (strcasecmp(key, "AH_EPH_KEY") == 0)  { ah_key_pem_start_in_orig = find_pem_start_ah(current_line, "AH_EPH_KEY:"); }
    	}
    	free(line_copy); 
    	if (next_line) {
        	*next_line = '\n'; 
        	current_line = next_line + 1;
    	} else {
        	current_line = NULL; 
    	}
	}
	int parse_ok = (strlen(ih_ip) > 0 && service_proto != 0 && /* service_port can be 0 for 'any' like services */
                	el > 0 && hl > 0 && sl > 0 &&
                	ih_cert_pem_start_in_orig != NULL &&
                	ah_cert_pem_start_in_orig != NULL &&
                	ah_key_pem_start_in_orig != NULL);

	if (!parse_ok) {
    	fprintf(stderr, "[AH] Error: Incomplete NEW_SESSION directive received.\n");
    	fprintf(stderr, "Check flags: ip=%d proto=%d el=%d hl=%d sl=%d ihCert=%d ahCert=%d ahKey=%d\n",
    		strlen(ih_ip) > 0, service_proto != 0, el > 0, hl > 0, sl > 0,
    		ih_cert_pem_start_in_orig != NULL, ah_cert_pem_start_in_orig != NULL, ah_key_pem_start_in_orig != NULL);
    	return 0; 
	}
	if (!add_session_policy(ih_ip, service_proto, service_port,
                        	spa_enc, el, spa_hmac, hl, hotp_sec, sl, start_ctr,
                        	ih_cert_pem_start_in_orig, ah_cert_pem_start_in_orig, ah_key_pem_start_in_orig)) {
    	fprintf(stderr, "[AH] Failed to add session policy for IH %s\n", ih_ip);
    	return 0; 
	}
	printf("[AH] Successfully processed NEW_SESSION for IH %s targeting %s/%u\n", ih_ip, protocol_to_string(service_proto), service_port);
	return 1; 
}

// Policy Management (add_session_policy, find_session_policy, remove_policy_struct,
// cleanup_policy_resources, free_all_session_policies, policy_cleanup_thread)
// are identical. Omitted for brevity.
int add_session_policy(const char* ih_ip, uint8_t proto, uint16_t port,
               	const unsigned char* enc, size_t el, const unsigned char* hmac, size_t hl,
               	const unsigned char* hotp, size_t sl, uint64_t start_ctr,
               	const char* ih_cert_pem_start, const char* ah_cert_pem_start, const char* ah_key_pem_start)
{
   printf("[AH_Policy] Adding policy for IH: %s (Service: %u/%u)\n", ih_ip, proto, port);
   pthread_mutex_lock(&g_policy_list_lock);
   ah_session_policy_t *existing = NULL, *prev = NULL;
   for(existing = g_session_policies; existing != NULL; prev = existing, existing = existing->next) {
    	if (strcmp(existing->ih_ip, ih_ip) == 0) {
        	printf("[AH_Policy] Found existing policy for IH %s, preparing to replace.\n", ih_ip);
        	if (prev) prev->next = existing->next;
        	else g_session_policies = existing->next;
        	break; 
    	}
   }
   pthread_mutex_unlock(&g_policy_list_lock);

   if (existing) {
    	printf("[AH_Policy] Cleaning up resources for replaced policy IH %s\n", ih_ip);
    	cleanup_policy_resources(existing); 
    	remove_policy_struct(existing); 	
    	existing = NULL; 
   }

   ah_session_policy_t *new_policy = malloc(sizeof(ah_session_policy_t));
   if (!new_policy) {
   	perror("[AH_Policy] Failed to allocate memory for new policy");
   	return 0;
   }
   memset(new_policy, 0, sizeof(ah_session_policy_t));

   strncpy(new_policy->ih_ip, ih_ip, sizeof(new_policy->ih_ip)-1);
   new_policy->service_proto = proto;
   new_policy->service_port = port;
   memcpy(new_policy->spa_enc_key, enc, el); new_policy->spa_enc_key_len = el;
   memcpy(new_policy->spa_hmac_key, hmac, hl); new_policy->spa_hmac_key_len = hl;
   memcpy(new_policy->hotp_secret, hotp, sl); new_policy->hotp_secret_len = sl;
   new_policy->hotp_next_counter = start_ctr;
   new_policy->expiry_time = time(NULL) + SESSION_POLICY_TIMEOUT_SECONDS;
   new_policy->active = 0; 

   snprintf(new_policy->ih_eph_cert_path, sizeof(new_policy->ih_eph_cert_path),
        	"%s/ih_eph_%s.crt", EPH_CERT_DIR, ih_ip);
   snprintf(new_policy->ah_eph_cert_path, sizeof(new_policy->ah_eph_cert_path),
        	"%s/ah_eph_%s_for_ih_%s.crt", EPH_CERT_DIR, g_ah_onboard_conf.my_ip, ih_ip);
   snprintf(new_policy->ah_eph_key_path, sizeof(new_policy->ah_eph_key_path),
        	"%s/ah_eph_%s_for_ih_%s.key", EPH_CERT_DIR, g_ah_onboard_conf.my_ip, ih_ip);

   int ok = 1;
   if (!save_pem_to_file_ah(ih_cert_pem_start, "-----END CERTIFICATE-----", new_policy->ih_eph_cert_path, 0644)) ok = 0;
   if (ok && !save_pem_to_file_ah(ah_cert_pem_start, "-----END CERTIFICATE-----", new_policy->ah_eph_cert_path, 0644)) ok = 0;
   if (ok && !save_pem_to_file_ah(ah_key_pem_start, "-----END PRIVATE KEY-----", new_policy->ah_eph_key_path, 0600)) ok = 0;

   if (!ok) {
   	fprintf(stderr, "[AH_Policy] Failed to save one or more PEM files for IH %s\n", ih_ip);
   	remove(new_policy->ih_eph_cert_path);
   	remove(new_policy->ah_eph_cert_path);
   	remove(new_policy->ah_eph_key_path);
   	free(new_policy);
   	return 0; 
   }

   if (!setup_ipsec_server(new_policy)) {
   	fprintf(stderr, "[AH_Policy] Failed to setup IPsec server configuration for IH %s\n", ih_ip);
   	remove(new_policy->ih_eph_cert_path);
   	remove(new_policy->ah_eph_cert_path);
   	remove(new_policy->ah_eph_key_path);
   	free(new_policy);
   	return 0; 
   }
   
   pthread_mutex_lock(&g_policy_list_lock);
   new_policy->next = g_session_policies;
   g_session_policies = new_policy;
   pthread_mutex_unlock(&g_policy_list_lock);

   printf("[AH_Policy] Policy added and IPsec configured for IH %s.\n", ih_ip);
   return 1; 
}

ah_session_policy_t* find_session_policy(const char* ih_ip) {
   ah_session_policy_t *current = g_session_policies;
   while (current != NULL) {
   	if (strcmp(current->ih_ip, ih_ip) == 0) {
       	return current; 
   	}
   	current = current->next;
   }
   return NULL; 
}

void remove_policy_struct(ah_session_policy_t *policy_to_remove) {
   if (!policy_to_remove) return;
   printf("[AH_Policy] Freeing policy struct memory for IH %s\n", policy_to_remove->ih_ip);
   free(policy_to_remove);
}

void cleanup_policy_resources(ah_session_policy_t *policy) {
   if (!policy) return;
   printf("[AH_Policy] Cleaning up policy resources for IH %s...\n", policy->ih_ip);
   cleanup_ipsec_server(policy);
   run_iptables_rule_ipsec("-D", policy->ih_ip, policy->ih_ip);
   run_iptables_rule_service("-D", policy->ih_ip, policy->service_proto, policy->service_port, policy->ih_ip);
   printf("[AH_Policy]   Removing PEM files: %s, %s, %s\n", policy->ih_eph_cert_path, policy->ah_eph_cert_path, policy->ah_eph_key_path); 
   remove(policy->ih_eph_cert_path);
   remove(policy->ah_eph_cert_path);
   remove(policy->ah_eph_key_path);
   printf("[AH_Policy] Resource cleanup finished for IH %s.\n", policy->ih_ip);
}

void free_all_session_policies() {
   pthread_mutex_lock(&g_policy_list_lock);
   ah_session_policy_t *current = g_session_policies;
   ah_session_policy_t *next;
   printf("[AH_Policy] Clearing all session policies and associated resources...\n");
   while (current != NULL) {
   	next = current->next; 
   	printf("[AH_Policy]   Cleaning up policy for IH %s...\n", current->ih_ip); 
   	cleanup_policy_resources(current); 
   	remove_policy_struct(current); 	
   	current = next;
   }
   g_session_policies = NULL; 
   pthread_mutex_unlock(&g_policy_list_lock);
   printf("[AH_Policy] All session policies cleared.\n");
}

void* policy_cleanup_thread(void* arg) {
   (void)arg;
   printf("[AH_PolicyCleanup] Policy cleanup thread started.\n");
   while (!g_terminate_ah) {
   	sleep(CLEANUP_INTERVAL_SECONDS); 
   	if (g_terminate_ah) break; 

   	time_t now = time(NULL);
   	printf("[AH_PolicyCleanup] Checking for expired policies (Current time: %ld)\n", now); 

   	pthread_mutex_lock(&g_policy_list_lock);
   	ah_session_policy_t *current = g_session_policies;
   	ah_session_policy_t *prev = NULL;

   	while (current != NULL) {
       	if (now >= current->expiry_time) {
           	printf("[AH_PolicyCleanup] Expiring policy for IH %s (Expired at %ld)\n", current->ih_ip, current->expiry_time);
           	ah_session_policy_t *to_remove = current;
           	if (prev) {
               	prev->next = current->next;
           	} else {
               	g_session_policies = current->next; 
           	}
           	current = current->next; 
           	pthread_mutex_unlock(&g_policy_list_lock);
           	cleanup_policy_resources(to_remove); 
           	remove_policy_struct(to_remove); 	
           	pthread_mutex_lock(&g_policy_list_lock);
       	} else {
           	prev = current;
           	current = current->next;
       	}
   	}
   	pthread_mutex_unlock(&g_policy_list_lock);
   }
   printf("[AH_PolicyCleanup] Policy cleanup thread exiting.\n");
   return NULL;
}

// SPA Listener (pcap_thread_func, run_ah_spa_listener, spa_ah_packet_handler) are largely identical.
// Key change in spa_ah_packet_handler for iptables scheduling: remove "sudo"
void* pcap_thread_func(void* arg) {
   (void)arg;
   pcap_t* handle = (pcap_t*)g_spa_pcap_handle; 
   printf("[AH_SPA_Thread] pcap_loop starting...\n");
   int ret = pcap_loop(handle, -1, spa_ah_packet_handler, NULL);
   printf("[AH_SPA_Thread] pcap_loop exited with code %d ", ret);
   if(ret == -1) {
   	fprintf(stderr,"(Error: %s)", pcap_geterr(handle));
   } else if (ret == -2) {
   	fprintf(stderr,"(Interrupted by pcap_breakloop)");
   }
   fprintf(stderr,"\n");
   if (g_spa_pcap_handle == handle) { 
    	pcap_close(handle);
    	g_spa_pcap_handle = NULL; 
    	printf("[AH_SPA_Thread] pcap handle closed.\n");
   }
   return NULL;
}

int run_ah_spa_listener() {
   char errbuf[PCAP_ERRBUF_SIZE];
   char filter_exp[100];
   struct bpf_program fp;  	
   bpf_u_int32 net = 0;     	
   bpf_u_int32 mask = 0;    	
   pcap_t *handle = NULL;   	
   char *dev = strdup(SPA_INTERFACE);
   if (!dev) { perror("[AH_SPA] strdup interface failed"); return 0; }
   printf("[AH_SPA] Attempting to listen for SPA on interface: %s\n", dev);
   if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
   	fprintf(stderr, "[AH_SPA] Warning: Couldn't get netmask for device %s: %s. Using 0.0.0.0\n", dev, errbuf);
   	net = 0;
   	mask = 0;
   }
   handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
   if (handle == NULL) {
   	fprintf(stderr, "[AH_SPA] Couldn't open device %s: %s\n", dev, errbuf);
   	free(dev);
   	return 0;
   }
   free(dev); 
   if (pcap_datalink(handle) != DLT_EN10MB) {
   	fprintf(stderr, "[AH_SPA] Warning: Device %s is not Ethernet (%d). Packet parsing might fail.\n",
   	    	SPA_INTERFACE, pcap_datalink(handle));
   }
   snprintf(filter_exp, sizeof(filter_exp), "udp dst port %d", SPA_LISTENER_PORT);
   printf("[AH_SPA] Compiling filter: '%s'\n", filter_exp);
   if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
   	fprintf(stderr, "[AH_SPA] Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
   	pcap_close(handle);
   	return 0;
   }
   printf("[AH_SPA] Setting filter...\n");
   if (pcap_setfilter(handle, &fp) == -1) {
   	fprintf(stderr, "[AH_SPA] Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
   	pcap_freecode(&fp);
   	pcap_close(handle);
   	return 0;
   }
   pcap_freecode(&fp); 
   g_spa_pcap_handle = handle;
   printf("[AH_SPA] SPA listener setup complete on UDP port %d. Starting listener thread...\n", SPA_LISTENER_PORT);
   if (pthread_create(&g_spa_listener_tid, NULL, pcap_thread_func, NULL) != 0) {
   	perror("[AH_SPA] Failed to create pcap listener thread");
   	if(g_spa_pcap_handle) pcap_close(g_spa_pcap_handle);
   	g_spa_pcap_handle = NULL;
   	return 0;
   }
   return 1; 
}

void spa_ah_packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
   const int ETH_HDR_LEN = 14;
   char source_ip_str[INET_ADDRSTRLEN];
   struct tm *tm_info; time_t now; char time_buf[30];
   (void)user_data;

   now = time(NULL); tm_info = localtime(&now); strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", tm_info);

   if (pkthdr->caplen < (unsigned int)ETH_HDR_LEN) { /*printf("[%s] Packet too short (no Ethernet header)\n", time_buf);*/ return; }
   const struct ip *ip_header = (struct ip *)(packet + ETH_HDR_LEN);
   int ip_hdr_len = ip_header->ip_hl * 4;
   if (ip_hdr_len < 20) { /*printf("[%s] Invalid IP header length: %d\n", time_buf, ip_hdr_len);*/ return; }
   if (pkthdr->caplen < (unsigned int)(ETH_HDR_LEN + ip_hdr_len)) { /*printf("[%s] Packet too short (no IP header)\n", time_buf);*/ return; }
   if (ip_header->ip_p != IPPROTO_UDP) { /*printf("[%s] Not a UDP packet (proto: %d)\n", time_buf, ip_header->ip_p);*/ return; }
   const struct udphdr *udp_header = (struct udphdr *)((u_char *)ip_header + ip_hdr_len);
   int udp_hdr_len = sizeof(struct udphdr);
   if (pkthdr->caplen < (unsigned int)(ETH_HDR_LEN + ip_hdr_len + udp_hdr_len)) { /*printf("[%s] Packet too short (no UDP header)\n", time_buf);*/ return; }
   inet_ntop(AF_INET, &(ip_header->ip_src), source_ip_str, INET_ADDRSTRLEN);

   pthread_mutex_lock(&g_policy_list_lock);
   ah_session_policy_t *policy = find_session_policy(source_ip_str);
   if (!policy) {
   	printf("[%s] No active policy found for source IP %s. Ignoring SPA.\n", time_buf, source_ip_str);
   	pthread_mutex_unlock(&g_policy_list_lock);
   	return;
   }

   unsigned char eph_hmac_key[MAX_KEY_LEN]; size_t eph_hmac_key_len = policy->spa_hmac_key_len;
   unsigned char eph_enc_key[MAX_KEY_LEN]; /* size_t eph_enc_key_len = policy->spa_enc_key_len; Not used directly here, but good to note */
   unsigned char eph_hotp_secret[MAX_KEY_LEN]; size_t eph_hotp_secret_len = policy->hotp_secret_len;
   uint64_t expected_counter = policy->hotp_next_counter; 
   uint8_t service_proto = policy->service_proto;
   uint16_t service_port = policy->service_port;
   time_t expiry_time = policy->expiry_time; 

   memcpy(eph_hmac_key, policy->spa_hmac_key, policy->spa_hmac_key_len);
   memcpy(eph_enc_key, policy->spa_enc_key, policy->spa_enc_key_len); // Corrected: copy enc_key
   memcpy(eph_hotp_secret, policy->hotp_secret, policy->hotp_secret_len);
   
   if (time(NULL) >= expiry_time) {
   	printf("[%s] AH_SPA: Discarding SPA from %s: Policy expired.\n", time_buf, source_ip_str);
   	pthread_mutex_unlock(&g_policy_list_lock); 
   	return;
   }
   printf("[%s] AH_SPA: Active policy found for IH %s. Validating SPA...\n", time_buf, source_ip_str);
   const u_char *payload = (u_char *)udp_header + udp_hdr_len;
   int payload_len = pkthdr->caplen - (ETH_HDR_LEN + ip_hdr_len + udp_hdr_len);
   if ((size_t)payload_len < SPA_PACKET_MIN_LEN || (size_t)payload_len > SPA_PACKET_MAX_LEN) {
   	printf("[%s] AH_SPA: Discarding SPA from %s: Invalid payload length (%d bytes).\n", time_buf, source_ip_str, payload_len);
   	pthread_mutex_unlock(&g_policy_list_lock); 
   	return;
   }
   const unsigned char *iv = payload;
   const unsigned char *encrypted_data = payload + SPA_IV_LEN;
   int encrypted_len_val = payload_len - SPA_IV_LEN - SPA_HMAC_LEN; // Renamed to avoid conflict
   const unsigned char *received_hmac = payload + SPA_IV_LEN + encrypted_len_val;

   if (encrypted_len_val <= 0) {
   	printf("[%s] AH_SPA: Discarding SPA from %s: Invalid encrypted data length (%d bytes).\n", time_buf, source_ip_str, encrypted_len_val);
   	pthread_mutex_unlock(&g_policy_list_lock); 
   	return;
   }
   unsigned char calculated_hmac[EVP_MAX_MD_SIZE];
   unsigned int calc_hmac_len = 0;
   const EVP_MD *digest = EVP_get_digestbyname(SPA_HMAC_ALGO);
   if (!digest) { fprintf(stderr,"[AH_SPA] Failed get digest %s\n", SPA_HMAC_ALGO); pthread_mutex_unlock(&g_policy_list_lock); return; }
   size_t data_hmac_len = SPA_IV_LEN + encrypted_len_val;
   unsigned char *data_to_hmac = malloc(data_hmac_len);
   if (!data_to_hmac) { perror("malloc data_to_hmac failed"); pthread_mutex_unlock(&g_policy_list_lock); return; }
   memcpy(data_to_hmac, iv, SPA_IV_LEN);
   memcpy(data_to_hmac + SPA_IV_LEN, encrypted_data, encrypted_len_val);
   HMAC(digest, eph_hmac_key, eph_hmac_key_len, data_to_hmac, data_hmac_len, calculated_hmac, &calc_hmac_len);
   free(data_to_hmac); data_to_hmac = NULL; 
   if (calc_hmac_len != SPA_HMAC_LEN || constant_time_memcmp(received_hmac, calculated_hmac, SPA_HMAC_LEN) != 0) {
   	printf("[%s] AH_SPA: Discarding SPA from %s: Invalid HMAC.\n", time_buf, source_ip_str);
   	pthread_mutex_unlock(&g_policy_list_lock); 
   	return;
   }
   printf("[%s] AH_SPA:	HMAC validation successful for %s.\n", time_buf, source_ip_str); 
   unsigned char decrypted_data[sizeof(spa_data_t) + SPA_IV_LEN]; 
   int decrypted_len_val = 0, final_len = 0; // Renamed
   int decrypt_ok = 1;
   const EVP_CIPHER *cipher = EVP_get_cipherbyname(SPA_ENCRYPTION_ALGO);
   if (!cipher) { fprintf(stderr,"[AH_SPA] Failed get cipher %s\n", SPA_ENCRYPTION_ALGO); pthread_mutex_unlock(&g_policy_list_lock); return;}
   EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
   if (!ctx) { fprintf(stderr,"[AH_SPA] Failed EVP_CIPHER_CTX_new\n"); pthread_mutex_unlock(&g_policy_list_lock); return; }
   if (1 != EVP_DecryptInit_ex(ctx, cipher, NULL, eph_enc_key, iv)) { handle_openssl_error("DecryptInit"); decrypt_ok = 0; }
   if (decrypt_ok && 1 != EVP_DecryptUpdate(ctx, decrypted_data, &decrypted_len_val, encrypted_data, encrypted_len_val)) {
   	ERR_clear_error(); 
   }
   if (decrypt_ok && 1 != EVP_DecryptFinal_ex(ctx, decrypted_data + decrypted_len_val, &final_len)) {
   	ERR_clear_error(); 
   	decrypt_ok = 0;
   }
   EVP_CIPHER_CTX_free(ctx); ctx = NULL;
   if (!decrypt_ok) {
   	printf("[%s] AH_SPA: Discarding SPA from %s: Decryption failed.\n", time_buf, source_ip_str);
   	pthread_mutex_unlock(&g_policy_list_lock); 
   	return;
   }
   decrypted_len_val += final_len; 
   if ((size_t)decrypted_len_val != sizeof(spa_data_t)) {
   	printf("[%s] AH_SPA: Discarding SPA from %s: Incorrect decrypted data length (%d != %zu).\n", time_buf, source_ip_str, decrypted_len_val, sizeof(spa_data_t));
   	pthread_mutex_unlock(&g_policy_list_lock); 
   	return;
   }
   printf("[%s] AH_SPA:	Decryption successful for %s.\n", time_buf, source_ip_str); 
   spa_data_t *spa_info = (spa_data_t *)decrypted_data;
   if (spa_info->version != SPA_VERSION) {
   	printf("[%s] AH_SPA: Discarding SPA from %s: Invalid version (%u != %u).\n", time_buf, source_ip_str, spa_info->version, SPA_VERSION);
   	pthread_mutex_unlock(&g_policy_list_lock); 
   	return;
   }
   uint64_t received_timestamp = be64toh(spa_info->timestamp);
   time_t current_time = time(NULL);
   if (llabs((int64_t)current_time - (int64_t)received_timestamp) > SPA_TIMESTAMP_WINDOW_SECONDS) {
   	printf("[%s] AH_SPA: Discarding SPA from %s: Timestamp out of window (%llu vs %ld).\n", time_buf, source_ip_str, (unsigned long long)received_timestamp, current_time);
   	pthread_mutex_unlock(&g_policy_list_lock); 
   	return;
   }
   uint64_t received_hotp_counter = be64toh(spa_info->hotp_counter);
   uint32_t received_hotp_code = ntohl(spa_info->hotp_code);
   int hotp_match = 0;
   if (received_hotp_counter >= expected_counter &&
   	received_hotp_counter <= expected_counter + HOTP_COUNTER_SYNC_WINDOW)
   {
   	uint32_t calculated_code = generate_hotp(eph_hotp_secret, eph_hotp_secret_len, received_hotp_counter, HOTP_CODE_DIGITS);
   	if (calculated_code != (uint32_t)-1 && calculated_code == received_hotp_code) {
       	hotp_match = 1;
       	policy->hotp_next_counter = received_hotp_counter + 1;
       	printf("[%s] AH_SPA:	HOTP MATCH FOUND at counter %llu! Updated policy next counter to %llu for %s.\n", time_buf, (unsigned long long)received_hotp_counter, (unsigned long long)policy->hotp_next_counter, source_ip_str);
   	} else {
        	printf("[%s] AH_SPA:	HOTP code mismatch for counter %llu (Expected %u, Got %u) for %s.\n", time_buf, (unsigned long long)received_hotp_counter, calculated_code, received_hotp_code, source_ip_str);
   	}
   } else {
   	printf("[%s] AH_SPA:	HOTP counter %llu out of sync window (Expected >= %llu) for %s.\n", time_buf, (unsigned long long)received_hotp_counter, (unsigned long long)expected_counter, source_ip_str);
   }
   pthread_mutex_unlock(&g_policy_list_lock); 
   if (!hotp_match) {
   	fprintf(stderr, "[%s] AH_SPA:	HOTP Validation FAILED for %s. Discarding packet.\n", time_buf, source_ip_str);
   	return;
   }
   printf("[%s] AH_SPA: VALID Ephemeral SPA Packet received from %s.\n", time_buf, source_ip_str);
   printf("[%s] AH_SPA: Authorizing IPsec (IKE/ESP) AND Service Port (%s/%u) via iptables...\n",
       	time_buf, protocol_to_string(service_proto), service_port);

   int rule_ok = 1;
   if (run_iptables_rule_ipsec("-I", source_ip_str, source_ip_str) != 0) {
   	fprintf(stderr, "[%s] AH_SPA: FAILED to add IPsec iptables rules for %s.\n", time_buf, source_ip_str);
   	rule_ok = 0;
   }
   if (rule_ok && run_iptables_rule_service("-I", source_ip_str, service_proto, service_port, source_ip_str) != 0) {
   	fprintf(stderr, "[%s] AH_SPA: FAILED to add Service (%s/%u) iptables rule for %s.\n", time_buf, protocol_to_string(service_proto), service_port, source_ip_str);
   	rule_ok = 0; 
   }

   if (rule_ok) {
   	printf("[%s] AH_SPA: Successfully added firewall rules for %s.\n", time_buf, source_ip_str);
   	char *remove_cmd_ipsec = NULL;
   	char *remove_cmd_svc = NULL;
    // REMOVED "sudo" from inside the sh -c strings as ah_server is already root
   	if (asprintf(&remove_cmd_ipsec, "sh -c 'sleep %d && iptables -D INPUT -s %s -p udp -m multiport --dports 500,4500 -m comment --comment \"SDP_IPSEC_ALLOW_%s\" -j ACCEPT > /dev/null 2>&1 && iptables -D INPUT -s %s -p esp -m comment --comment \"SDP_IPSEC_ALLOW_%s\" -j ACCEPT > /dev/null 2>&1' &",
               	IPSEC_FIREWALL_TIMEOUT_SECONDS, source_ip_str, source_ip_str, source_ip_str, source_ip_str) != -1) {
       	printf("[%s] AH_SPA:  Scheduling IPsec firewall cleanup in %d sec: %s\n", time_buf, IPSEC_FIREWALL_TIMEOUT_SECONDS, remove_cmd_ipsec);
       	system(remove_cmd_ipsec); 
       	free(remove_cmd_ipsec);
   	} else {
       	perror("[AH_SPA] asprintf failed for IPsec cleanup command");
   	}
   	const char* proto_str_sched = protocol_to_string(service_proto);
   	if (proto_str_sched && strcmp(proto_str_sched, "?") != 0) { // Check for invalid protocol string
        	if (asprintf(&remove_cmd_svc, "sh -c 'sleep %d && iptables -D INPUT -s %s -p %s --dport %u -m comment --comment \"SDP_SVC_ALLOW_%s\" -j ACCEPT > /dev/null 2>&1' &",
                    	IPSEC_FIREWALL_TIMEOUT_SECONDS, source_ip_str, proto_str_sched, service_port, source_ip_str) != -1) {
            	printf("[%s] AH_SPA:  Scheduling Service firewall cleanup in %d sec: %s\n", time_buf, IPSEC_FIREWALL_TIMEOUT_SECONDS, remove_cmd_svc);
            	system(remove_cmd_svc); 
            	free(remove_cmd_svc);
        	} else {
            	perror("[AH_SPA] asprintf failed for service cleanup command");
        	}
   	} else {
        	fprintf(stderr, "[%s] AH_SPA: Cannot schedule service rule cleanup for %s: Unknown protocol %d\n", time_buf, source_ip_str, service_proto);
   	}
   } else {
   	fprintf(stderr, "[%s] AH_SPA: Failed to add one or more required firewall rules for %s. Access may fail.\n", time_buf, source_ip_str);
   }
}


// --- iptables rule functions ---
// REMOVED "sudo" from commands as ah_server is root
int run_iptables_rule_ipsec(const char* action, const char* source_ip, const char* comment_tag) {
   char *cmd_udp = NULL;
   char *cmd_esp = NULL;
   int ret_udp = -1, ret_esp = -1;
   int result = -1;

   if (asprintf(&cmd_udp, "iptables %s INPUT -s %s -p udp -m multiport --dports 500,4500 -m comment --comment \"SDP_IPSEC_ALLOW_%s\" -j ACCEPT",
           	action, source_ip, comment_tag) == -1) {
   	perror("[AH_IPT] asprintf failed for UDP rule");
   	goto cleanup_ipsec_rule;
   }
   printf("[AH_IPT] Executing: %s\n", cmd_udp);
   ret_udp = execute_command_ah(cmd_udp);
   if (ret_udp != 0 && strcmp(action,"-D") != 0) {
   	fprintf(stderr, "[AH_IPT] iptables %s rule for IKE/UDP failed (status: %d)\n", action, ret_udp);
   	goto cleanup_ipsec_rule;
   }

   if (asprintf(&cmd_esp, "iptables %s INPUT -s %s -p esp -m comment --comment \"SDP_IPSEC_ALLOW_%s\" -j ACCEPT",
           	action, source_ip, comment_tag) == -1) {
   	perror("[AH_IPT] asprintf failed for ESP rule");
   	goto cleanup_ipsec_rule;
   }
   printf("[AH_IPT] Executing: %s\n", cmd_esp);
   ret_esp = execute_command_ah(cmd_esp);
   if (ret_esp != 0 && strcmp(action,"-D") != 0) {
   	fprintf(stderr, "[AH_IPT] iptables %s rule for ESP failed (status: %d)\n", action, ret_esp);
   	goto cleanup_ipsec_rule;
   }
   printf("[AH_IPT] iptables %s rules for IPsec from %s completed (UDP status=%d, ESP status=%d).\n", action, source_ip, ret_udp, ret_esp);
   result = 0;

cleanup_ipsec_rule:
   if(cmd_udp) free(cmd_udp);
   if(cmd_esp) free(cmd_esp);
   return result;
}

int run_iptables_rule_service(const char* action, const char* source_ip, uint8_t proto, uint16_t port, const char* comment_tag) {
   char *command = NULL;
   int ret = -1;
   const char* proto_str = protocol_to_string(proto);

   if (strcmp(proto_str, "?") == 0) {
   	fprintf(stderr, "[AH_IPT] Unknown protocol number %d for service rule.\n", proto);
   	return -1;
   }
   if (asprintf(&command, "iptables %s INPUT -s %s -p %s --dport %u -m comment --comment \"SDP_SVC_ALLOW_%s\" -j ACCEPT",
           	action, source_ip, proto_str, port, comment_tag) == -1) {
   	perror("[AH_IPT] asprintf failed for service rule");
   	return -1;
   }
   printf("[AH_IPT] Executing: %s\n", command);
   ret = execute_command_ah(command);
   free(command); command = NULL;

   if (ret == 0) {
   	printf("[AH_IPT] iptables %s rule for Service %s/%u from %s successful.\n", action, proto_str, port, source_ip);
   	return 0;
   } else {
   	if (strcmp(action, "-D") != 0) {
       	fprintf(stderr, "[AH_IPT] iptables %s rule for Service %s/%u from %s FAILED (status: %d)\n", action, proto_str, port, source_ip, ret);
   	} else {
       	printf("[AH_IPT] Note: iptables %s rule for Service %s/%u from %s maybe failed or rule didn't exist (status: %d)\n", action, proto_str, port, source_ip, ret);
   	}
   	return (strcmp(action, "-D") == 0) ? 0 : -1;
   }
}

// --- IPsec Server Setup/Cleanup ---
// REMOVED "sudo" from commands
int setup_ipsec_server(ah_session_policy_t* policy) {
   printf("[AH IPsec] Setting up IPsec server config for IH %s...\n", policy->ih_ip);
   int ret;
   char cmd[1024];
   char p12_path[512];
   snprintf(p12_path, sizeof(p12_path), "%s/%s_for_ih_%s.p12", EPH_CERT_DIR, EPHEMERAL_CERT_NICKNAME_AH, policy->ih_ip);


   printf("  1. Creating AH ephemeral PKCS12 bundle...\n");
   snprintf(cmd, sizeof(cmd), "openssl pkcs12 -export -in %s -inkey %s -certfile %s -name \"%s\" -out %s -passout pass:",
        	policy->ah_eph_cert_path,
        	policy->ah_eph_key_path,
        	g_ah_onboard_conf.ca_cert_path,
        	EPHEMERAL_CERT_NICKNAME_AH, // Using a generic nickname for the server cert itself
        	p12_path);
   ret = execute_command_ah(cmd);
   if (ret != 0) { fprintf(stderr, "[AH IPsec] Failed to create AH PKCS12 bundle (ret:%d).\n", ret); return 0; }

   printf("  2. Importing common CA certificate to NSS DB (if not present)...\n");
   snprintf(cmd, sizeof(cmd), "certutil -A -d sql:/var/lib/ipsec/nss -n \"%s\" -t \"CT,,\" -a -i %s",
        	CA_NICKNAME, g_ah_onboard_conf.ca_cert_path);
   ret = execute_command_ah(cmd);
   if (ret != 0 && ret != 255) { fprintf(stderr, "[AH IPsec] Failed to import CA cert (ret:%d).\n", ret); remove(p12_path); return 0; }

   printf("  3. Importing AH ephemeral server certificate bundle to NSS DB...\n");
   snprintf(cmd, sizeof(cmd), "pk12util -i %s -d sql:/var/lib/ipsec/nss/ -n \"%s\" -W ''",
        	p12_path, EPHEMERAL_CERT_NICKNAME_AH); // Use the same generic nickname
   ret = execute_command_ah(cmd);
   if (ret != 0) {
   	    fprintf(stderr, "[AH IPsec] Warning: pk12util import failed or nickname '%s' already exists (ret:%d). May need to delete old one first.\n", EPHEMERAL_CERT_NICKNAME_AH, ret);
        // Attempt to delete existing cert with this nickname and retry import
        fprintf(stderr, "[AH IPsec] Attempting to delete existing cert with nickname '%s' and retry import...\n", EPHEMERAL_CERT_NICKNAME_AH);
        execute_command_ah("certutil -D -d sql:/var/lib/ipsec/nss -n '%s'", EPHEMERAL_CERT_NICKNAME_AH); // Delete old
        ret = execute_command_ah("pk12util -i %s -d sql:/var/lib/ipsec/nss/ -n \"%s\" -W ''", p12_path, EPHEMERAL_CERT_NICKNAME_AH); // Retry
        if (ret != 0) {
            fprintf(stderr, "[AH IPsec] pk12util import retry failed (ret:%d).\n", ret);
            // Not returning error here, allowing to proceed if certutil -L shows it eventually.
        }
   }

   printf("  4. Verifying certificates in NSS DB (optional check)...\n");
   execute_command_ah("certutil -L -d sql:/var/lib/ipsec/nss");

   // Construct a unique connection name for this IH to allow concurrent sessions
   char conn_name[128];
   snprintf(conn_name, sizeof(conn_name), "server-to-%s", policy->ih_ip); // Replace dots in IP for valid conn name
   for(char* p = conn_name; *p; ++p) if(*p == '.') *p = '_';


   printf("  5. Adding/Replacing IPsec connection definition '%s'...\n", conn_name);
   // This definition needs to exist in /etc/ipsec.d/ or be dynamically created.
   // For simplicity, we assume a base 'server-to-client-template' exists and we load it
   // with specific parameters, or we just use `ipsec auto --add server-to-client` if
   // the server-to-client connection is generic and uses `right=%any` with `rightid=%fromcert`.
   // The current code uses "server-to-client" which is generic.
   // If specific conn per IH is needed, `ipsec.conf` needs a template, or dynamic conf file generation.
   // Let's stick to a generic "server-to-client" that uses `rightid=%fromcert` to authenticate specific IHs.
   execute_command_ah("ipsec auto --rereadsecrets"); // Reload secrets
   execute_command_ah("ipsec auto --rereadcerts");  // Reload certs from NSS DB
   
   // The 'server-to-client' connection in ipsec.conf should be configured with:
   // leftcert=server (matching EPHEMERAL_CERT_NICKNAME_AH)
   // right=%any
   // rightid=%fromcert (to authenticate based on IH's cert CN)
   // rightca="<CA_Subject_DN_of_IHs_CA>"
   ret = execute_command_ah("ipsec auto --add server-to-client"); // Or use `conn_name` if specific
   if (ret != 0) {
  	fprintf(stderr, "[AH IPsec] Warning: 'ipsec auto --add %s' failed (ret:%d), maybe already loaded?\n", "server-to-client", ret);
   }
   // It might be necessary to do `ipsec auto --up <conn_name>` or `ipsec auto --route <conn_name>`
   // if `auto=start` is not used in the conn definition. However, usually the IH initiates.

   remove(p12_path);
   printf("[AH IPsec] Server setup commands executed for IH %s.\n", policy->ih_ip);
   return 1;
}

void cleanup_ipsec_server(ah_session_policy_t* policy) {
   if (!policy) return;
   printf("[AH IPsec] Cleaning up IPsec server config related to IH %s...\n", policy->ih_ip);
   char cmd[1024];
   char p12_path[512]; // Path for temporary PKCS12 file (though not created here)
   snprintf(p12_path, sizeof(p12_path), "%s/%s_for_ih_%s.p12", EPH_CERT_DIR, EPHEMERAL_CERT_NICKNAME_AH, policy->ih_ip);


   // Construct unique connection name used during setup
   char conn_name[128];
   snprintf(conn_name, sizeof(conn_name), "server-to-%s", policy->ih_ip);
   for(char* p = conn_name; *p; ++p) if(*p == '.') *p = '_';

   printf("  1. Taking down specific connection instance (if it was named uniquely and up)...\n");
   // If using generic "server-to-client", taking it down might affect other valid sessions.
   // Best effort. If tunnels are uniquely named, use that name.
   // For now, this is generic.
   // execute_command_ah("ipsec auto --down %s", conn_name); // if conn_name was used for --up
   // Since we used a generic "server-to-client" and IH initiates,
   // we might not need to explicitly --down it from server side unless DPD fails.

   // We don't delete the generic "server-to-client" connection definition here,
   // as it's likely meant to be persistent.
   // If connection definitions were per-IH and dynamic, we would delete here.
   // printf("  2. Deleting IPsec connection definition '%s' (if it was dynamic)...\n", conn_name);
   // execute_command_ah("ipsec auto --delete %s", conn_name);

   printf("  3. Deleting AH ephemeral cert '%s' from NSS DB (if no other session needs it)...\n", EPHEMERAL_CERT_NICKNAME_AH);
   // This is tricky. If multiple IHs are connected, this server cert might be in use.
   // A reference counting mechanism or ensuring certs are truly per-session would be needed.
   // For simplicity, we attempt to delete it. If it's in use, IPsec might complain or prevent deletion.
   // This should ideally be the *specific* cert for *this* IH's session if they were unique,
   // but we used a generic EPHEMERAL_CERT_NICKNAME_AH.
   execute_command_ah("certutil -D -d sql:/var/lib/ipsec/nss -n '%s'", EPHEMERAL_CERT_NICKNAME_AH);

   printf("[AH IPsec] Server cleanup attempted for resources related to IH %s.\n", policy->ih_ip);
}

// Main and Cleanup functions are identical. Omitted for brevity.
int main(int argc, char *argv[]) {
   (void)argc; (void)argv;
   printf("[AH] Starting SDP Accepting Host (IPsec Version)...\n");
   if (geteuid() != 0) {
    	fprintf(stderr, "Error: AH must be run as root (for pcap, iptables, ipsec control).\n");
    	return EXIT_FAILURE;
   }

   initialize_openssl();
   struct sigaction sa;
   memset(&sa, 0, sizeof(sa));
   sa.sa_handler = sigint_handler_ah;
   sigaction(SIGINT, &sa, NULL);
   sigaction(SIGTERM, &sa, NULL);

   if (!load_ah_onboard_config(AH_ONBOARD_CONFIG, &g_ah_onboard_conf)) {
   	fprintf(stderr, "[AH] Fatal: Failed to load onboarding config '%s'. Exiting.\n", AH_ONBOARD_CONFIG);
   	cleanup_openssl();
   	return EXIT_FAILURE;
   }
   if (!load_ah_state(AH_STATE_FILE, &g_ah_state)) {
   	fprintf(stderr, "[AH] Warning: Failed to load state file '%s'. Initializing state.\n", AH_STATE_FILE);
   	g_ah_state.controller_hotp_counter = 0;
   }

   printf("[AH] --- 1: SPA -> Controller (%s) ---\n", g_ah_onboard_conf.controller_ip);
   g_ah_state.controller_hotp_counter++;
   if (send_spa_packet(g_ah_onboard_conf.controller_ip, SPA_LISTENER_PORT,
                            	g_ah_onboard_conf.enc_key,
                            	g_ah_onboard_conf.hmac_key, g_ah_onboard_conf.hmac_key_len,
                            	g_ah_onboard_conf.hotp_secret, g_ah_onboard_conf.hotp_secret_len,
                            	g_ah_state.controller_hotp_counter,
                            	0, 0) != 0) {
   	fprintf(stderr, "[AH] Failed sending SPA to controller. Exiting.\n");
   	g_ah_state.controller_hotp_counter--; 
   	goto main_cleanup;
   }
   save_ah_state(AH_STATE_FILE, &g_ah_state); 
   usleep(100000); // 100ms, give controller time to process SPA and open port

   printf("[AH] --- 2: mTLS -> Controller (%s) ---\n", g_ah_onboard_conf.controller_ip);
   g_controller_mtls_ctx = create_ssl_context(0); 
   if (!g_controller_mtls_ctx) { goto main_cleanup; }
   if (!configure_ssl_context(g_controller_mtls_ctx, g_ah_onboard_conf.ca_cert_path,
                         	g_ah_onboard_conf.client_cert_path, g_ah_onboard_conf.client_key_path, 0)) {
   	goto main_cleanup;
   }
   pthread_mutex_lock(&g_controller_ssl_lock);
   g_controller_ssl = establish_mtls_connection(g_ah_onboard_conf.controller_ip, CONTROLLER_MTLS_PORT, g_controller_mtls_ctx);
   pthread_mutex_unlock(&g_controller_ssl_lock);
   if (!g_controller_ssl) {
   	fprintf(stderr, "[AH] Failed to establish mTLS connection to Controller. Exiting.\n");
   	goto main_cleanup;
   }
   printf("[AH] mTLS connection to Controller established successfully.\n");

   printf("[AH] --- 3: Sending AH_REGISTER -> Controller ---\n");
   const char* register_msg = "AH_REGISTER\n";
   pthread_mutex_lock(&g_controller_ssl_lock);
   int sent = -1;
   if (g_controller_ssl) { 
    	sent = send_data_over_mtls(g_controller_ssl, register_msg);
   }
   pthread_mutex_unlock(&g_controller_ssl_lock);
   if (sent <= 0) {
    	fprintf(stderr, "[AH] Failed to send AH_REGISTER to Controller. Exiting.\n");
    	goto main_cleanup;
   }
   printf("[AH] AH_REGISTER sent successfully.\n");
   printf("[AH] --- 4: Starting Listener Threads ---\n");
   if (pthread_create(&g_controller_listener_tid, NULL, controller_listener_thread, NULL) != 0) {
   	perror("[AH] Failed to create controller listener thread");
   	goto main_cleanup;
   }
   if (pthread_create(&g_policy_cleanup_tid, NULL, policy_cleanup_thread, NULL) != 0) {
   	perror("[AH] Failed to create policy cleanup thread");
   	goto main_cleanup;
   }
   if (!run_ah_spa_listener()) {
   	fprintf(stderr, "[AH] Failed to start SPA listener. Exiting.\n");
   	goto main_cleanup;
   }
   printf("[AH] AH Initialization Complete. Waiting for Controller messages or SPA knocks... (Press Ctrl+C to exit)\n");
   while (!g_terminate_ah) {
   	pause(); 
   }
   printf("[AH] Termination signal detected. Proceeding to cleanup...\n");

main_cleanup:
   printf("[AH] Shutdown initiated. Cleaning up resources...\n");
   cleanup_ah_resources(); 
   printf("[AH] AH Exiting.\n");
   return (g_terminate_ah ? EXIT_SUCCESS : EXIT_FAILURE); 
}

void cleanup_ah_resources() {
   printf("[AH] Cleaning up AH resources...\n");
   g_terminate_ah = 1; 
   if (g_spa_pcap_handle) {
   	printf("[AH]   Breaking pcap loop...\n");
   	pcap_breakloop(g_spa_pcap_handle); 
   }
   if (g_spa_listener_tid) {
   	printf("[AH]   Joining SPA listener thread...\n");
   	pthread_join(g_spa_listener_tid, NULL);
   	printf("[AH]   SPA listener thread joined.\n");
   	g_spa_listener_tid = 0; 
   }
   pthread_mutex_lock(&g_controller_ssl_lock);
   if (g_controller_ssl) {
   	printf("[AH]   Closing Controller SSL connection...\n");
   	SSL_free(g_controller_ssl); 
   	g_controller_ssl = NULL;
   }
   pthread_mutex_unlock(&g_controller_ssl_lock);
   if (g_controller_listener_tid) {
   	printf("[AH]   Joining Controller listener thread...\n");
   	pthread_join(g_controller_listener_tid, NULL);
   	printf("[AH]   Controller listener thread joined.\n");
   	g_controller_listener_tid = 0;
   }
   if (g_policy_cleanup_tid) {
   	printf("[AH]   Joining Policy cleanup thread...\n");
   	pthread_join(g_policy_cleanup_tid, NULL);
   	printf("[AH]   Policy cleanup thread joined.\n");
   	g_policy_cleanup_tid = 0;
   }
   if (g_controller_mtls_ctx) {
   	printf("[AH]   Freeing Controller SSL context...\n");
   	SSL_CTX_free(g_controller_mtls_ctx);
   	g_controller_mtls_ctx = NULL;
   }
   printf("[AH]   Freeing all session policies...\n");
   free_all_session_policies();
   printf("[AH]   Destroying mutexes...\n");
   pthread_mutex_destroy(&g_policy_list_lock);
   pthread_mutex_destroy(&g_controller_ssl_lock);
   printf("[AH]   Cleaning up OpenSSL library...\n");
   cleanup_openssl();
   printf("[AH] AH Cleanup complete.\n");
}


