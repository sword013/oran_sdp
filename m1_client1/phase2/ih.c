// ih.c - Initiating Host Orchestrator (IPsec Version - OPTIMIZED)
#define _GNU_SOURCE // For asprintf
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <sys/stat.h>   // For chmod
#include <time.h>
#include <stdarg.h>
#include <ctype.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/pkcs12.h> // For PKCS12 creation (optional future optimization)
#include <openssl/pem.h>    // For PKCS12 creation (optional future optimization)


#include "spa_common.h"

// --- Configuration & State Files ---
#define IH_STATE_FILE "ih_state.dat"
#define IH_ONBOARD_CONFIG "client_onboard.conf"
#define MAX_CONTROLLER_RESPONSE 8192
#define EPH_KEY_FILE_PATH "/tmp/ih_eph.key"
#define EPH_CERT_FILE_PATH "/tmp/ih_eph.crt"
#define EPH_P12_FILE_PATH "/tmp/ih_eph.p12"
#define EPHEMERAL_CERT_NICKNAME "client"
#define CA_NICKNAME "MyCA"

// --- Structs ---
typedef struct {
 char controller_ip[INET_ADDRSTRLEN];
 unsigned char enc_key[MAX_KEY_LEN]; size_t enc_key_len;
 unsigned char hmac_key[MAX_KEY_LEN]; size_t hmac_key_len;
 unsigned char hotp_secret[MAX_KEY_LEN]; size_t hotp_secret_len;
 char ca_cert_path[256]; char client_cert_path[256]; char client_key_path[256];
 int has_enc, has_hmac, has_hotp, has_ca, has_cert, has_key;
} onboarding_config_t;

typedef struct {
 char ah_ip[INET_ADDRSTRLEN];
 unsigned char spa_enc_key[MAX_KEY_LEN]; size_t spa_enc_key_len;
 unsigned char spa_hmac_key[MAX_KEY_LEN]; size_t spa_hmac_key_len;
 unsigned char hotp_secret[MAX_KEY_LEN]; size_t hotp_secret_len;
 char ih_eph_cert_path[256]; char ih_eph_key_path[256];
 int has_ah_ip, has_spa_enc, has_spa_hmac, has_hotp, has_ih_cert, has_ih_key;
} ephemeral_data_t;

typedef struct {
 uint64_t controller_hotp_counter; uint64_t ah_hotp_counter;
} ih_state_t;

// --- Globals ---
volatile sig_atomic_t g_terminate = 0;
onboarding_config_t g_onboard_conf;
ephemeral_data_t g_ephemeral_data;
ih_state_t g_ih_state;
char g_target_ah_ip_cmd[INET_ADDRSTRLEN];
uint8_t g_target_proto_num = 0;
uint16_t g_target_port_num = 0;
int g_ipsec_active = 0;

// --- Function Prototypes ---
void sigint_handler(int signo);
int load_onboarding_config(const char* filename, onboarding_config_t *conf);
int load_ih_state(const char* filename, ih_state_t *state);
int save_ih_state(const char* filename, const ih_state_t *state);
int execute_command(const char* command_format, ...);
int parse_controller_response(char* response, ephemeral_data_t* eph_data);
void cleanup_resources();
const char* find_pem_start(const char* buffer, const char* key_marker);
int save_pem_to_file(const char* pem_start, const char* end_marker, const char* filename, mode_t mode);
int setup_ipsec_client();
void cleanup_ipsec_client();

// --- Assumed external from spa_common.c ---
// (Prototypes are in spa_common.h)

// --- Signal Handler ---
void sigint_handler(int signo) {
  if (g_terminate == 0) {
       g_terminate = 1;
       printf("\n[IH] Signal %d received, initiating shutdown...\n", signo);
  }
}

// --- Config/State/Execute/PEM Helpers ---
// load_onboarding_config, load_ih_state, save_ih_state, find_pem_start, save_pem_to_file
// are identical to your provided version.
// For brevity, I'll omit them here, assuming they are correct.
// Make sure to re-paste them if you're replacing the whole file.
int load_onboarding_config(const char* filename, onboarding_config_t *conf) {
  FILE *fp = fopen(filename, "r");
  if (!fp) {
       perror("[IH] Error opening onboard config");
       fprintf(stderr,"[IH] Could not open: %s\n", filename);
       return 0;
  }
  printf("[IH] Loading onboard config: %s\n", filename);
  memset(conf, 0, sizeof(onboarding_config_t));
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
                   fprintf(stderr, "[IH] Error: Invalid Controller IP '%s' in header line %d\n", controller_ip_from_file, line_num);
                   fclose(fp);
                   return 0;
               }
               strncpy(conf->controller_ip, controller_ip_from_file, sizeof(conf->controller_ip) - 1);
               conf->controller_ip[sizeof(conf->controller_ip) - 1] = '\0';
               in_stanza = 1;
               printf("[IH] Found config stanza for Controller IP: %s\n", conf->controller_ip);
           } else {
               fprintf(stderr, "[IH] Error: Invalid stanza header format line %d\n", line_num);
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
                   else { fprintf(stderr, "[IH] Error: Invalid ENCRYPTION_KEY format line %d\n", line_num); fclose(fp); return 0; }
               } else if (strcasecmp(k, "HMAC_KEY") == 0) {
                   int l = hex_string_to_bytes(v, conf->hmac_key, MAX_KEY_LEN);
                   if (l > 0) { conf->hmac_key_len = l; conf->has_hmac = 1; }
                   else { fprintf(stderr, "[IH] Error: Invalid HMAC_KEY format line %d\n", line_num); fclose(fp); return 0; }
               } else if (strcasecmp(k, "HOTP_SECRET") == 0) {
                   int l = hex_string_to_bytes(v, conf->hotp_secret, MAX_KEY_LEN);
                   if (l > 0) { conf->hotp_secret_len = l; conf->has_hotp = 1; }
                   else { fprintf(stderr, "[IH] Error: Invalid HOTP_SECRET format line %d\n", line_num); fclose(fp); return 0; }
               } else if (strcasecmp(k, "CA_CERT_PATH") == 0) {
                   strncpy(conf->ca_cert_path, v, sizeof(conf->ca_cert_path) - 1); conf->has_ca = 1;
               } else if (strcasecmp(k, "CLIENT_CERT_PATH") == 0) {
                   strncpy(conf->client_cert_path, v, sizeof(conf->client_cert_path) - 1); conf->has_cert = 1;
               } else if (strcasecmp(k, "CLIENT_KEY_PATH") == 0) {
                   strncpy(conf->client_key_path, v, sizeof(conf->client_key_path) - 1); conf->has_key = 1;
               } else {
                   fprintf(stderr, "[IH] Warn: Unknown key '%s' in config line %d\n", k, line_num);
               }
           }
      }
  }
  fclose(fp);
  if (!conf->has_enc || !conf->has_hmac || !conf->has_hotp || !conf->has_ca || !conf->has_cert || !conf->has_key || strlen(conf->controller_ip) == 0) {
      fprintf(stderr, "[IH] Error: Missing required fields in %s\n", filename);
      return 0;
  }
  printf("[IH] Onboarding config loaded successfully.\n");
  return 1;
}

int load_ih_state(const char* filename, ih_state_t *state) {
  FILE *fp = fopen(filename, "rb");
  if (!fp) {
      printf("[IH] State file '%s' not found, initializing counters to 0.\n", filename);
      state->controller_hotp_counter = 0;
      state->ah_hotp_counter = 0;
      return 1; 
  }
  if (fread(state, sizeof(ih_state_t), 1, fp) != 1) {
      perror("[IH] Error reading state file");
      fclose(fp);
      state->controller_hotp_counter = 0;
      state->ah_hotp_counter = 0;
      return 0; 
  }
  fclose(fp);
  printf("[IH] Loaded state: Controller Counter=%llu, AH Counter=%llu\n", (unsigned long long)state->controller_hotp_counter, (unsigned long long)state->ah_hotp_counter);
  return 1;
}

int save_ih_state(const char* filename, const ih_state_t *state) {
  FILE *fp = fopen(filename, "wb");
  if (!fp) {
      perror("[IH] Error opening state file for writing");
      return 0;
  }
  if (fwrite(state, sizeof(ih_state_t), 1, fp) != 1) {
      perror("[IH] Error writing state file");
      fclose(fp);
      return 0;
  }
  fclose(fp);
  printf("[IH] Saved state: Controller Counter=%llu, AH Counter=%llu\n", (unsigned long long)state->controller_hotp_counter, (unsigned long long)state->ah_hotp_counter);
  return 1;
}

int execute_command(const char* command_format, ...) {
  va_list args;
  char *command = NULL;
  int sys_ret = -1, exit_status = -1;
  va_start(args, command_format);
  if (vasprintf(&command, command_format, args) == -1) {
      perror("[IH] vasprintf");
      va_end(args);
      return -1;
  }
  va_end(args);

  printf("[IH] Executing: %s\n", command);
  sys_ret = system(command);

  if (sys_ret == -1) {
      perror("[IH] system() failed");
      exit_status = -1;
  } else {
      if (WIFEXITED(sys_ret)) {
          exit_status = WEXITSTATUS(sys_ret);
      } else if (WIFSIGNALED(sys_ret)) {
          fprintf(stderr, "[IH] Command killed signal: %d\n", WTERMSIG(sys_ret));
          exit_status = -2;
      } else {
          fprintf(stderr, "[IH] Command terminated abnormally\n");
          exit_status = -3;
      }
  }
  free(command);
  return exit_status;
}

const char* find_pem_start(const char* buffer, const char* key_marker) {
  if (!buffer || !key_marker) return NULL;
  const char* key_ptr = strstr(buffer, key_marker);
  if (!key_ptr) return NULL;
  const char* value_start = strchr(key_ptr, ':');
  if (!value_start) return NULL;
  value_start++; 
  return strstr(value_start, "-----BEGIN");
}

int save_pem_to_file(const char* pem_start, const char* end_marker, const char* filename, mode_t mode) {
  if (!pem_start || !end_marker || !filename) return 0;

  const char* pem_end = strstr(pem_start, end_marker);
  if (!pem_end) {
      fprintf(stderr, "[IH] Error: PEM end marker '%s' not found for %s\n", end_marker, filename);
      return 0;
  }
  pem_end += strlen(end_marker); 

  while (*pem_end == '\r' || *pem_end == '\n' || isspace((unsigned char)*pem_end)) {
      pem_end++;
  }

  size_t pem_len = pem_end - pem_start;
  if (pem_len == 0) {
      fprintf(stderr, "[IH] Error: Zero length PEM data found for %s\n", filename);
      return 0;
  }

  FILE* fp = fopen(filename, "w");
  if (!fp) {
      perror("[IH] fopen PEM");
      return 0;
  }

  if (fwrite(pem_start, 1, pem_len, fp) != pem_len) {
      perror("[IH] fwrite PEM");
      fclose(fp);
      remove(filename); 
      return 0;
  }
  fclose(fp);

  if (chmod(filename, mode) == -1) {
      perror("[IH] chmod PEM");
  }
  printf("[IH]   Saved PEM data to %s (%zu bytes)\n", filename, pem_len);
  return 1;
}

// --- Controller Response Parsing ---
// (Identical to your provided version - good parsing logic)
// For brevity, I'll omit it here.
int parse_controller_response(char* response_orig, ephemeral_data_t* eph_data) {
  printf("[IH] Parsing controller response...\n");
  memset(eph_data, 0, sizeof(ephemeral_data_t));

  snprintf(eph_data->ih_eph_cert_path, sizeof(eph_data->ih_eph_cert_path), EPH_CERT_FILE_PATH);
  snprintf(eph_data->ih_eph_key_path, sizeof(eph_data->ih_eph_key_path), EPH_KEY_FILE_PATH);

  char *current_line = response_orig;
  char *next_line = NULL;
  printf("[IH] Parsing Key:Value pairs...\n");
  while (current_line != NULL && *current_line != '\0') {
      next_line = strchr(current_line, '\n');
      size_t line_len;
      if (next_line) {
          line_len = next_line - current_line;
          *next_line = '\0'; 
      } else {
          line_len = strlen(current_line); 
      }

      if (strncmp(current_line, "-----BEGIN", 10) != 0 && strncmp(current_line,"END_RESPONSE", 12) != 0) {
          char *line_copy = strndup(current_line, line_len);
          if (!line_copy) {
              if(next_line) *next_line = '\n'; 
              return 0; 
          }

          char *key = line_copy;
          char *value = strchr(key, ':');

          if (value) {
               *value = '\0'; 
               value++;       
               key = trim_whitespace(key);
               value = trim_whitespace(value);

               if (strlen(key) > 0 && strlen(value) > 0) {
                   printf("  Found Key: '%s', Value: '%s'\n", key, value); 
                   if (strcasecmp(key, "AH_IP") == 0) {
                       strncpy(eph_data->ah_ip, value, sizeof(eph_data->ah_ip) - 1);
                       eph_data->ah_ip[sizeof(eph_data->ah_ip) - 1] = '\0'; 
                       eph_data->has_ah_ip = 1;
                   }
                    else if (strcasecmp(key, "EPH_SPA_ENC_KEY") == 0) {
                       int l = hex_string_to_bytes(value, eph_data->spa_enc_key, MAX_KEY_LEN);
                       if (l > 0) { eph_data->spa_enc_key_len = l; eph_data->has_spa_enc = 1; }
                       else { fprintf(stderr, "[IH] Invalid EPH_SPA_ENC_KEY format\n"); } 
                   } else if (strcasecmp(key, "EPH_SPA_HMAC_KEY") == 0) {
                       int l = hex_string_to_bytes(value, eph_data->spa_hmac_key, MAX_KEY_LEN);
                       if (l > 0) { eph_data->spa_hmac_key_len = l; eph_data->has_spa_hmac = 1; }
                       else { fprintf(stderr, "[IH] Invalid EPH_SPA_HMAC_KEY format\n"); } 
                   } else if (strcasecmp(key, "EPH_HOTP_SECRET") == 0) {
                       int l = hex_string_to_bytes(value, eph_data->hotp_secret, MAX_KEY_LEN);
                       if (l > 0) { eph_data->hotp_secret_len = l; eph_data->has_hotp = 1; }
                       else { fprintf(stderr, "[IH] Invalid EPH_HOTP_SECRET format\n"); } 
                   }
                    else { fprintf(stderr, "[IH] Unknown key: %s\n", key); } 
               }
          }
          free(line_copy); 
      }

      if (next_line) {
          *next_line = '\n';
          current_line = next_line + 1;
      } else {
          current_line = NULL; 
      }
  }

  printf("[IH] Extracting PEM data...\n");
  const char *pem_ih_cert = find_pem_start(response_orig, "IH_EPH_CERT:");
  if (pem_ih_cert && save_pem_to_file(pem_ih_cert, "-----END CERTIFICATE-----", eph_data->ih_eph_cert_path, 0644)) {
      eph_data->has_ih_cert = 1;
  } else {
      fprintf(stderr, "[IH] Failed to find or save IH_EPH_CERT\n");
      eph_data->has_ih_cert = 0;
  }

  const char *pem_ih_key = find_pem_start(response_orig, "IH_EPH_KEY:");
  if (pem_ih_key && save_pem_to_file(pem_ih_key, "-----END PRIVATE KEY-----", eph_data->ih_eph_key_path, 0600)) {
      eph_data->has_ih_key = 1;
  } else {
      fprintf(stderr, "[IH] Failed to find or save IH_EPH_KEY\n");
      eph_data->has_ih_key = 0;
  }

  if (!eph_data->has_ah_ip || !eph_data->has_spa_enc || !eph_data->has_spa_hmac || !eph_data->has_hotp || !eph_data->has_ih_cert || !eph_data->has_ih_key) {
      fprintf(stderr, "[IH] Error: Incomplete ephemeral credentials received.\n Check Flags: IP=%d ENC=%d HMAC=%d HOTP=%d IHCert=%d IHKey=%d\n",
              eph_data->has_ah_ip, eph_data->has_spa_enc, eph_data->has_spa_hmac,
              eph_data->has_hotp, eph_data->has_ih_cert, eph_data->has_ih_key);
      if (eph_data->has_ih_cert) remove(eph_data->ih_eph_cert_path);
      if (eph_data->has_ih_key) remove(eph_data->ih_eph_key_path);
      return 0; 
  }

  if (strcmp(g_target_ah_ip_cmd, eph_data->ah_ip) != 0) {
       fprintf(stderr, "[IH] FATAL ERROR: Target AH IP from command line (%s) does not match AH IP received from Controller (%s)!\n",
               g_target_ah_ip_cmd, eph_data->ah_ip);
        remove(eph_data->ih_eph_cert_path);
        remove(eph_data->ih_eph_key_path);
        return 0; 
  }

  printf("[IH] Successfully parsed ephemeral credentials. Target AH IP (from Controller): %s\n", eph_data->ah_ip);
  return 1; 
}


// --- IPsec Client Setup ---
int setup_ipsec_client() {
  printf("[IH] Setting up IPsec client connection...\n");
  int ret;

  // Commands will be executed as root since ih_app is run as root.
  // Removed "sudo " prefix from commands.

  printf("  1. Creating PKCS12 bundle...\n");
  // Note: openssl command does not need sudo if ih_app is root and has write perms to /tmp
  ret = execute_command("openssl pkcs12 -export -in %s -inkey %s -certfile %s -name \"%s\" -out %s -passout pass:",
           g_ephemeral_data.ih_eph_cert_path, g_ephemeral_data.ih_eph_key_path, g_onboard_conf.ca_cert_path, EPHEMERAL_CERT_NICKNAME, EPH_P12_FILE_PATH);
  if (ret != 0) {
      fprintf(stderr, "[IH] Failed PKCS12 bundle (ret:%d).\n", ret);
      return 0;
  }

  printf("  2. Importing CA certificate to NSS DB...\n");
  ret = execute_command("certutil -A -d sql:/var/lib/ipsec/nss -n \"%s\" -t \"CT,,\" -a -i %s",
           CA_NICKNAME, g_onboard_conf.ca_cert_path);
  if (ret != 0 && ret != 255) { // Allow 255 (already exists)
      fprintf(stderr, "[IH] Failed import CA cert (ret:%d).\n", ret);
      // return 0; // Decide if fatal
  }

  printf("  3. Importing client certificate bundle to NSS DB...\n");
  ret = execute_command("pk12util -i %s -d sql:/var/lib/ipsec/nss/ -n \"%s\" -W ''",
           EPH_P12_FILE_PATH, EPHEMERAL_CERT_NICKNAME);
  if (ret != 0) {
      fprintf(stderr, "[IH] Warning: pk12util import failed/exists (ret:%d).\n", ret);
  }

  printf("  4. Verifying certificates in NSS DB...\n");
  execute_command("certutil -L -d sql:/var/lib/ipsec/nss");

  printf("  5. Adding IPsec connection definition 'client-to-server'...\n");
  ret = execute_command("ipsec auto --add client-to-server");
  if (ret != 0) {
     fprintf(stderr, "[IH] Warning: 'ipsec auto --add' failed (ret:%d), maybe already added?\n", ret);
  }

  printf("[IH] IPsec client setup commands executed.\n");
  return 1;
}

// --- IPsec Client Cleanup ---
void cleanup_ipsec_client() {
  printf("[IH] Cleaning up IPsec client connection...\n");

  // Commands will be executed as root. Removed "sudo " prefix.
  if (g_ipsec_active) {
      printf("  1. Taking IPsec connection down...\n");
      execute_command("ipsec auto --down client-to-server");
      g_ipsec_active = 0;
  }

  printf("  2. Deleting IPsec connection definition...\n");
  execute_command("ipsec auto --delete client-to-server");

  printf("  3. Deleting ephemeral cert '%s' from NSS DB...\n", EPHEMERAL_CERT_NICKNAME);
  execute_command("certutil -D -d sql:/var/lib/ipsec/nss -n '%s'", EPHEMERAL_CERT_NICKNAME);

  printf("  5. Removing temporary files...\n");
  remove(EPH_P12_FILE_PATH);
  remove(EPH_CERT_FILE_PATH);
  remove(EPH_KEY_FILE_PATH);

  printf("[IH] IPsec client cleanup complete.\n");
}

// --- Resource Cleanup ---
void cleanup_resources(){
  printf("[IH] Cleaning up resources (Post-IPsec Cleanup)...\n");
  remove(EPH_CERT_FILE_PATH);
  remove(EPH_KEY_FILE_PATH);
  remove(EPH_P12_FILE_PATH);
  printf("[IH] Resource cleanup finished.\n");
}

// --- Main Orchestration ---
int main(int argc, char *argv[]) {
  if (geteuid() != 0) {
      fprintf(stderr, "[IH] Error: This application must be run as root.\n");
      return EXIT_FAILURE;
  }

  if (argc != 4) {
      fprintf(stderr, "Usage: %s <target_ah_ip> <service_proto> <service_port>\n", argv[0]);
      fprintf(stderr, "  Example: %s 10.9.65.55 sctp 38472\n", argv[0]);
      return EXIT_FAILURE;
  }
  strncpy(g_target_ah_ip_cmd, argv[1], sizeof(g_target_ah_ip_cmd) - 1);
  g_target_ah_ip_cmd[sizeof(g_target_ah_ip_cmd) - 1] = '\0';
  const char* req_proto_str = argv[2];
  g_target_port_num = (uint16_t)atoi(argv[3]);

  int tpni = string_to_protocol(req_proto_str);
  if (tpni < 0) { tpni = atoi(req_proto_str); }
  if (tpni <= 0 || tpni > 255) {
      fprintf(stderr,"[IH] Error: Invalid protocol '%s'\n", req_proto_str);
      return EXIT_FAILURE;
  }
  g_target_proto_num = (uint8_t)tpni;

  if (g_target_port_num == 0 && strcmp(argv[3], "0") != 0) {
       fprintf(stderr,"[IH] Error: Invalid port '%s'\n", argv[3]);
       return EXIT_FAILURE;
  }

  char target_service_id_str[64];
  snprintf(target_service_id_str, sizeof(target_service_id_str), "%s/%u", req_proto_str, g_target_port_num);

  SSL_CTX *ctl_ctx = NULL;
  SSL *ctl_ssl = NULL;
  int main_ret = EXIT_FAILURE;

  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = sigint_handler;
  sigaction(SIGINT, &sa, NULL);
  sigaction(SIGTERM, &sa, NULL);

  initialize_openssl();

  if (!load_onboarding_config(IH_ONBOARD_CONFIG, &g_onboard_conf)) {
      fprintf(stderr, "[IH] Fatal: Failed to load onboarding config '%s'.\n", IH_ONBOARD_CONFIG);
      goto main_cleanup;
  }
  if (!load_ih_state(IH_STATE_FILE, &g_ih_state)) {
      fprintf(stderr, "[IH] Warning: Failed to load state file '%s', starting counters at 0.\n", IH_STATE_FILE);
  }

  printf("\n--- [IH] 1: SPA -> Controller (%s) ---\n", g_onboard_conf.controller_ip);
  g_ih_state.controller_hotp_counter++;
  if (send_spa_packet(g_onboard_conf.controller_ip, SPA_LISTENER_PORT,
                               g_onboard_conf.enc_key,
                               g_onboard_conf.hmac_key, g_onboard_conf.hmac_key_len,
                               g_onboard_conf.hotp_secret, g_onboard_conf.hotp_secret_len,
                               g_ih_state.controller_hotp_counter,
                               0, 0) != 0) {
      fprintf(stderr, "[IH] Failed sending SPA to controller.\n");
      g_ih_state.controller_hotp_counter--;
      goto main_cleanup;
  }
  save_ih_state(IH_STATE_FILE, &g_ih_state);
  // Consider a very short sleep if the first SYN still gets lost, e.g. usleep(50000) for 50ms
  // This gives iptables a moment to update IF `system("iptables")` is still a bottleneck.
  usleep(0); // 50ms, uncomment if TCP SYN to controller is still lost

  printf("\n--- [IH] 2: mTLS -> Controller (%s) ---\n", g_onboard_conf.controller_ip);
  ctl_ctx = create_ssl_context(0);
  if (!ctl_ctx) { goto main_cleanup; }
  if (!configure_ssl_context(ctl_ctx, g_onboard_conf.ca_cert_path, g_onboard_conf.client_cert_path, g_onboard_conf.client_key_path, 0)) {
      goto main_cleanup;
  }
  ctl_ssl = establish_mtls_connection(g_onboard_conf.controller_ip, CONTROLLER_MTLS_PORT, ctl_ctx);
  if (!ctl_ssl) {
      goto main_cleanup;
  }

  printf("\n--- [IH] 3: AuthReq -> Controller (TargetAH=%s, Service=%s) ---\n", g_target_ah_ip_cmd, target_service_id_str);
  char req_buffer[256];
  snprintf(req_buffer, sizeof(req_buffer), "AUTH_REQ:TARGET_IP=%s:SERVICE=%s\n", g_target_ah_ip_cmd, target_service_id_str);
  if (send_data_over_mtls(ctl_ssl, req_buffer) <= 0) {
      goto main_cleanup;
  }

  printf("\n--- [IH] 4: RecvCreds <- Controller ---\n");
  char resp_buffer[MAX_CONTROLLER_RESPONSE];
  int bytes_read = SSL_read(ctl_ssl, resp_buffer, sizeof(resp_buffer) - 1);
  if (bytes_read <= 0) {
      handle_openssl_error("[IH] Reading response");
      goto main_cleanup;
  }
  resp_buffer[bytes_read] = '\0';
  printf("[IH] Received %d bytes from controller. Parsing...\n", bytes_read);

  SSL_shutdown(ctl_ssl); SSL_free(ctl_ssl); ctl_ssl = NULL;
  SSL_CTX_free(ctl_ctx); ctl_ctx = NULL;

  if (!parse_controller_response(resp_buffer, &g_ephemeral_data)) {
      goto main_cleanup_ipsec;
  }
  g_ih_state.ah_hotp_counter = 0;
  save_ih_state(IH_STATE_FILE, &g_ih_state);

  printf("\n--- [IH] 5: Setting up Local IPsec ---\n");
  if (!setup_ipsec_client()) {
      fprintf(stderr, "[IH] Failed during IPsec client setup.\n");
      goto main_cleanup_ipsec;
  }

  printf("\n--- [IH] 6: SPA -> AH (%s) for Service %s/%d ---\n", g_ephemeral_data.ah_ip, req_proto_str, g_target_port_num);
  g_ih_state.ah_hotp_counter++;
  if (send_spa_packet(g_ephemeral_data.ah_ip, SPA_LISTENER_PORT,
                               g_ephemeral_data.spa_enc_key,
                               g_ephemeral_data.spa_hmac_key, g_ephemeral_data.spa_hmac_key_len,
                               g_ephemeral_data.hotp_secret, g_ephemeral_data.hotp_secret_len,
                               g_ih_state.ah_hotp_counter,
                               g_target_proto_num, g_target_port_num) != 0) {
      fprintf(stderr, "[IH] Failed sending SPA to AH.\n");
      g_ih_state.ah_hotp_counter--;
      save_ih_state(IH_STATE_FILE, &g_ih_state);
      goto main_cleanup_ipsec;
  }
  save_ih_state(IH_STATE_FILE, &g_ih_state);
  usleep(0); // 50ms, uncomment if TCP SYN to AH (IPsec IKE) is lost

  printf("\n--- [IH] 7: Initiating IPsec Tunnel 'client-to-server' to AH %s ---\n", g_ephemeral_data.ah_ip);
  int ipsec_up_ret = execute_command("ipsec auto --up client-to-server");
  if (ipsec_up_ret != 0) {
      fprintf(stderr, "[IH] Failed ipsec --up (ret:%d). Check system IPsec logs.\n", ipsec_up_ret);
      g_ipsec_active = 0;
      goto main_cleanup_ipsec;
  }
  else {
      printf("[IH] IPsec tunnel initiated successfully (check 'ipsec status').\n");
      g_ipsec_active = 1;
  }

  printf("\n--- [IH] 8: IPsec configured. Ready for application traffic. ---\n");
  printf(">>> Application should now connect to %s (port %u or others via IPsec) <<<\n", g_target_ah_ip_cmd, g_target_port_num);
  printf("[IH] Waiting for termination signal (Ctrl+C) to clean up...\n");

  main_ret = EXIT_SUCCESS;

  while (!g_terminate) {
      pause();
  }
  printf("[IH] Termination signal received. Proceeding to cleanup...\n");

main_cleanup_ipsec:
  printf("[IH] Main cleanup sequence initiated (including IPsec)...\n");
  cleanup_ipsec_client();

main_cleanup:
  printf("[IH] General resource cleanup initiated...\n");
  cleanup_resources();

  if (ctl_ssl) { SSL_shutdown(ctl_ssl); SSL_free(ctl_ssl); }
  if (ctl_ctx) { SSL_CTX_free(ctl_ctx); }

  cleanup_openssl();
  printf("[IH] Application Finished. Exit code: %d\n", main_ret);
  return main_ret;
}

