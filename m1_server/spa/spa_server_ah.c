// spa_server_ah.c (AH / Gateway SPA Listener for IHs)
#define _GNU_SOURCE // For asprintf
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/err.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <ifaddrs.h>
#include <unistd.h>
#include <netdb.h>
#include <ctype.h>
#include <pthread.h>
#include <endian.h>
#include <errno.h>
#include <sys/file.h> // Include flock

#include "spa_common.h"
#include "ah_structs.h" // Include AH-specific structs
      
#include <signal.h> // Include signal.h for SIGHUP

    
// --- Configuration ---
#define AH_ACCESS_CONFIG "access_ah.conf" // Ephemeral policies file

// --- Function Prototypes ---
void spa_ah_terminate_handler(int signo);
void sighup_handler(int signo);
int load_ephemeral_policies(const char *filename);
ephemeral_policy_t* find_ephemeral_policy(const char *ip_str); // Locks list, caller must unlock
void free_ephemeral_policies(ephemeral_policy_t *head);
int run_ah_iptables_rule(const char* action, const char* source_ip, uint16_t target_port);
void spa_ah_packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet);
// Assumed external from spa_common.c: get_interface_ip, generate_hotp, handle_openssl_error, etc.

// --- Global Variables ---
pcap_t *spa_ah_pcap_handle = NULL;
ephemeral_policy_t *g_ephemeral_policies = NULL; // Head of ephemeral policies
pthread_mutex_t g_eph_policy_lock = PTHREAD_MUTEX_INITIALIZER; // Lock for list/file access
volatile sig_atomic_t g_reload_config_flag = 0; // Flag for SIGHUP
volatile sig_atomic_t g_terminate_flag = 0;     // Flag for SIGINT/SIGTERM

// --- Config Loading (Reads ephemeral policies) ---
int load_ephemeral_policies(const char *filename) {
    FILE *fp = fopen(filename, "r");
    if (!fp) { if (errno == ENOENT) { printf("[SPA_AH] Ephemeral policy file '%s' not found.\n", filename); return 1; } perror("Open eph policy"); return 0; }
    printf("[SPA_AH] Loading ephemeral policies from: %s\n", filename);
    char line[1024]; int ln=0; int loaded=0; ephemeral_policy_t *curr=NULL, *new_head=NULL; time_t now=time(NULL);
    if (flock(fileno(fp), LOCK_SH) == -1) { perror("Lock policy read"); fclose(fp); return 0; } // Use shared lock for read
    // --- Parsing loop (as provided before) ---
    while (fgets(line, sizeof(line), fp)) {
        ln++; char *t = trim_whitespace(line); if (!t || t[0]=='\0' || t[0]=='#') continue;
        if (t[0]=='[' && t[strlen(t)-1]==']') {
            if(curr){ if(curr->has_enc && curr->has_hmac && curr->has_hotp && curr->has_counter && curr->has_proto && curr->has_port && curr->has_expiry){ if(curr->expiry_timestamp > now){ curr->next=new_head; new_head=curr; loaded++; curr=NULL; } else { /* expired */ } } if(curr){free(curr);curr=NULL;} } // Finalize previous
            curr=malloc(sizeof(ephemeral_policy_t)); if(!curr){perror("malloc policy");flock(fileno(fp),LOCK_UN);fclose(fp);free_ephemeral_policies(new_head);return 0;} memset(curr,0,sizeof(ephemeral_policy_t)); size_t idl=strlen(t)-2; if(idl==0||idl>=INET_ADDRSTRLEN){free(curr);curr=NULL;continue;} strncpy(curr->ih_ip_str,t+1,idl); curr->ih_ip_str[idl]='\0'; struct sockaddr_in sa; if(inet_pton(AF_INET,curr->ih_ip_str,&sa.sin_addr)!=1){free(curr);curr=NULL;continue;} // Start new
        } else if (curr) {
            char *k=t,*v=NULL; for(char*p=k;*p!='\0';++p){if(isspace((unsigned char)*p)||*p=='='){*p='\0';v=p+1;while(*v!='\0'&&(isspace((unsigned char)*v)||*v=='=')){v++;}break;}}
            if(v&&*v!='\0'){ k=trim_whitespace(k); char*cmt=strchr(v,'#');if(cmt)*cmt='\0'; v=trim_whitespace(v); if(strlen(k)==0||strlen(v)==0)continue;
                if(strcasecmp(k,"ENCRYPTION_KEY")==0){int l=hex_string_to_bytes(v,curr->enc_key,MAX_KEY_LEN);if(l>0){curr->enc_key_len=l;curr->has_enc=1;}}
                else if(strcasecmp(k,"HMAC_KEY")==0){int l=hex_string_to_bytes(v,curr->hmac_key,MAX_KEY_LEN);if(l>0){curr->hmac_key_len=l;curr->has_hmac=1;}}
                else if(strcasecmp(k,"HOTP_SECRET")==0){int l=hex_string_to_bytes(v,curr->hotp_secret,MAX_KEY_LEN);if(l>0){curr->hotp_secret_len=l;curr->has_hotp=1;}}
                else if(strcasecmp(k,"HOTP_NEXT_COUNTER")==0){curr->hotp_next_counter=strtoull(v,NULL,10);curr->has_counter=1;}
                else if(strcasecmp(k,"ALLOWED_PROTO")==0){int p=atoi(v);if(p>0&&p<=255){curr->allowed_proto=p;curr->has_proto=1;}}
                else if(strcasecmp(k,"ALLOWED_PORT")==0){int p=atoi(v);if(p>=0&&p<=65535){curr->allowed_port=p;curr->has_port=1;}}
                else if(strcasecmp(k,"EXPIRY_TIMESTAMP")==0){curr->expiry_timestamp=(time_t)strtoul(v,NULL,10);curr->has_expiry=1;}
                else {/* Warn unknown */}
            } else {/* Warn malformed */}
        }
    } // end while
    // Finalize last stanza
    if(curr){ if(curr->has_enc&&curr->has_hmac&&curr->has_hotp&&curr->has_counter&&curr->has_proto&&curr->has_port&&curr->has_expiry){ if(curr->expiry_timestamp>now){curr->next=new_head;new_head=curr;loaded++;} else {free(curr);}} else {free(curr);}}
    flock(fileno(fp), LOCK_UN); fclose(fp);

    // Atomically replace global list
    pthread_mutex_lock(&g_eph_policy_lock);
    g_ephemeral_policies = new_head;            // <<< CORRECTED: Use new_head
    pthread_mutex_unlock(&g_eph_policy_lock);
    printf("[SPA_AH] Finished loading ephemeral policies. %d valid loaded.\n", loaded);
    return 1;
}

// Find ephemeral policy (locks list, caller must unlock)
ephemeral_policy_t* find_ephemeral_policy(const char *ip_str) {
    if (!ip_str) return NULL;
    pthread_mutex_lock(&g_eph_policy_lock);
    ephemeral_policy_t *current = g_ephemeral_policies; ephemeral_policy_t *found = NULL; time_t now = time(NULL);
    while (current != NULL) { if (strcmp(current->ih_ip_str, ip_str) == 0) { if (current->expiry_timestamp > now) { found = current; } break; } current = current->next; }
    if (!found) { pthread_mutex_unlock(&g_eph_policy_lock); } // Unlock if not found
    return found; // Return pointer (caller holds lock if found)
}

// Free policy list (assumes caller holds lock or it's safe)
void free_ephemeral_policies(ephemeral_policy_t *head) {
     ephemeral_policy_t *current = head, *next; while(current){ next = current->next; free(current); current = next;}
}

// Run iptables rule
int run_ah_iptables_rule(const char* action, const char* source_ip, uint16_t target_port) {
     char *cmd = NULL; int ret;
     if (asprintf(&cmd, "sudo iptables %s INPUT -s %s -p tcp --dport %u -m comment --comment \"SPA_AH_ALLOW_%s\" -j ACCEPT", action, source_ip, target_port, source_ip) == -1) { perror("asprintf"); return -1; }
     printf("[SPA_AH] Executing: %s\n", cmd); ret = system(cmd); free(cmd);
     if (ret == -1) { perror("system(iptables)"); return -1;}
     if (WIFEXITED(ret) && WEXITSTATUS(ret) == 0) { printf(" iptables %s OK\n", action); return 0; }
     else { fprintf(stderr," iptables %s FAILED (status %d)\n", action, WEXITSTATUS(ret)); return -1; }
}

// --- Packet Handler (AH Ephemeral SPA) ---
void spa_ah_packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    // ... (Packet parsing logic - unchanged) ...
    const int ETH_HDR_LEN=14; char src_ip[INET_ADDRSTRLEN]; time_t now=time(NULL); (void)user_data; if(pkthdr->caplen<(unsigned int)ETH_HDR_LEN)return; const struct ip*iph=(struct ip*)(packet+ETH_HDR_LEN); int iph_len=iph->ip_hl*4; if(pkthdr->caplen<(unsigned int)(ETH_HDR_LEN+iph_len))return; if(iph->ip_p!=IPPROTO_UDP)return; const struct udphdr*udph=(struct udphdr*)((u_char*)iph+iph_len); int udph_len=sizeof(struct udphdr); if(pkthdr->caplen<(unsigned int)(ETH_HDR_LEN+iph_len+udph_len))return; inet_ntop(AF_INET,&(iph->ip_src),src_ip,sizeof(src_ip)); printf("\n[%lu] AH SPA Rcvd from %s\n",(unsigned long)now,src_ip);

    // --- Find & Lock Policy ---
    ephemeral_policy_t *policy = find_ephemeral_policy(src_ip); // Returns with lock held if found
    if (!policy) { printf(" -> Discard: No valid policy.\n"); return; }
    printf("  Policy found. Validating...\n");

    // --- SPA Processing (HMAC, Decrypt, Payload Validation) ---
    const u_char*payload=(u_char*)udph+udph_len; int payload_len=pkthdr->caplen-(ETH_HDR_LEN+iph_len+udph_len); if((size_t)payload_len<SPA_PACKET_MIN_LEN||(size_t)payload_len>SPA_PACKET_MAX_LEN){printf("->Bad len\n");pthread_mutex_unlock(&g_eph_policy_lock);return;}
    const unsigned char*iv=payload; const unsigned char*enc_data=payload+SPA_IV_LEN; int enc_len=payload_len-SPA_IV_LEN-SPA_HMAC_LEN; const unsigned char*rx_hmac=payload+SPA_IV_LEN+enc_len; if(enc_len<=0){printf("->Bad enc len\n");pthread_mutex_unlock(&g_eph_policy_lock);return;}
    printf("  Verify HMAC..."); unsigned char calc_hmac[EVP_MAX_MD_SIZE];unsigned int calc_len=0; const EVP_MD*d=EVP_get_digestbyname(SPA_HMAC_ALGO); if(!d){pthread_mutex_unlock(&g_eph_policy_lock);return;} unsigned char dh[SPA_IV_LEN+enc_len]; memcpy(dh,iv,SPA_IV_LEN);memcpy(dh+SPA_IV_LEN,enc_data,enc_len); HMAC(d,policy->hmac_key,policy->hmac_key_len,dh,sizeof(dh),calc_hmac,&calc_len); if(calc_len!=SPA_HMAC_LEN||constant_time_memcmp(rx_hmac,calc_hmac,SPA_HMAC_LEN)!=0){printf(" FAILED\n");pthread_mutex_unlock(&g_eph_policy_lock);return;} printf(" OK\n");
    printf("  Decrypting..."); unsigned char dec_data[sizeof(spa_data_t)]; int dec_len=0,fin_len=0;int ok=1; const EVP_CIPHER*c=EVP_get_cipherbyname(SPA_ENCRYPTION_ALGO);if(!c){pthread_mutex_unlock(&g_eph_policy_lock);return;} EVP_CIPHER_CTX*ctx=EVP_CIPHER_CTX_new();if(!ctx){pthread_mutex_unlock(&g_eph_policy_lock);return;} if(1!=EVP_DecryptInit_ex(ctx,c,NULL,policy->enc_key,iv))ok=0; if(ok&&1!=EVP_DecryptUpdate(ctx,dec_data,&dec_len,enc_data,enc_len)){ERR_clear_error();ok=0;} if(ok&&1!=EVP_DecryptFinal_ex(ctx,dec_data+dec_len,&fin_len)){ERR_clear_error();ok=0;} EVP_CIPHER_CTX_free(ctx); if(!ok){printf(" FAILED\n");pthread_mutex_unlock(&g_eph_policy_lock);return;} dec_len+=fin_len; printf(" OK\n");
    if((size_t)dec_len!=sizeof(spa_data_t)){fprintf(stderr,"Bad decrypt size\n");pthread_mutex_unlock(&g_eph_policy_lock);return;} spa_data_t*info=(spa_data_t*)dec_data; uint64_t rx_ts=be64toh(info->timestamp);uint64_t rx_ctr=be64toh(info->hotp_counter);uint32_t rx_code=ntohl(info->hotp_code); uint8_t req_p=info->req_protocol; uint16_t req_port=ntohs(info->req_port);
    if(info->version!=SPA_VERSION){fprintf(stderr,"Bad ver\n");pthread_mutex_unlock(&g_eph_policy_lock);return;} time_t ct=time(NULL);int64_t td=(int64_t)ct-(int64_t)rx_ts;if(llabs(td)>SPA_TIMESTAMP_WINDOW_SECONDS){fprintf(stderr,"Bad ts\n");pthread_mutex_unlock(&g_eph_policy_lock);return;}

    // --- HOTP Validation (Lock still held from find_ephemeral_policy) ---
    printf("  Validate HOTP..."); printf(" Rcv Ctr:%llu Code:%0*u\n",(unsigned long long)rx_ctr,HOTP_CODE_DIGITS,rx_code);
    uint64_t exp_ctr = policy->hotp_next_counter; int hotp_match=0;
    if(rx_ctr<exp_ctr || rx_ctr>exp_ctr+HOTP_COUNTER_SYNC_WINDOW){fprintf(stderr," Ctr out of window\n");} else {for(uint64_t c=rx_ctr;c<=exp_ctr+HOTP_COUNTER_SYNC_WINDOW;++c){uint32_t calc=generate_hotp(policy->hotp_secret,policy->hotp_secret_len,c,HOTP_CODE_DIGITS); if(calc==rx_code){hotp_match=1;policy->hotp_next_counter=c+1;printf(" HOTP MATCH Ctr=%llu! Next=%llu (Save TBD)\n",(unsigned long long)c,policy->hotp_next_counter);/*TODO:Save Counter!*/break;}}}

    // --- Unlock Policy List ---
    pthread_mutex_unlock(&g_eph_policy_lock); // Unlock after use

    if(!hotp_match){fprintf(stderr," HOTP FAILED\n");printf(" -> Discard: Invalid HOTP\n");return;} printf(" HOTP OK.\n");

    // --- Policy Check ---
    if (req_p == policy->allowed_proto && (req_port == policy->allowed_port || policy->allowed_port == 0)) {
        printf("  Policy allows access.\n"); printf("  VALID EPHEMERAL SPA. Authorizing mTLS...\n"); uint16_t ah_mtls_port=AH_MTLS_PORT_DEFAULT; // FIXME
        if (run_ah_iptables_rule("-I", src_ip, ah_mtls_port) == 0) { char *rm_cmd=NULL; if(asprintf(&rm_cmd, "sh -c 'sleep %d && sudo iptables -D INPUT -s %s -p tcp --dport %u -m comment --comment \"SPA_AH_ALLOW_%s\" -j ACCEPT' &", SPA_DEFAULT_DURATION_SECONDS, src_ip, ah_mtls_port, src_ip)!=-1){printf(" Sched cleanup: %s\n", rm_cmd); system(rm_cmd); free(rm_cmd);}} else {fprintf(stderr," iptables ADD fail\n");}
    } else { printf(" POLICY VIOLATION: Req %u/%u Allowed %u/%u.\n",req_p,req_port,policy->allowed_proto,policy->allowed_port); printf(" -> Discard: Denied.\n");}
    printf("----------------------------------------\n");
}

// --- Signal Handlers ---
void sighup_handler(int signo) { (void)signo; g_reload_config_flag = 1; printf("[SPA_AH] SIGHUP received, flagging reload.\n"); signal(SIGHUP, sighup_handler); }
void spa_ah_terminate_handler(int signo) { printf("\n[SPA_AH] Signal %d, setting termination flag...\n", signo); g_terminate_flag = 1; if (spa_ah_pcap_handle) { pcap_breakloop(spa_ah_pcap_handle); } signal(signo, SIG_DFL); }


// --- Main SPA Server Function (AH) ---
int main(int argc, char *argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE]; char *dev = NULL; bpf_u_int32 net=0, mask=0; struct bpf_program fp; char filter_exp[100]; int use_strdup = 0; int pcap_ret = 0;

    if (geteuid() != 0) { fprintf(stderr, "[SPA_AH] Error: Requires root.\n"); return EXIT_FAILURE; }
    printf("[SPA_AH] Starting Ephemeral SPA Listener...\n");
    initialize_openssl();
    if (!load_ephemeral_policies(AH_ACCESS_CONFIG)) { fprintf(stderr, "[SPA_AH] Warning: Error loading initial policies.\n"); }
    signal(SIGHUP, sighup_handler); signal(SIGINT, spa_ah_terminate_handler); signal(SIGTERM, spa_ah_terminate_handler); printf("[SPA_AH] Registered signal handlers.\n");

    // Interface selection
    if (argc > 2 && strcmp(argv[1], "-i") == 0) { if (argc > 2 && argv[2]) { dev = argv[2]; } else { fprintf(stderr, "-i needs interface\n"); goto common_cleanup_main; } } else if (argc > 1) { fprintf(stderr, "Usage: %s [-i interface]\n", argv[0]); goto common_cleanup_main; } else { printf("Finding default interface...\n"); dev = pcap_lookupdev(errbuf); if(!dev){ fprintf(stderr,"Warn: %s\n",errbuf); dev = strdup(SPA_INTERFACE); if (!dev) { perror("strdup"); goto common_cleanup_main;} use_strdup = 1; printf("Warn: Using fallback '%s'\n", dev); }} printf("[SPA_AH] Using interface: %s\n", dev);

    // Crypto Init Check
    if (!EVP_get_cipherbyname(SPA_ENCRYPTION_ALGO) || !EVP_get_digestbyname(SPA_HMAC_ALGO) || !EVP_get_digestbyname(SPA_HOTP_HMAC_ALGO)) { fprintf(stderr, "Fatal crypto algo missing\n"); goto common_cleanup_main; } printf("[SPA_AH] Crypto OK.\n");

    // Pcap Setup
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) { fprintf(stderr,"Warn: No netmask\n"); }
    spa_ah_pcap_handle = pcap_open_live(dev, BUFSIZ, 1, 100, errbuf); if (!spa_ah_pcap_handle) { fprintf(stderr, "Fatal: pcap_open_live: %s\n", errbuf); goto common_cleanup_main; }
    if (pcap_datalink(spa_ah_pcap_handle) != DLT_EN10MB) { /* Warn */ } snprintf(filter_exp, sizeof(filter_exp), "udp dst port %d", SPA_LISTENER_PORT); printf("[SPA_AH] Filter: '%s'\n", filter_exp);
    if (pcap_compile(spa_ah_pcap_handle, &fp, filter_exp, 0, net) == -1) { fprintf(stderr, "Fatal: Compile: %s\n", pcap_geterr(spa_ah_pcap_handle)); pcap_close(spa_ah_pcap_handle); spa_ah_pcap_handle=NULL; goto common_cleanup_main; }
    if (pcap_setfilter(spa_ah_pcap_handle, &fp) == -1) { fprintf(stderr, "Fatal: Set filter: %s\n", pcap_geterr(spa_ah_pcap_handle)); pcap_freecode(&fp); pcap_close(spa_ah_pcap_handle); spa_ah_pcap_handle=NULL; goto common_cleanup_main; }
    pcap_freecode(&fp); // Free compiled filter after setting

    printf("[SPA_AH] Listening... Ctrl+C to exit.\n");

    // Modified Pcap Loop
    while(!g_terminate_flag) {
        if (g_reload_config_flag) { printf("Reloading policies...\n"); load_ephemeral_policies(AH_ACCESS_CONFIG); g_reload_config_flag = 0; }
        pcap_ret = pcap_dispatch(spa_ah_pcap_handle, 10, spa_ah_packet_handler, NULL); // Process multiple packets
        if (pcap_ret < 0) { if(g_terminate_flag) printf("pcap broken by signal.\n"); else fprintf(stderr, "pcap_dispatch error: %s\n", pcap_geterr(spa_ah_pcap_handle)); break; }
        // If pcap_ret == 0, timeout occurred, loop continues to check flags
        // If pcap_ret > 0, packets processed, loop continues
    }

    printf("\n[SPA_AH] Pcap loop ended.\n");

common_cleanup_main:
    printf("[SPA_AH] Cleaning up...\n"); if (spa_ah_pcap_handle) { pcap_close(spa_ah_pcap_handle); spa_ah_pcap_handle = NULL; } if (use_strdup) { free(dev); dev = NULL; }
    pthread_mutex_lock(&g_eph_policy_lock); free_ephemeral_policies(g_ephemeral_policies); g_ephemeral_policies = NULL; pthread_mutex_unlock(&g_eph_policy_lock); pthread_mutex_destroy(&g_eph_policy_lock);
    cleanup_openssl(); printf("[SPA_AH] Shutdown complete.\n"); return (g_terminate_flag) ? EXIT_SUCCESS : EXIT_FAILURE;
}