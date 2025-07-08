// spa_server.c
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
#include <signal.h>     // For signal handling
#include <sys/types.h>  // For getifaddrs
#include <sys/socket.h> // For getifaddrs
#include <ifaddrs.h>    // For getifaddrs
#include <unistd.h>     // For geteuid
#include <netdb.h>      // For getnameinfo, gai_strerror

#include "spa_common.h" // Include common definitions

// Global pcap handle for signal handler
pcap_t *pcap_handle = NULL;

void handle_openssl_error_server(const char *msg) {
    fprintf(stderr, "OpenSSL Error (%s): ", msg);
    ERR_print_errors_fp(stderr);
    fprintf(stderr, "\n");
}

// Simple constant time memory comparison
int constant_time_memcmp(const void *a, const void *b, size_t size) {
    const unsigned char *ap = (const unsigned char *)a;
    const unsigned char *bp = (const unsigned char *)b;
    volatile unsigned char result = 0;
    for (size_t i = 0; i < size; ++i) {
        result |= ap[i] ^ bp[i];
    }
    return result != 0;
}

// pcap packet handler callback
void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    const int ETHERNET_HDR_LEN = 14;
    char source_ip_str[INET_ADDRSTRLEN];
    char dest_ip_str[INET_ADDRSTRLEN];
    uint16_t source_port, dest_port; // These are from the UDP header
    struct tm *tm_info;
    char time_buf[30];

    time_t now = time(NULL);
    tm_info = localtime(&now);
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", tm_info);

    printf("\n[%s] Packet received (len %d)\n", time_buf, pkthdr->caplen);

    // --- Basic Packet Parsing ---
    if (pkthdr->caplen < ETHERNET_HDR_LEN) { printf("  -> Discarding: Too short for Ethernet\n"); return; }
    const struct ip *ip_header = (struct ip *)(packet + ETHERNET_HDR_LEN);
    int ip_header_len = ip_header->ip_hl * 4;
    if (pkthdr->caplen < (unsigned int)(ETHERNET_HDR_LEN + ip_header_len)) { printf("  -> Discarding: Too short for IP\n"); return; }
    if (ip_header->ip_p != IPPROTO_UDP) { /* Filtered by pcap, ignore */ return; }
    const struct udphdr *udp_header = (struct udphdr *)((u_char *)ip_header + ip_header_len);
    int udp_header_len = sizeof(struct udphdr);
     if (pkthdr->caplen < (unsigned int)(ETHERNET_HDR_LEN + ip_header_len + udp_header_len)) { printf("  -> Discarding: Too short for UDP\n"); return; }

    inet_ntop(AF_INET, &(ip_header->ip_src), source_ip_str, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), dest_ip_str, INET_ADDRSTRLEN);
    source_port = ntohs(udp_header->source);
    dest_port = ntohs(udp_header->uh_dport); // This is the SPA listener port (e.g., 62201)

    // Log received UDP packet details
    printf("  Source: %s:%u, Destination: %s:%u (SPA Listener Port)\n", source_ip_str, source_port, dest_ip_str, dest_port);

    // Pcap filter should already ensure dest_port == SPA_SERVER_UDP_PORT, no need to check again

    // --- SPA Processing ---
    const u_char *payload = (u_char *)udp_header + udp_header_len;
    int payload_len = pkthdr->caplen - (ETHERNET_HDR_LEN + ip_header_len + udp_header_len);
    printf("  UDP Payload Length: %d bytes\n", payload_len);

    if (payload_len < SPA_PACKET_MIN_LEN || payload_len > SPA_PACKET_MAX_LEN) {
        printf("  -> Discarding: Payload length (%d) outside expected SPA range [%d, %d]\n", payload_len, SPA_PACKET_MIN_LEN, SPA_PACKET_MAX_LEN); return;
    }
    printf("  Payload length OK.\n");

    // --- Extract SPA Components ---
    const unsigned char *iv = payload;
    const unsigned char *encrypted_data = payload + SPA_IV_LEN;
    int encrypted_len = payload_len - SPA_IV_LEN - SPA_HMAC_LEN;
    const unsigned char *received_hmac = payload + SPA_IV_LEN + encrypted_len;

    if (encrypted_len <= 0) { printf("  -> INVALID SPA: Negative/zero encrypted data length (%d).\n", encrypted_len); return; }
    printf("  Parsed SPA: IV[%d], EncryptedData[%d], HMAC[%d]\n", SPA_IV_LEN, encrypted_len, SPA_HMAC_LEN);

    // --- Verify HMAC ---
    printf("  Verifying HMAC... ");
    unsigned char calculated_hmac[EVP_MAX_MD_SIZE];
    unsigned int calculated_hmac_len = 0;
    const EVP_MD *digest = EVP_get_digestbyname(SPA_HMAC_ALGO);
    if (!digest) { fprintf(stderr, "FATAL: HMAC algo '%s' not found!\n", SPA_HMAC_ALGO); return; }
    unsigned char data_to_hmac[SPA_IV_LEN + encrypted_len]; // Combine IV and Ciphertext for HMAC input
    memcpy(data_to_hmac, iv, SPA_IV_LEN);
    memcpy(data_to_hmac + SPA_IV_LEN, encrypted_data, encrypted_len);
    HMAC(digest, SPA_PSK, strlen(SPA_PSK), data_to_hmac, SPA_IV_LEN + encrypted_len, calculated_hmac, &calculated_hmac_len);

    if (calculated_hmac_len != SPA_HMAC_LEN) { fprintf(stderr, "\n  Internal HMAC length error (%u != %d)\n", calculated_hmac_len, SPA_HMAC_LEN); printf("FAILED (Internal)\n"); return; }
    if (constant_time_memcmp(received_hmac, calculated_hmac, SPA_HMAC_LEN) != 0) {
        printf("FAILED (Mismatch)\n"); printf("  -> INVALID SPA Packet: HMAC mismatch.\n"); return;
    }
    printf("OK\n");

    // --- Decrypt Data ---
    printf("  Decrypting data... ");
    unsigned char decrypted_data[sizeof(spa_data_t)];
    int decrypted_len = 0;
    int final_len = 0;
    int decrypt_ok = 1;
    const EVP_CIPHER *cipher = EVP_get_cipherbyname(SPA_ENCRYPTION_ALGO);
    if (!cipher) { fprintf(stderr, "FATAL: Cipher algo '%s' not found!\n", SPA_ENCRYPTION_ALGO); printf("FAILED (Internal)\n"); return; }
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { handle_openssl_error_server("Failed create CTX"); printf("FAILED (Internal)\n"); return; }
    if (1 != EVP_DecryptInit_ex(ctx, cipher, NULL, (const unsigned char*)SPA_PSK, iv)) { handle_openssl_error_server("DecryptInit"); decrypt_ok = 0; }
    if (decrypt_ok && 1 != EVP_DecryptUpdate(ctx, decrypted_data, &decrypted_len, encrypted_data, encrypted_len)) { ERR_clear_error(); decrypt_ok = 0; } // Don't flood logs on bad data
    if (decrypt_ok && 1 != EVP_DecryptFinal_ex(ctx, decrypted_data + decrypted_len, &final_len)) { ERR_clear_error(); decrypt_ok = 0; } // Don't flood logs on bad padding
    EVP_CIPHER_CTX_free(ctx);

    if (!decrypt_ok) { printf("FAILED (Decrypt Error)\n"); printf("  -> INVALID SPA Packet: Decryption failed.\n"); return; }
    decrypted_len += final_len;
    printf("OK (Plaintext size: %d bytes)\n", decrypted_len);

    // --- Validate Decrypted Data ---
    printf("  Validating structure size... ");
    if (decrypted_len != sizeof(spa_data_t)) {
        printf("FAILED\n"); fprintf(stderr, "Decrypted size %d != expected %zu\n", decrypted_len, sizeof(spa_data_t)); printf("  -> INVALID SPA Packet: Size mismatch.\n"); return;
    }
    printf("OK\n");

    spa_data_t *spa_info = (spa_data_t *)decrypted_data;

    printf("  Validating version... ");
    if (spa_info->version != SPA_VERSION) { printf("FAILED (Got %u, Want %d)\n", spa_info->version, SPA_VERSION); printf("  -> INVALID SPA Packet: Version mismatch.\n"); return; }
    printf("OK (Version %d)\n", spa_info->version);

    printf("  Validating timestamp... ");
    time_t current_time = time(NULL);
    int64_t time_diff = (int64_t)current_time - (int64_t)spa_info->timestamp;
    if (llabs(time_diff) > SPA_TIMESTAMP_WINDOW_SECONDS) {
         printf("FAILED\n"); fprintf(stderr, " Time diff %llds > %ds\n", (long long)time_diff, SPA_TIMESTAMP_WINDOW_SECONDS); printf("  -> INVALID SPA Packet: Timestamp invalid.\n"); return;
    }
    printf("OK (Diff %llds)\n", (long long)time_diff);
    printf("  NOTE: Advanced replay detection (nonce caching) is NOT implemented.\n");


    // --- Authorization Action ---
    // *** Extract the TARGET port requested by the client from the payload ***
    uint16_t requested_target_port = ntohs(spa_info->req_port);
    const char* requested_proto_str = protocol_to_string(spa_info->req_protocol);
    const uint16_t duration = SPA_DEFAULT_DURATION_SECONDS; // Use fixed duration

    printf("----------------------------------------\n");
    printf("  VALID SPA Packet Processed!\n");
    printf("  Source IP (Client): %s\n", source_ip_str);
    printf("  Requested Proto:    %s (%d)\n", requested_proto_str, spa_info->req_protocol);
    // *** Log the TARGET port ***
    printf("  Requested Target Port: %u\n", requested_target_port);
    printf("  Access Duration:    %u seconds (Server Defined)\n", duration);
    printf("----------------------------------------\n");

    // --- Generate Firewall Command (Example: iptables) ---
    printf("FIREWALL ACTION (Example - Command NOT executed):\n");
    // *** Use the requested_target_port in the firewall rule ***
    if (requested_target_port > 0 && duration > 0 && strlen(source_ip_str) > 6) {
        printf("  Rule to ADD (Allows initial connection for %d sec):\n", duration);
        printf("  sudo iptables -I INPUT 1 -s %s -p %s --dport %u -m conntrack --ctstate NEW -m comment --comment \"SPA Allow %s:%u (%ds)\" -j ACCEPT\n",
               source_ip_str, requested_proto_str, requested_target_port, /* Target Port */
               source_ip_str, requested_target_port, duration); // Comment for ID

        printf("\n  Rule to REMOVE (after %d seconds):\n", duration);
        printf("  ( sleep %u && sudo iptables -D INPUT -s %s -p %s --dport %u -m conntrack --ctstate NEW -m comment --comment \"SPA Allow %s:%u (%ds)\" -j ACCEPT ) &\n",
               duration, source_ip_str, requested_proto_str, requested_target_port, /* Target Port */
               source_ip_str, requested_target_port, duration); // Match comment

        printf("\n  NOTE: Assumes pre-existing rule: sudo iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n");
    } else {
        printf("  -> Invalid parameters for firewall rule generation (Target Port=%u, Duration=%u)\n", requested_target_port, duration);
    }
    printf("----------------------------------------\n");
}

// Signal handler for graceful shutdown
void cleanup(int signo) {
    printf("\nCaught signal %d, shutting down...\n", signo);
    if (pcap_handle) { pcap_breakloop(pcap_handle); }
}

// Function to get IP address of an interface
int get_interface_ip(const char *interface_name, char *ip_buffer, size_t buffer_len) {
    struct ifaddrs *ifaddr, *ifa;
    int family, s;
    char host[NI_MAXHOST];
    int found = 0;
    if (getifaddrs(&ifaddr) == -1) { perror("getifaddrs"); return -1; }
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) continue;
        family = ifa->ifa_addr->sa_family;
        if (strcmp(ifa->ifa_name, interface_name) == 0 && family == AF_INET) {
            s = getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in), host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
            if (s == 0) {
                strncpy(ip_buffer, host, buffer_len - 1);
                ip_buffer[buffer_len - 1] = '\0'; found = 1; break;
            } else { fprintf(stderr, "getnameinfo() failed: %s\n", gai_strerror(s)); }
        }
    }
    freeifaddrs(ifaddr);
    return found ? 0 : -1;
}

int main(int argc, char *argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];
    char *dev = NULL;
    bpf_u_int32 net, mask;
    struct bpf_program fp;
    char filter_exp[100];
    char server_ip_buf[INET_ADDRSTRLEN] = "N/A";
    int use_strdup = 0;

    if (geteuid() != 0) { fprintf(stderr, "Error: Requires root privileges.\n"); return 1; }

    // Interface selection logic (same as before)
    if (argc > 2 && strcmp(argv[1], "-i") == 0) {
        if (argc > 2) { dev = argv[2]; printf("Using interface specified: %s\n", dev); }
        else { fprintf(stderr, "Error: -i requires an interface name.\n"); return 1; }
    } else if (argc > 1) { fprintf(stderr, "Usage: %s [-i interface_name]\n", argv[0]); return 1; }
    else {
        printf("Attempting find default interface...\n");
        dev = pcap_lookupdev(errbuf);
        if (dev == NULL) {
            fprintf(stderr, "Warning: pcap_lookupdev failed: %s\n", errbuf);
            dev = strdup(SPA_INTERFACE); if (!dev) { perror("strdup"); return 2;}
            use_strdup = 1; printf("Warning: Falling back to '%s'\n", dev);
        } else { printf("Using detected interface: %s\n", dev); }
    }

    if (get_interface_ip(dev, server_ip_buf, sizeof(server_ip_buf)) == 0) {
        printf("Server IP Address on %s: %s\n", dev, server_ip_buf);
    } else { fprintf(stderr, "Warning: Could not get IP for %s.\n", dev); }

    OpenSSL_add_all_algorithms(); ERR_load_crypto_strings();
    if (!EVP_get_cipherbyname(SPA_ENCRYPTION_ALGO)) { fprintf(stderr, "Fatal: Enc algo '%s' not found.\n", SPA_ENCRYPTION_ALGO); if(use_strdup) free(dev); return EXIT_FAILURE; }
    if (!EVP_get_digestbyname(SPA_HMAC_ALGO)) { fprintf(stderr, "Fatal: HMAC algo '%s' not found.\n", SPA_HMAC_ALGO); if(use_strdup) free(dev); return EXIT_FAILURE; }
    printf("Crypto algorithms OK (%s / %s).\n", SPA_ENCRYPTION_ALGO, SPA_HMAC_ALGO);

    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) { fprintf(stderr, "Warning: Couldn't get netmask for %s: %s\n", dev, errbuf); net = 0; mask = 0; }

    pcap_handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (pcap_handle == NULL) { fprintf(stderr, "Fatal: Couldn't open %s: %s\n", dev, errbuf); if(use_strdup) free(dev); return 2; }
    if (pcap_datalink(pcap_handle) != DLT_EN10MB) { fprintf(stderr, "Warning: %s is not Ethernet.\n", dev); }

    // *** The pcap filter ensures we ONLY capture packets destined for the SPA listener port ***
    snprintf(filter_exp, sizeof(filter_exp), "udp dst port %d", SPA_SERVER_UDP_PORT);
    printf("Compiling pcap filter: '%s'\n", filter_exp);
    if (pcap_compile(pcap_handle, &fp, filter_exp, 0, net) == -1) { fprintf(stderr, "Fatal: Filter compile error: %s\n", pcap_geterr(pcap_handle)); pcap_close(pcap_handle); if(use_strdup) free(dev); return 2; }
    if (pcap_setfilter(pcap_handle, &fp) == -1) { fprintf(stderr, "Fatal: Filter set error: %s\n", pcap_geterr(pcap_handle)); pcap_freecode(&fp); pcap_close(pcap_handle); if(use_strdup) free(dev); return 2; }

    printf("SPA Server listening on %s (IP: %s), UDP port %d...\n", dev, server_ip_buf, SPA_SERVER_UDP_PORT);
    printf("Waiting for SPA packets. Press Ctrl+C to shut down.\n");

    signal(SIGINT, cleanup); signal(SIGTERM, cleanup);

    int pcap_ret = pcap_loop(pcap_handle, -1, packet_handler, NULL);
    printf("\nPcap loop terminated.\n");
    if (pcap_ret == -1) { fprintf(stderr, "Pcap loop error: %s\n", pcap_geterr(pcap_handle)); }
    else if (pcap_ret == -2) { printf("Pcap loop broken by signal.\n"); }

    printf("Cleaning up...\n");
    pcap_freecode(&fp);
    if (pcap_handle) { pcap_close(pcap_handle); pcap_handle = NULL; }
    if (use_strdup) { free(dev); dev = NULL; }
    EVP_cleanup(); ERR_free_strings();
    printf("Server shutdown complete.\n");
    return 0;
}