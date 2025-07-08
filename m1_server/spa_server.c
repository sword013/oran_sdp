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
#include <signal.h> // For signal handling

#include "spa_common.h" // Include common definitions

// Global pcap handle for signal handler
pcap_t *pcap_handle = NULL;

void handle_openssl_error_server(const char *msg) {
    fprintf(stderr, "OpenSSL Error (%s): ", msg);
    ERR_print_errors_fp(stderr);
    fprintf(stderr, "\n");
    // Don't exit in server, just log
}

// Simple constant time memory comparison
int constant_time_memcmp(const void *a, const void *b, size_t size) {
    const unsigned char *ap = a;
    const unsigned char *bp = b;
    volatile unsigned char result = 0;
    for (size_t i = 0; i < size; ++i) {
        result |= ap[i] ^ bp[i];
    }
    return result != 0; // Return 0 if equal, non-zero if different
}


// pcap packet handler callback
void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    // Assume Ethernet header for simplicity
    const int ETHERNET_HDR_LEN = 14;
    if (pkthdr->caplen < ETHERNET_HDR_LEN) {
        fprintf(stderr, "Packet too short for Ethernet header\n");
        return;
    }

    // IP Header
    const struct ip *ip_header = (struct ip *)(packet + ETHERNET_HDR_LEN);
    int ip_header_len = ip_header->ip_hl * 4;
    if (pkthdr->caplen < (unsigned int)(ETHERNET_HDR_LEN + ip_header_len)) {
        fprintf(stderr, "Packet too short for IP header\n");
        return;
    }

    // Check IP protocol - must be UDP for our filter, but double-check
    if (ip_header->ip_p != IPPROTO_UDP) {
        return; // Should have been filtered by pcap, but safety first
    }

    // UDP Header
    const struct udphdr *udp_header = (struct udphdr *)((u_char *)ip_header + ip_header_len);
    int udp_header_len = sizeof(struct udphdr);
    if (pkthdr->caplen < (unsigned int)(ETHERNET_HDR_LEN + ip_header_len + udp_header_len)) {
         fprintf(stderr, "Packet too short for UDP header\n");
         return;
    }

    // UDP Payload (SPA packet)
    const u_char *payload = (u_char *)udp_header + udp_header_len;
    int payload_len = pkthdr->caplen - (ETHERNET_HDR_LEN + ip_header_len + udp_header_len);

    // Basic SPA packet length check
    if (payload_len < SPA_PACKET_MIN_LEN || payload_len > SPA_PACKET_MAX_LEN) {
        // Silently ignore packets that don't meet basic size criteria
        return;
    }

    // --- Extract SPA Components ---
    const unsigned char *iv = payload;
    const unsigned char *encrypted_data = payload + SPA_IV_LEN;
    int encrypted_len = payload_len - SPA_IV_LEN - SPA_HMAC_LEN;
    const unsigned char *received_hmac = payload + SPA_IV_LEN + encrypted_len;

    if (encrypted_len <= 0) {
        fprintf(stderr, "Invalid encrypted data length calculated: %d\n", encrypted_len);
        return; // Invalid packet structure
    }

    // --- Verify HMAC ---
    unsigned char calculated_hmac[EVP_MAX_MD_SIZE];
    unsigned int calculated_hmac_len = 0;

    const EVP_MD *digest = EVP_get_digestbyname(SPA_HMAC_ALGO);
    if (!digest) { // Should have been checked at startup, but defensive
        fprintf(stderr, "HMAC digest algo not found in handler!\n");
        return;
    }

    // Data for HMAC is IV + Ciphertext
    unsigned char data_to_hmac[SPA_IV_LEN + encrypted_len];
    memcpy(data_to_hmac, iv, SPA_IV_LEN);
    memcpy(data_to_hmac + SPA_IV_LEN, encrypted_data, encrypted_len);

    HMAC(digest, SPA_PSK, strlen(SPA_PSK), data_to_hmac, SPA_IV_LEN + encrypted_len,
         calculated_hmac, &calculated_hmac_len);

    if (calculated_hmac_len != SPA_HMAC_LEN) {
        fprintf(stderr, "Internal HMAC calculation error (length mismatch)\n");
        return; // Should not happen
    }

    // **CRITICAL: Use constant-time comparison for security**
    if (constant_time_memcmp(received_hmac, calculated_hmac, SPA_HMAC_LEN) != 0) {
        // HMAC mismatch - likely invalid packet or wrong key. SILENTLY DISCARD.
        // printf("Debug: HMAC mismatch\n"); // Uncomment for debugging ONLY
        return;
    }

    // --- Decrypt Data ---
    unsigned char decrypted_data[encrypted_len]; // Decrypted data cannot be larger than ciphertext
    int decrypted_len = 0;
    int final_len = 0;

    const EVP_CIPHER *cipher = EVP_get_cipherbyname(SPA_ENCRYPTION_ALGO);
     if (!cipher) { // Should have been checked at startup
         fprintf(stderr, "Cipher algo not found in handler!\n");
         return;
     }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        handle_openssl_error_server("Failed to create cipher context in handler");
        return;
    }

    if (1 != EVP_DecryptInit_ex(ctx, cipher, NULL, (const unsigned char*)SPA_PSK, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        handle_openssl_error_server("EVP_DecryptInit_ex failed");
        return; // Decryption failed
    }

    // Allow for padding removal by EVP functions
    if (1 != EVP_DecryptUpdate(ctx, decrypted_data, &decrypted_len, encrypted_data, encrypted_len)) {
        // Often fails here if padding is incorrect or data corrupted / wrong key
        EVP_CIPHER_CTX_free(ctx);
        // Silently discard on decryption errors usually
        // fprintf(stderr, "Debug: EVP_DecryptUpdate failed\n");
        return;
    }

    if (1 != EVP_DecryptFinal_ex(ctx, decrypted_data + decrypted_len, &final_len)) {
        // Indicates padding error or other issue
        EVP_CIPHER_CTX_free(ctx);
        // Silently discard
         // fprintf(stderr, "Debug: EVP_DecryptFinal_ex failed (padding?)\n");
        return;
    }
    decrypted_len += final_len;
    EVP_CIPHER_CTX_free(ctx);

    // --- Validate Decrypted Data ---
    if (decrypted_len != sizeof(spa_data_t)) {
        fprintf(stderr, "Decryption yielded unexpected size: %d (expected %zu)\n", decrypted_len, sizeof(spa_data_t));
        return; // Data structure mismatch
    }

    spa_data_t *spa_info = (spa_data_t *)decrypted_data;

    // Check version
    if (spa_info->version != SPA_VERSION) {
        fprintf(stderr, "Ignoring packet with version %u (expected %d)\n", spa_info->version, SPA_VERSION);
        return;
    }

    // Check timestamp (allow for skew)
    time_t current_time = time(NULL);
    int64_t time_diff = (int64_t)current_time - (int64_t)spa_info->timestamp; // Use signed difference

    if (llabs(time_diff) > SPA_TIMESTAMP_WINDOW_SECONDS) {
         fprintf(stderr, "Timestamp validation failed: Packet time %llu, Server time %llu, Diff %lld (Window %d)\n",
                (unsigned long long)spa_info->timestamp, (unsigned long long)current_time, (long long)time_diff, SPA_TIMESTAMP_WINDOW_SECONDS);
        return; // Expired or future timestamp (replay/clock skew)
    }

    // **TODO: Implement Replay Prevention**
    // A robust implementation would store recently seen nonces (or hashes of packets)
    // in a cache (e.g., hash table, ring buffer) and discard duplicates.
    // This basic example lacks replay prevention beyond the timestamp window.

    // --- Authorization Action ---
    char source_ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_header->ip_src), source_ip_str, INET_ADDRSTRLEN);

    uint16_t requested_port = ntohs(spa_info->req_port); // Convert back to host order for printing/use
    const char* requested_proto_str = protocol_to_string(spa_info->req_protocol);
    uint16_t duration = spa_info->req_duration;

    printf("----------------------------------------\n");
    printf("VALID SPA Packet Received!\n");
    printf("  Source IP:      %s (from packet header)\n", source_ip_str);
    printf("  Timestamp:      %llu (Valid within window)\n", (unsigned long long)spa_info->timestamp);
    printf("  Requested Proto:%s (%d)\n", requested_proto_str, spa_info->req_protocol);
    printf("  Requested Port: %u\n", requested_port);
    printf("  Requested Duration: %u seconds\n", duration);
    printf("----------------------------------------\n");

    // --- Generate Firewall Command (Example: iptables) ---
    // WARNING: Executing external commands needs extreme care regarding input sanitization.
    //          This example ONLY prints the command.
    printf("FIREWALL ACTION (Example):\n");
    // Basic sanitization check (more needed for real execution)
    if (requested_port > 0 && duration > 0 && strlen(source_ip_str) > 6)
    {
        // Construct the iptables command to ADD the rule
        printf("sudo iptables -I INPUT -s %s -p %s --dport %u -m comment --comment \"SPA Allow %s:%u for %us\" -j ACCEPT\n",
               source_ip_str,
               requested_proto_str,
               requested_port,
               source_ip_str, requested_port, duration); // Comment helps identify rule

        // Construct a command to REMOVE the rule after the duration
        // This usually requires a separate mechanism (at job, background timer, etc.)
        // For simplicity, just print what it might look like.
        printf("# To remove later (e.g., using 'at' or similar):\n");
        printf("# sleep %u && sudo iptables -D INPUT -s %s -p %s --dport %u -m comment --comment \"SPA Allow %s:%u for %us\" -j ACCEPT\n",
               duration,
               source_ip_str,
               requested_proto_str,
               requested_port,
               source_ip_str, requested_port, duration); // Match the exact add rule to delete
    } else {
        printf("  -> Invalid parameters for firewall rule generation (port=%u, duration=%u)\n", requested_port, duration);
    }
    printf("----------------------------------------\n");

    // No need to free spa_info, it's on the stack (decrypted_data)
}

// Signal handler for graceful shutdown
void cleanup(int signo) {
    printf("\nCaught signal %d, shutting down...\n", signo);
    if (pcap_handle) {
        pcap_breakloop(pcap_handle); // Stop the pcap_loop
        // pcap_close will be called in main after loop exits
    }
    // No exit() here, let main finish cleanup
}


int main(int argc, char *argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];
    char *dev = NULL;
    bpf_u_int32 net, mask;
    struct bpf_program fp;
    char filter_exp[100];

    // Allow overriding interface via command line
    if (argc > 2 && strcmp(argv[1], "-i") == 0) {
        dev = argv[2];
        printf("Using interface specified: %s\n", dev);
    } else if (argc > 1) {
        fprintf(stderr, "Usage: %s [-i interface_name]\n", argv[0]);
        return 1;
    } else {
        // Use default or try to find one
        dev = pcap_lookupdev(errbuf);
        if (dev == NULL) {
            fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
             // Fallback to hardcoded default if lookup fails
             dev = strdup(SPA_INTERFACE); // Need to free later if using strdup
             if (!dev) { perror("strdup failed"); return 2;}
             printf("Warning: Couldn't find default device, using hardcoded '%s'\n", dev);
        } else {
            printf("Using default sniff device: %s\n", dev);
        }
    }


    // Load crypto algorithms
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    // Pre-check that crypto algos are available
     if (!EVP_get_cipherbyname(SPA_ENCRYPTION_ALGO)) {
        fprintf(stderr, "Fatal: Encryption algorithm '%s' not found.\n", SPA_ENCRYPTION_ALGO);
        ERR_print_errors_fp(stderr);
        return EXIT_FAILURE;
    }
     if (!EVP_get_digestbyname(SPA_HMAC_ALGO)) {
        fprintf(stderr, "Fatal: HMAC algorithm '%s' not found.\n", SPA_HMAC_ALGO);
         ERR_print_errors_fp(stderr);
        return EXIT_FAILURE;
    }


    // Get network addr and mask for the device
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
        net = 0;
        mask = 0;
    }

    // Open capture device
    // Use a larger snaplen to capture full UDP payloads if needed
    // Set timeout to 1000ms (1 second) - pcap_loop will check for breakloop periodically
    pcap_handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (pcap_handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        if (strncmp(dev, SPA_INTERFACE, strlen(SPA_INTERFACE)) == 0) free(dev); // Free if we strdup'd fallback
        return 2;
    }

    // Ensure we are capturing on Ethernet (check datalink type)
    if (pcap_datalink(pcap_handle) != DLT_EN10MB) {
        fprintf(stderr, "%s is not an Ethernet device - this basic example may not work\n", dev);
        // You might need different offset calculations for other link types
    }

    // Compile the filter expression
    snprintf(filter_exp, sizeof(filter_exp), "udp dst port %d", SPA_SERVER_UDP_PORT);
    printf("Using pcap filter: %s\n", filter_exp);

    if (pcap_compile(pcap_handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(pcap_handle));
        pcap_close(pcap_handle);
         if (strncmp(dev, SPA_INTERFACE, strlen(SPA_INTERFACE)) == 0) free(dev);
        return 2;
    }

    // Apply the compiled filter
    if (pcap_setfilter(pcap_handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(pcap_handle));
        pcap_freecode(&fp);
        pcap_close(pcap_handle);
         if (strncmp(dev, SPA_INTERFACE, strlen(SPA_INTERFACE)) == 0) free(dev);
        return 2;
    }

    printf("SPA Server listening on %s, port %d...\n", dev, SPA_SERVER_UDP_PORT);

     // Setup signal handler for graceful shutdown
    signal(SIGINT, cleanup);
    signal(SIGTERM, cleanup);


    // Start packet capture loop (-1 means loop forever until pcap_breakloop)
    int pcap_ret = pcap_loop(pcap_handle, -1, packet_handler, NULL);

    if (pcap_ret == -1) {
        fprintf(stderr, "Error occurred during pcap_loop: %s\n", pcap_geterr(pcap_handle));
    } else if (pcap_ret == -2) {
        printf("pcap_loop broken (signal received?)\n");
    } else {
         printf("pcap_loop finished (received %d packets)\n", pcap_ret);
    }


    // Cleanup
    printf("Cleaning up...\n");
    pcap_freecode(&fp);
    pcap_close(pcap_handle);
    pcap_handle = NULL; // Prevent double close in signal handler edge case
    if (strncmp(dev, SPA_INTERFACE, strlen(SPA_INTERFACE)) == 0) free(dev); // Free if we strdup'd fallback

    EVP_cleanup();
    ERR_free_strings();
    printf("Server shutdown complete.\n");

    return 0;
}