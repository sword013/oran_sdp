// spa_common.c (Common helper functions)
#include "spa_common.h"
#include <string.h>
#include <netinet/in.h>
#include <stdio.h> // For snprintf

// Simple mapping for common protocols
const char* protocol_to_string(int proto) {
    switch (proto) {
        case IPPROTO_TCP: return "tcp";
        case IPPROTO_UDP: return "udp";
        case IPPROTO_SCTP: return "sctp";
        case IPPROTO_ICMP: return "icmp";
        // Add other protocols as needed
        default: {
            // Return numeric value as string for unknown protocols
            // Static buffer is generally bad, but simple for this example.
            // Ensure buffer is large enough.
            static char proto_num_str[16];
            snprintf(proto_num_str, sizeof(proto_num_str), "%d", proto);
            return proto_num_str;
        }
    }
}

int string_to_protocol(const char* proto_str) {
    if (strcasecmp(proto_str, "tcp") == 0) return IPPROTO_TCP;
    if (strcasecmp(proto_str, "udp") == 0) return IPPROTO_UDP;
    if (strcasecmp(proto_str, "sctp") == 0) return IPPROTO_SCTP;
    if (strcasecmp(proto_str, "icmp") == 0) return IPPROTO_ICMP;
    // Add other protocols as needed
    // Try parsing as a number? (Not implemented here for simplicity)
    return -1; // Indicate unknown/unsupported string
}