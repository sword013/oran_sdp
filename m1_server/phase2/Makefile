# Makefile for SDP Accepting Host (AH) Server (IPsec Version)

CC = gcc
# Need -pthread for multi-threading (Controller Listener, SPA Listener, Policy Cleanup)
# Need -std=gnu99 or later for vasprintf
CFLAGS = -Wall -Wextra -g -std=gnu99 -pthread
# Link OpenSSL, pcap (for SPA listener), pthreads, math library
LDFLAGS = -lssl -lcrypto -lpcap -pthread -lm

# Source files
AH_SRC = ah.c
COMMON_SRC = spa_common.c

# Object files
AH_OBJ = $(AH_SRC:.c=.o)
COMMON_OBJ = $(COMMON_SRC:.c=.o)

# Executable name
AH_EXE = ah_server

# --- Targets ---

# Default target: build the AH server executable
all: $(AH_EXE)

# Rule to build the executable
# Links AH object and common object
$(AH_EXE): $(AH_OBJ) $(COMMON_OBJ)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

# Rule to compile ah.c
# Depends on its source and relevant headers
$(AH_OBJ): $(AH_SRC) ah_structs.h spa_common.h
	$(CC) $(CFLAGS) -c $(AH_SRC) -o $(AH_OBJ)

# Rule to compile spa_common.c
# Depends on its source and its header
$(COMMON_OBJ): $(COMMON_SRC) spa_common.h
	$(CC) $(CFLAGS) -c $(COMMON_SRC) -o $(COMMON_OBJ)

# Clean up build files
clean:
	rm -f $(AH_EXE) $(AH_OBJ) $(COMMON_OBJ) *.o core *~ *.p12 # Clean p12

# Declare phony targets
.PHONY: all clean


