# Makefile for SDP Controller Components

CC = gcc
# Need -std=gnu99 or later for vasprintf
# Need -pthread for multi-threading in mTLS listener
CFLAGS = -Wall -Wextra -g -std=gnu99 -pthread
# Link OpenSSL, math library, pcap, and pthreads
LDFLAGS = -lssl -lcrypto -lm -lpcap -pthread

# Common files
COMMON_SRC = spa_common.c
COMMON_OBJ = $(COMMON_SRC:.c=.o)

# Controller Core Logic/Helpers object
CTRL_CORE_SRC = controller.c
CTRL_CORE_OBJ = $(CTRL_CORE_SRC:.c=.o)

# SPA Listener files
SPA_SRV_SRC = spa_server_controller.c
SPA_SRV_OBJ = $(SPA_SRV_SRC:.c=.o)
SPA_SRV_EXE = spa_ctrl_listener

# mTLS Listener files
MTLS_SRV_SRC = handle_connections_controller.c
MTLS_SRV_OBJ = $(MTLS_SRV_SRC:.c=.o)
MTLS_SRV_EXE = mtls_ctrl_listener

# --- Targets ---

# Default target: build both listeners
all: $(SPA_SRV_EXE) $(MTLS_SRV_EXE)

# Rule to build the SPA listener executable
# Links SPA server object, controller core object, and common object
$(SPA_SRV_EXE): $(SPA_SRV_OBJ) $(CTRL_CORE_OBJ) $(COMMON_OBJ)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

# Rule to build the mTLS listener executable
# Links mTLS server object, controller core object, and common object
$(MTLS_SRV_EXE): $(MTLS_SRV_OBJ) $(CTRL_CORE_OBJ) $(COMMON_OBJ)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

# Rule to compile controller core logic
$(CTRL_CORE_OBJ): $(CTRL_CORE_SRC) controller_structs.h spa_common.h
	$(CC) $(CFLAGS) -c $(CTRL_CORE_SRC) -o $(CTRL_CORE_OBJ)

# Rule to compile SPA server
$(SPA_SRV_OBJ): $(SPA_SRV_SRC) controller_structs.h spa_common.h
	$(CC) $(CFLAGS) -c $(SPA_SRV_SRC) -o $(SPA_SRV_OBJ)

# Rule to compile mTLS server
$(MTLS_SRV_OBJ): $(MTLS_SRV_SRC) controller_structs.h spa_common.h
	$(CC) $(CFLAGS) -c $(MTLS_SRV_SRC) -o $(MTLS_SRV_OBJ)

# Rule to compile spa_common.c
$(COMMON_OBJ): $(COMMON_SRC) spa_common.h
	$(CC) $(CFLAGS) -c $(COMMON_SRC) -o $(COMMON_OBJ)

# Clean up build files - CORRECTED AND SAFE VERSION
clean:
	rm -f $(SPA_SRV_EXE) $(MTLS_SRV_EXE) $(SPA_SRV_OBJ) $(MTLS_SRV_OBJ) $(CTRL_CORE_OBJ) $(COMMON_OBJ) *.o core

# Declare phony targets
.PHONY: all clean