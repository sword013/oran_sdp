# Makefile for SPA AH / Gateway Components

CC = gcc
CFLAGS = -Wall -Wextra -g -std=gnu99 -pthread
LDFLAGS = -lssl -lcrypto -lm -lpcap -pthread

# Common files
COMMON_SRC = spa_common.c
COMMON_OBJ = $(COMMON_SRC:.c=.o)

# AH Orchestrator files
AH_MAIN_SRC = ah.c
AH_MAIN_OBJ = $(AH_MAIN_SRC:.c=.o)
AH_MAIN_EXE = ah_app

# SPA Listener files (for IH)
SPA_SRV_AH_SRC = spa_server_ah.c
SPA_SRV_AH_OBJ = $(SPA_SRV_AH_SRC:.c=.o)
SPA_SRV_AH_EXE = spa_srv_ah

# mTLS Listener files (for IH)
MTLS_SRV_AH_SRC = handle_connections_ah.c
MTLS_SRV_AH_OBJ = $(MTLS_SRV_AH_SRC:.c=.o)
MTLS_SRV_AH_EXE = mtls_srv_ah

# --- Targets ---

# Default target: build all AH executables
all: $(AH_MAIN_EXE) $(SPA_SRV_AH_EXE) $(MTLS_SRV_AH_EXE)

# Rule to build the AH main orchestrator
$(AH_MAIN_EXE): $(AH_MAIN_OBJ) $(COMMON_OBJ)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

# Rule to build the AH SPA listener
$(SPA_SRV_AH_EXE): $(SPA_SRV_AH_OBJ) $(COMMON_OBJ)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

# Rule to build the AH mTLS listener/proxy
$(MTLS_SRV_AH_EXE): $(MTLS_SRV_AH_OBJ) $(COMMON_OBJ)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

# Compile rules for specific AH components
$(AH_MAIN_OBJ): $(AH_MAIN_SRC) ah_structs.h spa_common.h
	$(CC) $(CFLAGS) -c $(AH_MAIN_SRC) -o $(AH_MAIN_OBJ)

$(SPA_SRV_AH_OBJ): $(SPA_SRV_AH_SRC) ah_structs.h spa_common.h
	$(CC) $(CFLAGS) -c $(SPA_SRV_AH_SRC) -o $(SPA_SRV_AH_OBJ)

$(MTLS_SRV_AH_OBJ): $(MTLS_SRV_AH_SRC) ah_structs.h spa_common.h
	$(CC) $(CFLAGS) -c $(MTLS_SRV_AH_SRC) -o $(MTLS_SRV_AH_OBJ)

# Compile common code
$(COMMON_OBJ): $(COMMON_SRC) spa_common.h
	$(CC) $(CFLAGS) -c $(COMMON_SRC) -o $(COMMON_OBJ)

# Clean target
clean:
	rm -f $(AH_MAIN_EXE) $(SPA_SRV_AH_EXE) $(MTLS_SRV_AH_EXE) *.o core

# Phony targets
.PHONY: all clean