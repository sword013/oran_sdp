# Makefile for SDP Initiating Host (IH) Client (IPsec Version - Corrected Flow)

CC = gcc
# Need -std=gnu99 or later for vasprintf
CFLAGS = -Wall -Wextra -g -std=gnu99
# Link OpenSSL, math library. No pthreads needed.
LDFLAGS = -lssl -lcrypto -lm

# Source files
IH_SRC = ih.c
COMMON_SRC = spa_common.c # Does NOT need tun_alloc

# Object files
IH_OBJ = $(IH_SRC:.c=.o)
COMMON_OBJ = $(COMMON_SRC:.c=.o)

# Executable name
IH_EXE = ih_app

# --- Targets ---

# Default target: build the IH orchestrator
all: $(IH_EXE)

# Rule to build the IH orchestrator executable
$(IH_EXE): $(IH_OBJ) $(COMMON_OBJ)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

# Rule to compile ih.c
$(IH_OBJ): $(IH_SRC) spa_common.h
	$(CC) $(CFLAGS) -c $(IH_SRC) -o $(IH_OBJ)

# Rule to compile spa_common.c
$(COMMON_OBJ): $(COMMON_SRC) spa_common.h
	$(CC) $(CFLAGS) -c $(COMMON_SRC) -o $(COMMON_OBJ)

# Clean up build files
clean:
	rm -f $(IH_EXE) $(IH_OBJ) $(COMMON_OBJ) *.o core *~ *.p12 # Clean p12

# Declare phony targets
.PHONY: all clean


