# Makefile for Choi Seok-jeong's Jisugwimundo Cipher Tools

CC = gcc
CFLAGS = -O3 -Wall -Wextra -march=native
RM = rm -f

# Target Binaries
ENC_TARGET = choienc
DEC_TARGET = choidec

# Source Files
ENC_SRC = choi_enc.c
DEC_SRC = choi_dec.c

.PHONY: all clean help

# Default build: compile both tools
all: $(ENC_TARGET) $(DEC_TARGET)

$(ENC_TARGET): $(ENC_SRC)
	$(CC) $(CFLAGS) -o $@ $<

$(DEC_TARGET): $(DEC_SRC)
	$(CC) $(CFLAGS) -o $@ $<

# Clean up build artifacts
clean:
	$(RM) $(ENC_TARGET) $(DEC_TARGET) *.choi

# Usage help
help:
	@echo "Choi Seok-jeong's Cipher Build System"
	@echo "------------------------------------"
	@echo "make all      : Build both choienc and choidec"
	@echo "make clean    : Remove binaries and .choi files"
	@echo "make help     : Show this message" 
