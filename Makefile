# Choicrypt build system

CC = gcc
CFLAGS = -O2 -Wall -Wextra -Wpedantic -std=c11 -mssse3
RM = rm -f

# Main binaries
ENC_TARGET = choienc
DEC_TARGET = choidec
POC_TARGET = choi_poc

# Test binaries
TESTS = test_block test_ctr test_virtual_silicon test_honey
TEST_BINS = $(addprefix tests/, $(TESTS))

# Source files
ENC_SRC = choi_enc.c
DEC_SRC = choi_dec.c
POC_SRC = poc.c
POC_DEPS = virtual_silicon.c obfuscated_pipeline.c dynamic_asm.c

.PHONY: all clean test help

# Default: build main tools and PoC
all: $(ENC_TARGET) $(DEC_TARGET) $(POC_TARGET)

$(ENC_TARGET): $(ENC_SRC) choi_common.h
	$(CC) $(CFLAGS) -o $@ $<

$(DEC_TARGET): $(DEC_SRC) choi_common.h
	$(CC) $(CFLAGS) -o $@ $<

$(POC_TARGET): $(POC_SRC) $(POC_DEPS) choi_common.h virtual_silicon.h dynamic_asm.h obfuscated_pipeline.h
	$(CC) $(CFLAGS) -o $@ $(POC_SRC) $(POC_DEPS)

# Unit tests
test: $(TEST_BINS)
	@for bin in $(TEST_BINS); do echo "Running $$bin"; ./$$bin || exit 1; done
	@echo "All unit tests passed."

# Pattern rule for test binaries
tests/%: tests/%.c choi_common.h virtual_silicon.h dynamic_asm.h obfuscated_pipeline.h virtual_silicon.c obfuscated_pipeline.c dynamic_asm.c
	$(CC) $(CFLAGS) -o $@ $< virtual_silicon.c obfuscated_pipeline.c dynamic_asm.c

# Clean build artifacts
clean:
	$(RM) $(ENC_TARGET) $(DEC_TARGET) $(POC_TARGET)
	$(RM) $(TEST_BINS)
	$(RM) *.o
	$(RM) *.choi sample.bin sample.bin.* sample.key audit_report.txt

# Usage help
help:
	@echo "Choicrypt Build System"
	@echo "----------------------"
	@echo "make all      : Build choienc, choidec, and choi_poc"
	@echo "make test     : Build and run unit tests"
	@echo "make clean    : Remove binaries, tests, and sample artifacts"
	@echo "make help     : Show this message"
