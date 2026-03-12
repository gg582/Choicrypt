#!/bin/bash

# Choi Seok-jeong's Cipher Security Audit Script
# Generates sample data, encrypts, and runs audit.

echo "[*] Cleaning up old artifacts..."
make clean > /dev/null
rm -f sample.bin sample.bin.choi sample.bin.dec sample.bin.stdout.dec sample.key audit_report.txt

echo "[*] Compiling binaries..."
make all > /dev/null

if [ ! -f choienc ] || [ ! -f choidec ]; then
    echo "[!] Compilation failed."
    exit 1
fi

echo "[*] Generating 64KB sample data..."
dd if=/dev/urandom of=sample.bin bs=1k count=64 2>/dev/null

echo "[*] Creating key file (password: 'choi_seok_jeong_1700')..."
PW="choi_seok_jeong_1700_jisugwimundo_chaos_32_rounds"
echo -n "$PW" > sample.key

echo "[*] Encrypting data..."
echo "$PW" | ./choienc sample.bin

echo "[*] Decrypting data..."
echo "$PW" | ./choidec sample.bin.choi sample.bin.dec

echo "[*] Decrypting via inferred .choi path to stdout..."
echo "$PW" | ./choidec sample.bin /dev/stdout > sample.bin.stdout.dec

echo "[*] Verifying integrity..."
if diff sample.bin sample.bin.dec > /dev/null; then
    echo "[+] Integrity Check: PASSED"
else
    echo "[!] Integrity Check: FAILED"
    # exit 1 # Don't exit yet, still want to see audit if it partially worked
fi

if diff sample.bin sample.bin.stdout.dec > /dev/null; then
    echo "[+] Stdout Integrity Check: PASSED"
else
    echo "[!] Stdout Integrity Check: FAILED"
fi

echo "[*] Running Security Audit (NIST + Autocorrelation + Independence)..."
python3 crypt_hardcore_audit.py --origin sample.bin --encrypted sample.bin.choi --key sample.key | tee audit_report.txt

echo "[*] Audit complete."
