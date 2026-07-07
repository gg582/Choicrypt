#!/bin/bash

# check_safety.sh — Integrated safety and correctness verification for Choicrypt
#
# This script builds all binaries, runs unit tests, verifies encryption /
# decryption round-trips, checks failure behaviour with wrong passwords,
# and runs the statistical audit tool.

set -euo pipefail

PW="choi_seok_jeong_1700_jisugwimundo_chaos_32_rounds"
SAMPLE=sample.bin
ENCRYPTED=sample.bin.choi
DECRYPTED=sample.bin.dec
STDOUT_DEC=sample.bin.stdout.dec
KEYFILE=sample.key
REPORT=audit_report.txt

 cleanup() {
    rm -f "$SAMPLE" "$ENCRYPTED" "$DECRYPTED" "$STDOUT_DEC" "$KEYFILE" "$REPORT"
}
cleanup

echo "[*] Building project..."
make clean >/dev/null
make all >/dev/null
make test >/dev/null

echo "[*] Generating 64 KiB random sample..."
dd if=/dev/urandom of="$SAMPLE" bs=1K count=64 status=none

echo "[*] Storing test password..."
printf '%s' "$PW" > "$KEYFILE"

echo "[*] Encrypting..."
printf '%s\n' "$PW" | ./choienc "$SAMPLE"

echo "[*] Decrypting..."
printf '%s\n' "$PW" | ./choidec "$ENCRYPTED" "$DECRYPTED"

echo "[*] Decrypting via inferred .choi path to stdout..."
printf '%s\n' "$PW" | ./choidec "$SAMPLE" /dev/stdout > "$STDOUT_DEC"

echo "[*] Verifying integrity..."
if diff -q "$SAMPLE" "$DECRYPTED" >/dev/null; then
    echo "[+] File integrity check: PASSED"
else
    echo "[!] File integrity check: FAILED"
    exit 1
fi

if diff -q "$SAMPLE" "$STDOUT_DEC" >/dev/null; then
    echo "[+] Stdout integrity check: PASSED"
else
    echo "[!] Stdout integrity check: FAILED"
    exit 1
fi

echo "[*] Verifying wrong-password handling..."
if printf '%s\n' "wrong_password" | ./choidec "$ENCRYPTED" /tmp/should_not_exist 2>/dev/null; then
    echo "[!] Wrong password was accepted: FAILED"
    exit 1
else
    echo "[+] Wrong password correctly rejected"
fi

if [ -f /tmp/should_not_exist ]; then
    echo "[!] Output file created despite wrong password: FAILED"
    exit 1
fi

echo "[*] Verifying decoy mode..."
printf '%s\n' "wrong_password" | ./choidec --decoy "$ENCRYPTED" /tmp/decoy_out >/dev/null 2>&1
if [ -f /tmp/decoy_out ] && [ "$(stat -c%s /tmp/decoy_out)" -eq "$(stat -c%s "$SAMPLE")" ]; then
    echo "[+] Decoy mode produces output of correct size"
else
    echo "[!] Decoy mode did not produce expected output"
    exit 1
fi

echo "[*] Running PoC..."
./choi_poc >/dev/null

echo "[*] Running statistical audit..."
python3 crypt_hardcore_audit.py \
    --origin "$SAMPLE" \
    --encrypted "$ENCRYPTED" \
    --key "$KEYFILE" | tee "$REPORT"

echo "[*] Cleaning up temporary files..."
cleanup
rm -f /tmp/decoy_out /tmp/should_not_exist

echo "[*] All safety checks passed."
