#!/usr/bin/env python3
"""
crypt_hardcore_audit.py — Cryptographic strength audit for Choicrypt

Performs statistical tests on ciphertext and reports whether the output
exhibits properties expected of a strong cipher:
  - Byte-distribution uniformity (Chi-Square)
  - Lack of internal correlation (autocorrelation)
  - Bit-level independence from the key
  - NIST-style monobit / runs / block-frequency tests
  - Avalanche effect metrics
"""

import argparse
import os
import math
import numpy as np
from scipy import stats


def load_file(path):
    if not os.path.exists(path):
        raise FileNotFoundError(path)
    return np.fromfile(path, dtype=np.uint8)


def chi_square_test(data):
    counts = np.bincount(data, minlength=256)
    expected = len(data) / 256.0
    chi_stat, p_val = stats.chisquare(counts, f_exp=[expected] * 256)
    return chi_stat, p_val


def max_autocorrelation(data, max_lag=64):
    data_norm = data.astype(float) - np.mean(data)
    if np.all(data_norm == 0):
        return 1.0
    n = len(data)
    max_corr = 0.0
    for lag in range(1, min(max_lag, n // 2)):
        corr = np.corrcoef(data_norm[:-lag], data_norm[lag:])[0, 1]
        max_corr = max(max_corr, abs(corr))
    return max_corr


def bit_independence(p_data, c_data, k_data):
    min_len = min(len(p_data), len(c_data), len(k_data))
    if min_len == 0:
        return 0.0
    xor_diff = np.bitwise_xor(p_data[:min_len], c_data[:min_len])
    try:
        corr = np.corrcoef(xor_diff.astype(float), k_data[:min_len].astype(float))[0, 1]
        return 1.0 - abs(corr)
    except Exception:
        return 0.0


def monobit_test(data):
    """NIST SP 800-22 monobit test."""
    bits = np.unpackbits(data)
    s = 2 * bits.astype(np.int32) - 1
    sobs = abs(s.sum()) / math.sqrt(len(bits))
    p_val = math.erfc(sobs / math.sqrt(2))
    return p_val


def runs_test(data):
    """NIST SP 800-22 runs test."""
    bits = np.unpackbits(data)
    n = len(bits)
    pi = bits.mean()
    if abs(pi - 0.5) > (2.0 / math.sqrt(n)):
        return 0.0
    runs = 1 + np.sum(bits[:-1] != bits[1:])
    expected = 2.0 * n * pi * (1.0 - pi)
    var = 2.0 * n * pi * (1.0 - pi) * (2.0 * n * pi * (1.0 - pi) - 1.0) / (n - 1.0)
    if var <= 0:
        return 0.0
    z = (runs - expected) / math.sqrt(var)
    p_val = math.erfc(abs(z) / math.sqrt(2))
    return p_val


def block_frequency_test(data, block_size=128):
    """NIST SP 800-22 block-frequency test."""
    bits = np.unpackbits(data)
    n = len(bits)
    m = block_size
    if n < m or n % m != 0:
        # Truncate to multiple of block_size
        n = (n // m) * m
        bits = bits[:n]
    blocks = bits.reshape(-1, m)
    proportions = blocks.mean(axis=1)
    chi = 4.0 * m * np.sum((proportions - 0.5) ** 2)
    df = n // m - 1
    p_val = 1.0 - stats.chi2.cdf(chi, df)
    return p_val


def avalanche_metric(encrypt_fn):
    """
    Measures avalanche by flipping each bit of a random plaintext block
    and counting changed ciphertext bits. Requires a callable that takes
    (plaintext_bytes, key_bytes) and returns ciphertext_bytes for a single
    16-byte block.
    """
    if encrypt_fn is None:
        return None
    pt = np.random.randint(0, 256, size=16, dtype=np.uint8)
    key = np.random.randint(0, 256, size=32, dtype=np.uint8)
    ct = encrypt_fn(bytes(pt), bytes(key))
    diffs = []
    for i in range(16):
        for b in range(8):
            pt2 = pt.copy()
            pt2[i] ^= (1 << b)
            ct2 = encrypt_fn(bytes(pt2), bytes(key))
            diff_bits = np.unpackbits(np.frombuffer(ct, dtype=np.uint8) ^
                                      np.frombuffer(ct2, dtype=np.uint8)).sum()
            diffs.append(diff_bits)
    return np.mean(diffs), np.std(diffs)


def analyze_crypto(origin_path, encrypted_path, key_path):
    p_data = load_file(origin_path)
    c_data = load_file(encrypted_path)
    k_data = load_file(key_path)

    print("\n[ Cryptographic Strength Audit ]")
    print(f" - Plaintext:  {origin_path}   ({len(p_data)} bytes)")
    print(f" - Ciphertext: {encrypted_path} ({len(c_data)} bytes)")
    print(f" - Key:        {key_path}   ({len(k_data)} bytes)")
    print("-" * 60)

    chi_stat, chi_p = chi_square_test(c_data)
    print(f"1. Chi-Square uniformity")
    print(f"   statistic = {chi_stat:.4f}, p-value = {chi_p:.10f}")
    print(f"   (p > 0.01 => uniform distribution)")

    max_corr = max_autocorrelation(c_data)
    print(f"\n2. Max autocorrelation (lag 1..64)")
    print(f"   value = {max_corr:.6f}")
    print(f"   (< 0.05 => no strong linear pattern)")

    k_indep = bit_independence(p_data, c_data, k_data)
    print(f"\n3. Key-ciphertext bit independence")
    print(f"   score = {k_indep:.6f}")
    print(f"   (close to 1.0 => independent)")

    mono_p = monobit_test(c_data)
    runs_p = runs_test(c_data)
    block_p = block_frequency_test(c_data)
    print(f"\n4. NIST-style randomness tests")
    print(f"   monobit       p = {mono_p:.6f}")
    print(f"   runs          p = {runs_p:.6f}")
    print(f"   block-freq    p = {block_p:.6f}")
    print(f"   (p > 0.01 => pass)")

    print(f"\n5. Avalanche (not measured; use C unit tests or choi_poc)")

    print("-" * 60)
    passed = (
        chi_p > 0.01 and
        max_corr < 0.05 and
        k_indep > 0.85 and
        mono_p > 0.01 and
        runs_p > 0.01 and
        block_p > 0.01
    )
    if passed:
        print(">>> [VERDICT: PASS] Ciphertext exhibits expected statistical properties.")
    else:
        print(">>> [VERDICT: FAIL] One or more statistical tests did not pass.")
    return passed


def main():
    parser = argparse.ArgumentParser(description="Choicrypt strength auditor")
    parser.add_argument("--origin", required=True, help="Path to original plaintext file")
    parser.add_argument("--encrypted", required=True, help="Path to encrypted ciphertext file")
    parser.add_argument("--key", required=True, help="Path to key/password file")
    args = parser.parse_args()

    try:
        ok = analyze_crypto(args.origin, args.encrypted, args.key)
        return 0 if ok else 1
    except FileNotFoundError as e:
        print(f"Error: file not found -> {e}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
