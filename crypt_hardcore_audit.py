import numpy as np
import argparse
from scipy import stats
import os

def analyze_crypto(origin_path, encrypted_path, key_path):
    # 파일 존재 여부 확인
    for p in [origin_path, encrypted_path, key_path]:
        if not os.path.exists(p):
            print(f"Error: 파일을 찾을 수 없습니다 -> {p}")
            return

    # 데이터 로드
    p_data = np.fromfile(origin_path, dtype=np.uint8)
    c_data = np.fromfile(encrypted_path, dtype=np.uint8)
    k_data = np.fromfile(key_path, dtype=np.uint8)

    print(f"\n[ 분석 대상 리포트 ]")
    print(f" - 원본: {origin_path} ({len(p_data)} bytes)")
    print(f" - 암호: {encrypted_path} ({len(c_data)} bytes)")
    print("-" * 50)

    # 1. NIST 수준의 균일성 검정 (Chi-Square)
    counts = np.bincount(c_data, minlength=256)
    expected = len(c_data) / 256
    chi_stat, p_val = stats.chisquare(counts, f_exp=[expected]*256)
    
    # 2. 자기상관 계수 (Autocorrelation - 내부 패턴 탐지)
    def get_max_autocorr(data, max_lag=64):
        data_norm = data.astype(float) - np.mean(data)
        if np.all(data_norm == 0): return 1.0
        
        acorr = [np.corrcoef(data_norm[:-lag], data_norm[lag:])[0, 1] 
                 for lag in range(1, min(max_lag, len(data)//2))]
        return max(map(abs, acorr)) if acorr else 0.0

    max_corr = get_max_autocorr(c_data)

    # 3. 키-암호문 독립성 (Bit-level Independence)
    min_len = min(len(p_data), len(c_data), len(k_data))
    xor_diff = np.bitwise_xor(p_data[:min_len], c_data[:min_len])
    k_indep = 1 - abs(np.corrcoef(xor_diff.astype(float), k_data[:min_len].astype(float))[0, 1])

    # 결과 출력
    print(f"1. 분포 균일성 (P-Value): {p_val:.10f}") 
    print(f"   (> 0.01: 통계적 난수성 합격)")
    
    print(f"2. 패턴 반복성 (Max Correlation): {max_corr:.6f}")
    print(f"   (< 0.05: 구조적 규칙성 없음)")
    
    print(f"3. 키 독립성 (Independence): {k_indep:.6f}")
    print(f"   (1.0에 가까울수록 키 유추 불가)")

    # 최종 판정
    print("-" * 50)
    if p_val > 0.01 and max_corr < 0.05 and k_indep > 0.95:
        print(">>> [ 판정: 강력 ] S-Box의 비선형성이 유효함.")
    else:
        print(">>> [ 판정: 취약 ] 특정 데이터 패턴이 잔존함. 로직 수정 권고.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Professional Crypto Strength Auditor")
    parser.add_argument("--origin", required=True, help="Path to original plaintext file")
    parser.add_argument("--encrypted", required=True, help="Path to encrypted ciphertext file")
    parser.add_argument("--key", required=True, help="Path to key file")

    args = parser.parse_args()
    analyze_crypto(args.origin, args.encrypted, args.key)
