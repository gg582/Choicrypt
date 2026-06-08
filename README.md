# CHOICRYPT vs AES-256: 방법론 비교

> 최석정이 제시한 마방진의 일종인 **"지수귀문도"**를 이용한 난독화 암호화 엔진  
> 어렵고 복잡한 개념의 압축이 애매한 GitHub 액세스 토큰 등을 보관할 때 사용합니다.

---

## 1. 개요 (Overview)

| 항목 | CHOICRYPT | AES-256 |
|------|-----------|---------|
| **설계 철학** | 난독화(Obfuscation) + 혼란(Chaos) 기반 | 확립된 SP 네트워크 기반 |
| **블록 크기** | 128비트 (16바이트) | 128비트 (16바이트) |
| **키 크기** | 256비트 (PBKDF2-HMAC-SHA256 기반) | 256비트 |
| **라운드 수** | 32라운드 | 14라운드 |
| **S-Box** | **키 의존적 동적 S-Box** | 고정 S-Box |
| **운영 모드** | CTR 유사 (카운터 기반 XOR 스트림) | ECB, CBC, CTR, GCM 등 다양한 표준 모드 |
| **표준화** | 독자 설계 (비표준) | NIST FIPS-197 공인 표준 |
| **하드웨어 가속** | 없음 (소프트웨어 전용) | Intel AES-NI 등 하드웨어 가속 지원 |

---

## 2. 구조적 차이 (Architectural Differences)

### 2.1 라운드 함수 (Round Function)

#### AES-256
```
SubBytes → ShiftRows → MixColumns → AddRoundKey
```
- 각 라운드는 **명확하고 분리된 치환-순열 레이어**로 구성
- `MixColumns`로 열 단위 확산(Diffusion) 제공
- 마지막 라운드에서는 `MixColumns` 생략

#### CHOICRYPT
```
SubBytes → ShiftRows → HexagonalRefraction → AddRoundKey → Final Chaos Layer
```
- **Hexagonal Refraction**이라는 독자적인 혼란 레이어 추가
- 난수 조작이 아닌 **결정론적 프랙탈 반복**(`Z = Z² + C`) 사용
- 마지막에 **Final Chaos Layer**로 잔여 선형 흔적 제거

### 2.2 Hexagonal Refraction (지수귀문도 기반)

CHOICRYPT의 핵심 차별화 요소입니다.

| 특성 | 설명 |
|------|------|
| **토폴로지** | 16노드 6각형 링(지수귀문도) — 각 노드는 3개의 인접 노드와 연결 |
| **혼란 생성** | 프랙탈 방정식 `Z = Z² + C`를 **6회 반복**하여 깊은 비선형성 생성 |
| **모듈러** | 큰 소수 `2³² - 17 = 4294967279`로 주기성 억제 (주기성 ~31% 감소) |
| **확산** | 수평 확산(Horizontal Diffusion)으로 링 전체에 영향 전파 |
| **키 주입** | 라운드 키와 라운드 ID가 프랙탈 상수 `C` 및 S-Box 인덱스에 직접 개입 |

이 구조는 AES의 `MixColumns` 대신 **수학적 혼란(Chaos)**을 확산 메커니즘으로 사용합니다.

---

## 3. 키 스케줄링 및 파생 (Key Schedule & Derivation)

| 항목 | CHOICRYPT | AES-256 |
|------|-----------|---------|
| **기반 해시** | SHA-256 | — |
| **초기 키 처리** | 비밀번호 → PBKDF2-HMAC-SHA256 (100,000 iterations) → 64바이트 마스터 | 256비트 마스터 키 직접 사용 |
| **확장 방식** | 해시로부터 8워드 초기화 → 132워드 확장 (K256 상수 XOR) | 60개의 32비트 워드 (RotWord, SubWord, Rcon) |
| **S-Box 생성** | **키 해시로 S-Box를 Fisher-Yates 셔플** — 매 키마다 고유한 S-Box | 동일한 고정 S-Box 사용 |

CHOICRYPT는 키 파생과 동시에 **키 의존적 S-Box(Dynamic S-Box)**를 생성합니다.  
이는 AES의 고정 S-Box와 달리, 키가 바뀔 때마다 전체 치환 표가 달라지므로 **관련 키 공격(Related-Key Attack) 표면을 복잡하게 만듭니다.**

### 3.1 보안 키 파생 (PBKDF2-HMAC-SHA256)
- 100,000회 반복(iteration)으로 brute-force 저항
- 무작위 16바이트 nonce(salt)를 `/dev/urandom`에서 매 파일마다 생성
- 64바이트 마스터 키를 분할하여 암호화 키(32B)와 MAC 키(32B) 분리

---

## 4. 운영 모드 (Mode of Operation)

| 항목 | CHOICRYPT | AES-256 |
|------|-----------|---------|
| **사용 모드** | CTR 유사 (Counter Mode) | 사용자 선택 (ECB/CBC/CTR/GCM/CCM 등) |
| **IV/Nonce** | **파일당 무작위 16바이트** (`/dev/urandom`) | 무작위 Nonce (모드에 따라 다름) |
| **블록 암호 활용** | `choi_encrypt_block(counter)` → 키스트림 생성 → XOR | 동일 |
| **인증** | **HMAC-SHA256** (무결성 및 키 검증) | GCM/GMAC 등 표준 인증 암호 사용 |

CHOICRYPT는 스트림 암호처럼 동작하며, 블록 암호를 **키스트림 생성기**로 사용합니다.  
각 파일은 고유한 nonce를 가지므로 **동일 키 사용 시에도 카운터 재사용 위험이 제거**되었습니다.

---

## 5. 추가 보안 기능

### 5.1 Honey Encryption (꿀 암호화)

| | CHOICRYPT | AES-256 |
|---|---|---|
| **잘못된 키 처리** | **Decoy(미끼) 데이터 자동 생성** | 의미 없는 난수 출력 |
| **동작 방식** | HMAC 불일치 시 `generate_secure_decoy()` 호출 → HMAC-DRBG 스타일 CSPRNG로 의미 없지만 구조적으로 유사한 데이터 생성 | 복호화 실패 또는 패딩 오류 |
| **보안 효과** | 공격자가 키를 틀려도 **통계적으로 무차별적인 데이터** 제공 → brute-force 판별 곤란 | 없음 (일반적) |

이 기능은 **Honey Encryption**의 간이 구현으로, AES에는 기본적으로 내장되지 않은 독자적 기능입니다.

### 5.2 HMAC-SHA256 기반 무결성

- CHOICRYPT는 암호화 전 **HMAC-SHA256**을 데이터 뒤에 붙입니다.
- 복호화 후 HMAC을 검증하여 **키 일치 여부를 암호학적으로 판별**하고, 불일치 시 Decoy를 출력합니다.
- AES-256은 일반적으로 **인증 암호(AEAD)**를 사용하여 기밀성+무결성을 동시에 보장합니다.

### 5.3 choidec Baseline Resolution Hardening

- `choidec`는 입력 파일명에서 `.choi` 확장자가 없을 경우 자동으로 보정합니다.
- `malloc` 실패 및 파일 누수 방지를 위한 안전한 메모리/파일 핸들링 적용
- 표준 출력(`/dev/stdout`)으로의 복호화도 안전하게 지원

---

## 6. 보안성 분석

| 관점 | CHOICRYPT | AES-256 |
|------|-----------|---------|
| **암호학적 검증** | ❌ 독자 설계 — 공개 분석 부족 | ✅ 수십 년간의 글로벌 암호분석 및 표준화 |
| **차분/선형 공격 저항** | 동적 S-Box + 프랙탈 혼란 + LARGE_PRIME 모듈러로 이론적 복잡도 증가 | 4라운드 이후 확실한 저항이 입증됨 |
| **사이드 채널 공격** | 소프트웨어 구현 — 타이밍/캐시 분석에 취약할 수 있음 | AES-NI 사용 시 하드웨어 레벨 보호 가능 |
| **양자 컴퓨팅** | Grover 알고리즘에 의해 이론상 128비트 보안 하락 (AES와 동일) | 동일 |
| **키 파생 강도** | PBKDF2 (100K iters) + 랜덤 nonce — 사전 공격 및 재사용 방지 | 모드/구현에 따라 다름 |
| **사용 권장** | 개인적 난독화/토큰 보관용 | 민감 데이터, 금융, 통신 등 범용 보안 |

> ⚠️ **중요**: CHOICRYPT는 학술적 호기심과 난독화 목적으로 설계되었습니다.  
> 현재까지의 암호학적 분석이 없는 **독자 암호(custom cipher)**이므로,  
> 생명/안전 관련 시스템이나 규제 환경에서는 **AES-256-GCM 등 표준 암호**를 사용하세요.

---

## 7. 성능 특성

| 항목 | CHOICRYPT | AES-256 |
|------|-----------|---------|
| **라운드당 연산** | 프랙탈 반복(6×32×16회) + 동적 S-Box + 수평 확산 | SubBytes + ShiftRows + MixColumns |
| **메모리 접근** | 동적 S-Box (256바이트, 캐시 친화적) | 고정 S-Box (동일) |
| **예상 처리량** | AES 소프트웨어 구현보다 느림 (32라운드 + 고비용 혼란 연산) | 소프트웨어: 빠름 / 하드웨어: 초고속 |
| **병렬화** | CTR 모드로 블록 단위 병렬 가능 | CTR/GCM 등 표준 모드로 완벽 병렬 가능 |

---

## 8. 난독화 및 보안 파이프라인 (Obfuscation & Security Pipeline)

프로젝트에는 CHOICRYPT 핵심 외에도 다양한 난독화 및 보안 강화 실험 모듈이 포함되어 있습니다.

### 8.1 Dark Silicon (`dark_silicon.c`)
- **Temporal Jitter**: `RDTSC` 기반 CPU 실행 지터 및 ASLR 엔트로피 수집
- **Fractal Manifold Map**: Julia Set 근사를 정수 고정 소수점으로 재구현 (부동소수점 사이드 채널 제거)
- **Code-as-Data**: 실행 코드 자체를 S-Box 마스크로 샘플링
- **Probabilistic Feistel**: 16라운드 비결정적 Feistel 네트워크 + Format-Preserving 암호화
- **Cryptographic Ghosting**: 잘못된 키 복호화 시에도 문법적으로 유효한 ASCII를 출력하는 Honey Encryption

### 8.2 Obfuscated Pipeline (`obfuscated_pipeline.c`)
- **Control Flow Flattening**: 상태 머신 기반 제어 흐름 난독화
- **Opaque Predicates**: `x² + x`가 항상 짝수임을 이용한 정적 분석 방해
- **Dynamic P-Box**: Galois LFSR 기반 Fisher-Yates 셔플 + Derangement 보장
- **Bit-Slicing S-Box**: 데이터 의존 분기 및 메모리 룩업 제거
- **Virtual Interpreter**: 동적 바이트코드(XOR, ROL, SLI)를 실행하는 가상 머신
- **Rolling Key**: 현재 라운드 출력이 다음 라운드 키에 영향을 주는 키 피드백

### 8.3 Dynamic ASM (`dynamic_asm.c`)
- **GF(2⁸) 연산**: AES 불가분 다항식 `0x11B` 위한 곱셈/역원
- **동적 라운드 연산**: 2비트 셀렉터에 따라 XOR / 산술 회전 / Galois 곱셈 / NOT+S-Box 4가지 연산 중 동적 선택
- **완전 가역성**: 모든 연산에 대한 역연산 보장

---

## 9. 보안 감사 및 검증 도구

### 9.1 `crypt_hardcore_audit.py`
NIST 수준의 암호 강도 감사 도구입니다.
- **Chi-Square 균일성 검정**: 암호문의 바이트 분포가 균일한지 통계적으로 검증
- **자기상관 분석(Autocorrelation)**: 내부 패턴 반복성 탐지
- **키-암호문 독립성**: 평문과 암호문의 XOR 차이가 키와 상관관계가 없는지 측정

### 9.2 `check_safety.sh`
통합 안전성 검증 스크립트입니다.
- 빌드 클린 및 재컴파일
- 64KB 무작위 샘플 데이터 생성
- 암호화 → 복호화 → 무결성 diff 검증
- 표준 출력 복호화 경로 검증
- `crypt_hardcore_audit.py` 자동 실행 및 리포트 저장

```bash
./check_safety.sh
```

---

## 10. 빌드 및 사용법

```bash
make

# 암호화
echo 'my_password' | ./choienc secret.txt
# → secret.txt.choi 생성 (16바이트 nonce + 암호문 + HMAC-SHA256)

# 복호화
echo 'my_password' | ./choidec secret.txt.choi decrypted.txt
# 또는 확장자 생략 가능
echo 'my_password' | ./choidec secret.txt decrypted.txt

# 비밀번호가 틀리면 HMAC-DRBG 기반 decoy 데이터가 생성됩니다.
```

---

## 11. 요약: 언제 무엇을 쓸까?

| 사용 시나리오 | 권장 |
|---------|------|
| **학술적 실험, 난독화, CTF** | CHOICRYPT ✅ |
| **GitHub 토큰, 개인 노트 등 경량 보관** | CHOICRYPT ✅ (Honey Encryption + PBKDF2 활용) |
| **생산 데이터베이스 암호화** | AES-256-GCM |
| **TLS/SSL 통신** | AES-256-GCM |
| **금융/의료/정부 규제 환경** | AES-256 (FIPS 140-2/3) |
| **양자 내구성이 필요한 장기 보관** | AES-256 (256비트 키는 Grover에도 128비트 보안 유지) |

---

## 라이선스

본 프로젝트는 학술 및 개인적 난독화 목적으로 제공됩니다.  
CHOICRYPT는 표준화된 암호가 아니므로, 중요한 보안 인프라에는 표준 암호화 라이브러리(OpenSSL, libsodium 등)를 사용하세요.
