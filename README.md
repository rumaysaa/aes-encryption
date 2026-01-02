
# Repository Information Overview

## Repository Summary
Multi-project AES-128 encryption repository implementing the Rijndael algorithm in both C and Python. The C implementation provides a high-performance core with a shared library (rijndael.so), while the Python implementation serves as a reference and educational tool. Both implementations are tested against each other to ensure cryptographic correctness.

## Algorithm Overview: AES-128 (Advanced Encryption Standard)

The Advanced Encryption Standard (AES), also known as Rijndael, is a symmetric block cipher that encrypts and decrypts data in 128-bit blocks using cryptographic keys of 128, 192, or 256 bits. This implementation focuses on **AES-128** with a 128-bit (16-byte) key.

**How it works**:
1. **Key Expansion**: The original 16-byte key is expanded into a series of round keys (176 bytes total for 11 rounds in AES-128)
2. **Round Transformations** (10 rounds for AES-128):
   - **SubBytes**: Each byte is replaced using a substitution table (S-box)
   - **ShiftRows**: Rows of the internal state matrix are shifted left by varying amounts
   - **MixColumns**: Columns are multiplied with a fixed polynomial (provides diffusion)
   - **AddRoundKey**: XOR operation with the round key (provides confusion)
3. **Final Round**: Similar transformations without MixColumns

**Why it matters**: AES is the most widely used encryption standard for protecting sensitive data in government, finance, healthcare, and everyday applications (HTTPS, encrypted storage, etc.). It's been approved by the U.S. National Security Agency (NSA) for TOP SECRET classified information.

**In this repository**:
- The C implementation provides efficient block-level encryption/decryption
- The Python implementation demonstrates the algorithm clearly for educational purposes and serves as a reference for validation
- Integration tests ensure both implementations produce identical cryptographic results

## Repository Structure
- **Root level**: C implementation with build configuration and integration tests
- **aes/**: Python reference implementation as a git submodule
- **.github/workflows/**: CI/CD pipeline for automated testing
- **test_aes_v2.py**: Integration tests comparing C vs Python implementations (test_aes.py is deprecated)

### Main Repository Components
- **C Rijndael Implementation**: Core AES-128 block cipher with encryption/decryption and all round transformations
- **Python AES Reference**: Pure Python implementation with support for AES-128/192/256 and multiple modes (CBC, CTR, CFB, OFB, PCBC)
- **Testing Framework**: pytest-based integration tests and individual component validation

---

## Projects

### C Rijndael Implementation
**Configuration File**: `Makefile`

#### Language & Runtime
**Language**: C  
**Build System**: GNU Make  
**Compiler**: GCC or system default (cc)  
**Target**: Shared library (rijndael.so) and executable binary (main)

#### Key Components
- **rijndael.h**: Public API defining AES-128 functions (encrypt_block, decrypt_block, key expansion)
- **rijndael.c**: Core implementation (12.12 KB) with S-box tables and round transformations
- **main.c**: Demonstration program showing encrypt/decrypt workflow (1.24 KB)

#### Build & Installation
```bash
make all
```
Produces:
- `main`: Executable demonstration program
- `rijndael.so`: Shared library for use in other programs
- `rijndael.o`: Object file

**Clean**:
```bash
make clean
```

#### Testing
**Framework**: ctypes-based C library binding with Python test harness  
**Test File**: `test_aes_v2.py`  
**Test Location**: Root directory  
**Approach**: Validates C implementation against Python reference implementation  
**Note**: `test_aes.py` is a deprecated experimental file and should not be used

**Run Command**:
```bash
gcc -shared -o rijndael.so -fPIC rijndael.c
python3 -m pytest test_aes_v2.py -v
```

---

### Python AES Reference
**Configuration File**: `aes/README.md` (documentation), `requirements.txt` (dependencies)  
**Location**: `aes/` (git submodule)

#### Language & Runtime
**Language**: Python  
**Version**: 3.8+ (CI configured for Python 3.8)  
**Package Manager**: pip  
**Dependencies File**: `requirements.txt`

#### Main Dependencies
- **pytest**: Testing framework (development dependency)
- Built-in libraries only: `hashlib`, `hmac`, `secrets`, `io`

#### Key Components
- **aes.py**: Full AES implementation (549 lines) supporting AES-128/192/256 with multiple modes
- **tests.py**: Unit tests for block operations and high-level encrypt/decrypt functions

#### Features
- Pure Python implementation (no external crypto libraries)
- Supports AES-128, AES-192, and AES-256
- Block cipher modes: CBC (with PKCS#7 padding), CTR, CFB, OFB, PCBC
- Password-based encryption with PBKDF2 key derivation and HMAC authentication
- Reference implementation validated against NIST FIPS-197 standard

#### Build & Installation
```bash
pip install -r requirements.txt
```

#### Testing
**Framework**: unittest  
**Test File**: `aes/tests.py`  
**Naming Convention**: Methods prefixed with `test_`  
**Test Classes**: `TestBlock`, encryption/decryption validation

---

## CI/CD Pipeline

**Workflow File**: `.github/workflows/build.yml`  
**Trigger**: Pushes and pull requests to main branch  
**Environment**: Ubuntu latest

**Build Steps**:
1. Checkout with git submodules (aes/ submodule)
2. Set up Python 3.8
3. Install pip dependencies (pytest)
4. Install build-essential and libssl-dev
5. Compile C code: `gcc -shared -o rijndael.so -fPIC rijndael.c && make`
6. Run integration tests: `python3 -m pytest test_aes_v2.py -v`

---

## Integration Testing

**Test File**: `test_aes_v2.py`  
**Approach**: Compare C implementation against Python reference implementation using ctypes binding  
**Key Tests**:
- SubBytes transformation
- ShiftRows transformation
- MixColumns transformation
- AddRoundKey operation
- Full block encryption/decryption

**Validation**: Tests verify that C implementation produces identical output to the Python reference implementation.

**Note**: `test_aes.py` is an old experimental file and should not be used. All testing should use `test_aes_v2.py`.
