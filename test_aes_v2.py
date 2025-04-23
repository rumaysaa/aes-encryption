#!/usr/bin/env python3
"""
Test script for AES encryption/decryption functionality using Python and C implementations.
This script compares the results of AES encryption/decryption between a C implementation and Python.
"""

import ctypes
import os
import random
import unittest

# Add aes submodule to path
import sys
sys.path.append('./aes')

# Import the AES implementation
try:
    from aes import AES, encrypt, decrypt
    # Import transformation functions if needed
    from aes import sub_bytes, shift_rows, mix_columns, add_round_key
except ImportError:
    print("Error: Could not import the AES implementation.")
    sys.exit(1)

def bytes2matrix(input_bytes):
    """Convert a 16-byte array to a 4x4 matrix (list of lists)."""
    matrix = []
    for i in range(4):
        row = list(input_bytes[i*4:(i+1)*4])
        matrix.append(row)
    return matrix

def matrix2bytes(matrix):
    """Convert a 4x4 matrix back to a 16-byte array."""
    output_bytes = []
    for row in matrix:
        output_bytes.extend(row)  # Flatten the matrix into a single list of bytes
    return bytes(output_bytes)

class TestAES(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Load C library for AES
        try:
            cls.rijndael = ctypes.CDLL('./rijndael.so')
        except OSError:
            print("Error: Could not load rijndael.so. Make sure the library is compiled.")
            sys.exit(1)
        
        # Setting up C function return types
        cls.rijndael.aes_encrypt_block.restype = ctypes.POINTER(ctypes.c_ubyte)
        cls.rijndael.aes_decrypt_block.restype = ctypes.POINTER(ctypes.c_ubyte)
        
    def test_aes_encryption(self):
        """Test AES encryption with random inputs"""
        for i in range(3):  # Test 3 random cases
            plaintext = bytes([random.randint(0, 255) for _ in range(16)])
            key = bytes([random.randint(0, 255) for _ in range(16)])

            print(f"\nTest {i+1}/3 - AES Encryption:")
            print(f"Plaintext: {plaintext.hex()}")
            print(f"Key: {key.hex()}")

            # C encryption
            c_plaintext = ctypes.create_string_buffer(plaintext)
            c_key = ctypes.create_string_buffer(key)
            c_ciphertext_ptr = self.rijndael.aes_encrypt_block(c_plaintext, c_key)
            c_ciphertext = bytes([c_ciphertext_ptr[i] for i in range(16)])

            # Python encryption
            py_aes = AES(key)
            py_ciphertext = py_aes.encrypt_block(plaintext)

            # Compare encryption results
            self.assertEqual(c_ciphertext, py_ciphertext,
                             f"Encryption mismatch: Plaintext={plaintext.hex()}, C={c_ciphertext.hex()}, Python={py_ciphertext.hex()}")

    def test_aes_decryption(self):
        """Test AES decryption with random inputs"""
        for i in range(3):  # Test 3 random cases
            ciphertext = bytes([random.randint(0, 255) for _ in range(16)])
            key = bytes([random.randint(0, 255) for _ in range(16)])

            print(f"\nTest {i+1}/3 - AES Decryption:")
            print(f"Ciphertext: {ciphertext.hex()}")
            print(f"Key: {key.hex()}")

            # C decryption
            c_ciphertext = ctypes.create_string_buffer(ciphertext)
            c_key = ctypes.create_string_buffer(key)
            c_decrypted_ptr = self.rijndael.aes_decrypt_block(c_ciphertext, c_key)
            c_decrypted = bytes([c_decrypted_ptr[i] for i in range(16)])

            # Python decryption
            py_aes = AES(key)
            py_decrypted = py_aes.decrypt_block(ciphertext)

            # Compare decryption results
            self.assertEqual(c_decrypted, ciphertext,
                             f"Decryption mismatch: Original={ciphertext.hex()}, C={c_decrypted.hex()}, Python={py_decrypted.hex()}")

    def test_round_function(self):
        """Test the individual AES round functions: SubBytes, ShiftRows, MixColumns"""
        for i in range(3):  # Test 3 random cases
            input_data = bytes([random.randint(0, 255) for _ in range(16)])
            input_copy = input_data[:]  # Make a copy for Python implementation

            # Apply round function in C
            c_block = ctypes.create_string_buffer(input_data)
            self.rijndael.sub_bytes(c_block)
            c_result = bytes(c_block)[:16]

            # Apply round function in Python
            py_matrix = bytes2matrix(input_copy)
            sub_bytes(py_matrix)
            py_result = matrix2bytes(py_matrix)

            # Compare results
            self.assertEqual(c_result, py_result,
                             f"Round function mismatch: Input={input_data.hex()}, C={c_result.hex()}, Python={py_result.hex()}")

if __name__ == '__main__':
    unittest.main()
