#!/usr/bin/env python3
"""
Test script for AES SubBytes transformation (C implementation vs Python reference).
"""

import ctypes
import random
import sys
import unittest

# adding aes module in the path for Python implementation
sys.path.append('./aes')  

try:
    from aes import sub_bytes, bytes2matrix, matrix2bytes,shift_rows, mix_columns, inv_sub_bytes
    from aes import inv_shift_rows,inv_mix_columns,add_round_key
    from aes import AES


except ImportError:
    print("Error: Could not import the reference AES implementation.")
    sys.exit(1)

class TestAES(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Load the C library
        try:
            cls.rijndael = ctypes.CDLL('./rijndael.so')  
        except OSError:
            print("Error: Could not load rijndael.so. Make sure it's compiled and available.")
            sys.exit(1)

    def test_subbytes(self):
        """Test the SubBytes transformation"""
        for i in range(3):  # Test with 3 random inputs 
            # Generate random input block (16 bytes)
            input_data = bytes([random.randint(0, 255) for _ in range(16)])
            input_copy = input_data[:]  # Make a copy for Python implementation
            
            # Create C buffer for the input
            c_block = ctypes.create_string_buffer(input_data)
            
            # Apply SubBytes in C
            self.rijndael.sub_bytes(c_block)
            c_result = bytes(c_block)[:16]
            
            # Apply SubBytes in Python
            # Convert byte array to matrix for Python implementation
            py_matrix = bytes2matrix(input_copy)
            sub_bytes(py_matrix)
            py_result = matrix2bytes(py_matrix)
            
            # Compare results
            self.assertEqual(c_result, py_result, 
                             f"Test {i+1}/3: SubBytes mismatch: Input={input_data.hex()}, "
                             f"C result={c_result.hex()}, Python result={py_result.hex()}")

    def test_shiftrows(self):
        """Test the ShiftRows transformation"""
        for i in range(3):  # Test with 3 random inputs
            # Generate random input block (16 bytes)
            input_data = bytes([random.randint(0, 255) for _ in range(16)])
            input_copy = input_data[:]  # Make a copy for Python implementation
            
            # Create C buffer for the input
            c_block = ctypes.create_string_buffer(input_data)
            
            # Apply ShiftRows in C (from our C library)
            self.rijndael.shift_rows(c_block)
            c_result = bytes(c_block)[:16]
            
            # Apply ShiftRows in Python
            # Convert byte array to matrix for Python implementation
            py_matrix = bytes2matrix(input_copy)
            shift_rows(py_matrix)
            py_result = matrix2bytes(py_matrix)
            
            # Debug prints (optional)
            print(f"Test {i+1}/3:")
            print(f"Input data: {input_data.hex()}")
            print(f"C result: {c_result.hex()}")
            print(f"Python result: {py_result.hex()}")
            
            # Compare results
            self.assertEqual(c_result, py_result, 
                            f"Test {i+1}/3: ShiftRows mismatch: Input={input_data.hex()}, "
                            f"C result={c_result.hex()}, Python result={py_result.hex()}")
            

    def test_mixcolumns(self):
        """Test the MixColumns transformation"""
        for i in range(3):  # Test with 3 random inputs
            # Generate random input block (16 bytes)
            input_data = bytes([random.randint(0, 255) for _ in range(16)])
            input_copy = input_data[:]  # Make a copy for Python implementation
            
            # Create C buffer for the input
            c_block = ctypes.create_string_buffer(input_data)
            
            # Apply MixColumns in C (from our C library)
            self.rijndael.mix_columns(c_block)
            c_result = bytes(c_block)[:16]
            
            # Apply MixColumns in Python
            # Convert byte array to matrix for Python implementation
            py_matrix = bytes2matrix(input_copy)
            mix_columns(py_matrix)
            py_result = matrix2bytes(py_matrix)
            
            # Debug prints (optional)
            print(f"Test {i+1}/3:")
            print(f"Input data: {input_data.hex()}")
            print(f"C result: {c_result.hex()}")
            print(f"Python result: {py_result.hex()}")
            
            # Compare results
            self.assertEqual(c_result, py_result,
                             f"Test {i+1}/3: MixColumns mismatch: Input={input_data.hex()}, "
                             f"C result={c_result.hex()}, Python result={py_result.hex()}")

    def test_inv_subbytes(self):
        """Test the Inverse SubBytes transformation"""
        for i in range(3):  # Test with 3 random inputs
            # Generate random input block (16 bytes)
            input_data = bytes([random.randint(0, 255) for _ in range(16)])
            input_copy = input_data[:]  # Make a copy for Python implementation
            
            # Create C buffer for the input
            c_block = ctypes.create_string_buffer(input_data)
            
            # Apply Inverse SubBytes in C
            self.rijndael.invert_sub_bytes(c_block)
            c_result = bytes(c_block)[:16]
            
            # Apply Inverse SubBytes in Python
            # Convert byte array to matrix for Python implementation
            py_matrix = bytes2matrix(input_copy)
            inv_sub_bytes(py_matrix)
            py_result = matrix2bytes(py_matrix)
            
            # Debug prints (optional)
            print(f"Test {i+1}/3:")
            print(f"Input data: {input_data.hex()}")
            print(f"C result: {c_result.hex()}")
            print(f"Python result: {py_result.hex()}")
            
            # Compare results
            self.assertEqual(c_result, py_result, 
                             f"Test {i+1}/3: InvSubBytes mismatch: Input={input_data.hex()}, "
                             f"C result={c_result.hex()}, Python result={py_result.hex()}")
            
    def test_inv_shiftrows(self):
        """Test the Inverse ShiftRows transformation"""
        for i in range(3):  # Test with 3 random inputs
            # Generate random input block (16 bytes)
            input_data = bytes([random.randint(0, 255) for _ in range(16)])
            input_copy = input_data[:]  # Make a copy for Python implementation
            
            # Create C buffer for the input
            c_block = ctypes.create_string_buffer(input_data)
            
            # Apply Inverse ShiftRows in C
            self.rijndael.invert_shift_rows(c_block)
            c_result = bytes(c_block)[:16]
            
            # Apply Inverse ShiftRows in Python
            # Convert byte array to matrix for Python implementation
            py_matrix = bytes2matrix(input_copy)
            inv_shift_rows(py_matrix)
            py_result = matrix2bytes(py_matrix)
            
            # Debug prints (optional)
            print(f"Test {i+1}/3:")
            print(f"Input data: {input_data.hex()}")
            print(f"C result: {c_result.hex()}")
            print(f"Python result: {py_result.hex()}")
            
            # Compare results
            self.assertEqual(c_result, py_result, 
                             f"Test {i+1}/3: InvShiftRows mismatch: Input={input_data.hex()}, "
                             f"C result={c_result.hex()}, Python result={py_result.hex()}")

    def test_inv_mixcolumns(self):
        """Test the Inverse MixColumns transformation"""
        for i in range(3):  # Test with 3 random inputs
            # Generate random input block (16 bytes)
            input_data = bytes([random.randint(0, 255) for _ in range(16)])
            input_copy = input_data[:]  # Make a copy for Python implementation
            
            # Create C buffer for the input
            c_block = ctypes.create_string_buffer(input_data)
            
            # Apply Inverse MixColumns in C
            self.rijndael.invert_mix_columns(c_block)
            c_result = bytes(c_block)[:16]
            
            # Apply Inverse MixColumns in Python
            # Convert byte array to matrix for Python implementation
            py_matrix = bytes2matrix(input_copy)
            inv_mix_columns(py_matrix)
            py_result = matrix2bytes(py_matrix)
            
            # Debug prints (optional)
            print(f"Test {i+1}/3:")
            print(f"Input data: {input_data.hex()}")
            print(f"C result: {c_result.hex()}")
            print(f"Python result: {py_result.hex()}")
            
            # Compare results
            self.assertEqual(c_result, py_result,
                             f"Test {i+1}/3: InvMixColumns mismatch: Input={input_data.hex()}, "
                             f"C result={c_result.hex()}, Python result={py_result.hex()}")
            
    def test_addroundkey(self):
        """Test the AddRoundKey transformation"""
        for i in range(3):  # Test with 3 random inputs
            # Generate random input block and key (16 bytes each)
            input_data = bytes([random.randint(0, 255) for _ in range(16)])
            key_data = bytes([random.randint(0, 255) for _ in range(16)])
            input_copy = input_data[:]  # Make a copy for Python implementation
            
            # Create C buffers for the input and key
            c_block = ctypes.create_string_buffer(input_data)
            c_key = ctypes.create_string_buffer(key_data)
            
            # Apply AddRoundKey in C
            self.rijndael.add_round_key(c_block, c_key)
            c_result = bytes(c_block)[:16]
            
            # Apply AddRoundKey in Python
            # Convert byte arrays to matrices for Python implementation
            py_state_matrix = bytes2matrix(input_copy)
            py_key_matrix = bytes2matrix(key_data)
            add_round_key(py_state_matrix, py_key_matrix)
            py_result = matrix2bytes(py_state_matrix)
            
            # Debug prints (optional)
            print(f"Test {i+1}/3:")
            print(f"Input data: {input_data.hex()}")
            print(f"Key data: {key_data.hex()}")
            print(f"C result: {c_result.hex()}")
            print(f"Python result: {py_result.hex()}")
            
            # Compare results
            self.assertEqual(c_result, py_result,
                             f"Test {i+1}/3: AddRoundKey mismatch: Input={input_data.hex()}, "
                             f"Key={key_data.hex()}, C result={c_result.hex()}, Python result={py_result.hex()}")
            
    def test_encrypt(self):
        """Test the full AES encryption"""
        for i in range(3):  # Test with 3 random inputs
            # Generate random plaintext and key (16 bytes each)
            plaintext = bytes([random.randint(0, 255) for _ in range(16)])
            key = bytes([random.randint(0, 255) for _ in range(16)])
            plaintext_copy = plaintext[:]  # Make a copy for Python implementation
            
            # Create C buffers for the plaintext and key
            c_block = ctypes.create_string_buffer(plaintext)
            c_key = ctypes.create_string_buffer(key)
            
            # Apply AES encryption in C
            self.rijndael.aes_encrypt_block(c_block, c_key)
            c_result = bytes(c_block)[:16]
            
            # Apply AES encryption in Python using AES class
            aes = AES(key)  # Initialize with 16-byte key
            py_result = aes.encrypt_block(plaintext_copy)
            
            # Debug prints
            print(f"Test {i+1}/3:")
            print(f"Plaintext: {plaintext.hex()}")
            print(f"Key: {key.hex()}")
            print(f"C result: {c_result.hex()}")
            print(f"Python result: {py_result.hex()}")
            
            # Compare results
            self.assertEqual(c_result, py_result,
                            f"Test {i+1}/3: Encrypt mismatch: Plaintext={plaintext.hex()}, "
                            f"Key={key.hex()}, C result={c_result.hex()}, Python result={py_result.hex()}")

      
    def test_decrypt(self):
        """Test the full AES decryption"""
        for i in range(3):  # Test with 3 random inputs
            # Generate random ciphertext and key (16 bytes each)
            ciphertext = bytes([random.randint(0, 255) for _ in range(16)])
            key = bytes([random.randint(0, 255) for _ in range(16)])
            ciphertext_copy = ciphertext[:]  # Make a copy for Python implementation
            
            # Create C buffers for the ciphertext and key
            c_block = ctypes.create_string_buffer(ciphertext)
            c_key = ctypes.create_string_buffer(key)
            
            # Apply AES decryption in C
            self.rijndael.aes_decrypt_block(c_block, c_key)
            c_result = bytes(c_block)[:16]
            
            # Apply AES decryption in Python using AES class
            aes = AES(key)  # Initialize with 16-byte key
            py_result = aes.decrypt_block(ciphertext_copy)
            
            # Debug prints
            print(f"Test {i+1}/3:")
            print(f"Ciphertext: {ciphertext.hex()}")
            print(f"Key: {key.hex()}")
            print(f"C result: {c_result.hex()}")
            print(f"Python result: {py_result.hex()}")
            
            # Compare results
            self.assertEqual(c_result, py_result,
                            f"Test {i+1}/3: Decrypt mismatch: Ciphertext={ciphertext.hex()}, "
                            f"Key={key.hex()}, C result={c_result.hex()}, Python result={py_result.hex()}")
            
if __name__ == '__main__':
    unittest.main()
