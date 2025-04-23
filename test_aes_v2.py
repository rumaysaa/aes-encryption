#!/usr/bin/env python3
"""
Test script for AES SubBytes transformation (C implementation vs Python reference).
"""

import ctypes
import random
import sys
import unittest

# Ensure aes module is in the path for Python implementation
sys.path.append('./aes')  # Adjust this path if needed

try:
    from aes import sub_bytes, bytes2matrix, matrix2bytes
except ImportError:
    print("Error: Could not import the reference AES implementation.")
    sys.exit(1)

class TestAES(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Load the C library
        try:
            cls.rijndael = ctypes.CDLL('./rijndael.so')  # Ensure this is the correct path
        except OSError:
            print("Error: Could not load rijndael.so. Make sure it's compiled and available.")
            sys.exit(1)

    def test_subbytes(self):
        """Test the SubBytes transformation"""
        for i in range(3):  # Test with 3 random inputs as required
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

if __name__ == '__main__':
    unittest.main()
