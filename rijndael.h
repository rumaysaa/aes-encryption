/*
 * Author: Rumaysa Babulkhair
 * Student Number: D24125711
 * Description: This header file declares the functions for an AES-128 (Rijndael)
 * block cipher implementation in C. It provides interfaces for encrypting and
 * decrypting 16-byte blocks using a 16-byte key, along with internal functions
 * for key expansion, SubBytes, ShiftRows, MixColumns, and their inverses.
 * The implementation is used in a shared library (rijndael.so) and tested
 * against a Python reference implementation.
 */

 #ifndef RIJNDAEL_H
 #define RIJNDAEL_H
 
 // Macro to access a 4x4 block as a matrix (column-major order)
 #define BLOCK_ACCESS(block, row, col) block[(col * 4) + row]
 
 // Size of an AES-128 block (16 bytes)
 #define BLOCK_SIZE 16
 
 // Constants defining AES key size, number of rounds, and expanded key size
 #define KEY_SIZE 16
 #define NUM_ROUNDS 10
 #define EXPANDED_KEY_SIZE (KEY_SIZE * (NUM_ROUNDS + 1))
 
 /*
  * Main functions for AES-128 encryption and decryption.
  * These are the primary entry points for programs using the library.
  */
 unsigned char *aes_encrypt_block(unsigned char *plaintext, unsigned char *key);
 unsigned char *aes_decrypt_block(unsigned char *ciphertext, unsigned char *key);
 
 /*
  * Internal functions for the AES-128 algorithm.
  * These implement the core transformations used in encryption and decryption.
  */
 void sub_bytes(unsigned char *block);           // Apply S-box substitution
 void shift_rows(unsigned char *block);          // Shift rows of the state matrix
 void mix_columns(unsigned char *block);         // Mix columns of the state matrix
 void add_round_key(unsigned char *block, unsigned char *round_key); // XOR with round key
 void invert_sub_bytes(unsigned char *block);    // Apply inverse S-box substitution
 void invert_shift_rows(unsigned char *block);   // Reverse shift rows
 void invert_mix_columns(unsigned char *block);  // Reverse mix columns
 unsigned char *expand_key(unsigned char *cipher_key); // Expand 16-byte key to 176 bytes
 
 #endif