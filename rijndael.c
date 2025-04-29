/*
 * NAME: Rumaysa Babulkhair
 * STUDENT NUMBER: D24125711
 * Description: This file implements the AES-128 (Rijndael) block cipher in C,
 * providing functions to encrypt and decrypt 16-byte blocks using a 16-byte key.
 * The implementation includes key expansion, SubBytes, ShiftRows, MixColumns,
 * and their inverses, as well as AddRoundKey, following the AES-128 standard.
 * The code is tested against a Python reference implementation using unit tests
 */

#include <stdlib.h>
#include <string.h>
// TODO: Any other files you need to include should go here

#include "rijndael.h"

// Defining Constants

unsigned char S_BOX[256] = {
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B,
    0xFE, 0xD7, 0xAB, 0x76, 0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0,
    0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0, 0xB7, 0xFD, 0x93, 0x26,
    0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2,
    0xEB, 0x27, 0xB2, 0x75, 0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0,
    0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84, 0x53, 0xD1, 0x00, 0xED,
    0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F,
    0x50, 0x3C, 0x9F, 0xA8, 0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,
    0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2, 0xCD, 0x0C, 0x13, 0xEC,
    0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14,
    0xDE, 0x5E, 0x0B, 0xDB, 0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C,
    0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79, 0xE7, 0xC8, 0x37, 0x6D,
    0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F,
    0x4B, 0xBD, 0x8B, 0x8A, 0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,
    0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E, 0xE1, 0xF8, 0x98, 0x11,
    0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F,
    0xB0, 0x54, 0xBB, 0x16,
};

unsigned char INV_S_BOX[256] = {
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E,
    0x81, 0xF3, 0xD7, 0xFB, 0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87,
    0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB, 0x54, 0x7B, 0x94, 0x32,
    0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49,
    0x6D, 0x8B, 0xD1, 0x25, 0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16,
    0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92, 0x6C, 0x70, 0x48, 0x50,
    0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05,
    0xB8, 0xB3, 0x45, 0x06, 0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02,
    0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B, 0x3A, 0x91, 0x11, 0x41,
    0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8,
    0x1C, 0x75, 0xDF, 0x6E, 0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89,
    0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B, 0xFC, 0x56, 0x3E, 0x4B,
    0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59,
    0x27, 0x80, 0xEC, 0x5F, 0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D,
    0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF, 0xA0, 0xE0, 0x3B, 0x4D,
    0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63,
    0x55, 0x21, 0x0C, 0x7D,
};

/* Round constants for key expansion */
static const unsigned char Rcon[10] = {0x01, 0x02, 0x04, 0x08, 0x10,
                                       0x20, 0x40, 0x80, 0x1b, 0x36};

/*
 * Operations used when encrypting a block
 */
void sub_bytes(unsigned char *block) {
  for (int i = 0; i < BLOCK_SIZE; i++) {
    block[i] = S_BOX[block[i]];
  }
}

void shift_rows(unsigned char *block) {
  unsigned char temp;

  // Row 0: No shift (do nothing)

  // Row 1: Shift left by 1 [a, b, c, d] -> [b, c, d, a]
  temp = BLOCK_ACCESS(block, 1, 0);
  BLOCK_ACCESS(block, 1, 0) = BLOCK_ACCESS(block, 1, 1);
  BLOCK_ACCESS(block, 1, 1) = BLOCK_ACCESS(block, 1, 2);
  BLOCK_ACCESS(block, 1, 2) = BLOCK_ACCESS(block, 1, 3);
  BLOCK_ACCESS(block, 1, 3) = temp;

  // Row 2: Shift left by 2 [a, b, c, d] -> [c, d, a, b]
  temp = BLOCK_ACCESS(block, 2, 0);
  BLOCK_ACCESS(block, 2, 0) = BLOCK_ACCESS(block, 2, 2);
  BLOCK_ACCESS(block, 2, 2) = temp;
  temp = BLOCK_ACCESS(block, 2, 1);
  BLOCK_ACCESS(block, 2, 1) = BLOCK_ACCESS(block, 2, 3);
  BLOCK_ACCESS(block, 2, 3) = temp;

  // Row 3: Shift left by 3 [a, b, c, d] -> [d, a, b, c]
  temp = BLOCK_ACCESS(block, 3, 3);
  BLOCK_ACCESS(block, 3, 3) = BLOCK_ACCESS(block, 3, 2);
  BLOCK_ACCESS(block, 3, 2) = BLOCK_ACCESS(block, 3, 1);
  BLOCK_ACCESS(block, 3, 1) = BLOCK_ACCESS(block, 3, 0);
  BLOCK_ACCESS(block, 3, 0) = temp;
}

unsigned char xtime(unsigned char a) {
  if (a & 0x80) {
    return ((a << 1) ^ 0x1B) & 0xFF;
  } else {
    return (a << 1);
  }
}

void mix_single_column(unsigned char *a) {
  unsigned char t = a[0] ^ a[1] ^ a[2] ^ a[3];
  unsigned char u = a[0];
  a[0] ^= t ^ xtime(a[0] ^ a[1]);
  a[1] ^= t ^ xtime(a[1] ^ a[2]);
  a[2] ^= t ^ xtime(a[2] ^ a[3]);
  a[3] ^= t ^ xtime(a[3] ^ u);
}

void mix_columns(unsigned char *state) {
  unsigned char col[4];
  for (int i = 0; i < 4; i++) {
    // Get i-th column (column-major order)
    for (int j = 0; j < 4; j++) {
      col[j] = state[j + i * 4];  
    }

    // Mix it
    mix_single_column(col);

    // Store back
    for (int j = 0; j < 4; j++) {
      state[j + i * 4] = col[j]; 
    }
  }
}
/*
 * Operations used when decrypting a block
 */
void invert_sub_bytes(unsigned char *block) {
  for (int i = 0; i < BLOCK_SIZE; i++) {
    block[i] = INV_S_BOX[block[i]];
  }
}

void invert_shift_rows(unsigned char *block) {
  unsigned char temp;

  // Row 1: Shift right by 1
  temp = BLOCK_ACCESS(block, 1, 3);
  BLOCK_ACCESS(block, 1, 3) = BLOCK_ACCESS(block, 1, 2);
  BLOCK_ACCESS(block, 1, 2) = BLOCK_ACCESS(block, 1, 1);
  BLOCK_ACCESS(block, 1, 1) = BLOCK_ACCESS(block, 1, 0);
  BLOCK_ACCESS(block, 1, 0) = temp;

  // Row 2: Shift right by 2
  temp = BLOCK_ACCESS(block, 2, 0);
  BLOCK_ACCESS(block, 2, 0) = BLOCK_ACCESS(block, 2, 2);
  BLOCK_ACCESS(block, 2, 2) = temp;

  temp = BLOCK_ACCESS(block, 2, 1);
  BLOCK_ACCESS(block, 2, 1) = BLOCK_ACCESS(block, 2, 3);
  BLOCK_ACCESS(block, 2, 3) = temp;

  // Row3: Shift right by (equivalent to left by one)
  temp = BLOCK_ACCESS(block, 3, 0);
  BLOCK_ACCESS(block, 3, 0) = BLOCK_ACCESS(block, 3, 1);
  BLOCK_ACCESS(block, 3, 1) = BLOCK_ACCESS(block, 3, 2);
  BLOCK_ACCESS(block, 3, 2) = BLOCK_ACCESS(block, 3, 3);
  BLOCK_ACCESS(block, 3, 3) = temp;
}
// helper function for Galois multiplication
unsigned char gmul(unsigned char a, unsigned char b) {
  unsigned char result = 0;
  for (int i = 0; i < 8; i++) {
    if (b & 1) result ^= a;
    a = xtime(a);
    b >>= 1;
  }
  return result;
}
void invert_mix_columns(unsigned char *block) {
  unsigned char a[4];
  for (int i = 0; i < 4; i++) {
    // Extract the column
    for (int j = 0; j < 4; j++) {
      a[j] = BLOCK_ACCESS(block, j, i);
    }

    // Inverse MixColumns transformation
    BLOCK_ACCESS(block, 0, i) = gmul(a[0], 0x0E) ^ gmul(a[1], 0x0B) ^
                                gmul(a[2], 0x0D) ^ gmul(a[3], 0x09);
    BLOCK_ACCESS(block, 1, i) = gmul(a[0], 0x09) ^ gmul(a[1], 0x0E) ^
                                gmul(a[2], 0x0B) ^ gmul(a[3], 0x0D);
    BLOCK_ACCESS(block, 2, i) = gmul(a[0], 0x0D) ^ gmul(a[1], 0x09) ^
                                gmul(a[2], 0x0E) ^ gmul(a[3], 0x0B);
    BLOCK_ACCESS(block, 3, i) = gmul(a[0], 0x0B) ^ gmul(a[1], 0x0D) ^
                                gmul(a[2], 0x09) ^ gmul(a[3], 0x0E);
  }
}

/*
 * This operation is shared between encryption and decryption
 */
void add_round_key(unsigned char *block, unsigned char *round_key) {
  for (int i = 0; i < 4; i++) {
    for (int j = 0; j < 4; j++) {
      block[i * 4 + j] ^= round_key[i * 4 + j];
    }
  }
}

// Function to rotate a 4-byte word (used in key expansion)
void rot_word(unsigned char *word) {
  unsigned char temp = word[0];
  for (int i = 0; i < 3; i++) {
    word[i] = word[i + 1];
  }
  word[3] = temp;
}

// Function to apply the S-box transformation on a 4-byte word
void sub_word(unsigned char *word) {
  for (int i = 0; i < 4; i++) {
    word[i] = S_BOX[word[i]];
  }
}

/*
 * This function should expand the round key. Given an input,
 * which is a single 128-bit key, it should return a 176-byte
 * vector, containing the 11 round keys one after the other
 */
unsigned char *expand_key(unsigned char *cipher_key) {
  static unsigned char expanded_key[176];
  unsigned char temp[4];
  int i = 0;

  // Copy the initial cipher key into the expanded key array
  memcpy(expanded_key, cipher_key, KEY_SIZE);

  // Expand the key by iterating over the required number of rounds
  i = KEY_SIZE;
  while (i < EXPANDED_KEY_SIZE) {
    // Copy the previous word into the temp array
    memcpy(temp, expanded_key + (i - 4), 4);

    // Apply the key schedule core (if we are at a 16-byte boundary)
    if (i % KEY_SIZE == 0) {
      rot_word(temp);
      sub_word(temp);
      temp[0] ^= Rcon[(i / KEY_SIZE) - 1];  // Correct Rcon index
    }

    // XOR the temp word with the previous word
    for (int j = 0; j < 4; j++) {
      expanded_key[i] = expanded_key[i - KEY_SIZE] ^ temp[j];
      i++;
    }
  }

  return expanded_key;
}

/*
 * The implementations of the functions declared in the
 * header file should go here
 */
unsigned char *aes_encrypt_block(unsigned char *plaintext, unsigned char *key) {
  unsigned char *output =
      (unsigned char *)malloc(sizeof(unsigned char) * BLOCK_SIZE);

  if (output == NULL) {
    return NULL;  // Handle allocation failure
  }

  // Initialize output with the input block
  for (int i = 0; i < BLOCK_SIZE; i++) {
    output[i] = plaintext[i];
  }

  // Expand the key
  unsigned char *expanded_key = expand_key(key);

  // Initial round key addition
  add_round_key(output, expanded_key);

  // 9 main rounds
  for (int round = 1; round < NUM_ROUNDS; round++) {
    sub_bytes(output);
    shift_rows(output);
    mix_columns(output);
    add_round_key(output, expanded_key + round * BLOCK_SIZE);
  }

  // Final round (no mix_columns)
  sub_bytes(output);
  shift_rows(output);
  add_round_key(output, expanded_key + NUM_ROUNDS * BLOCK_SIZE);

  // Copy result back to plaintext to satisfy test's in-place expectation
  memcpy(plaintext, output, BLOCK_SIZE);

  // Free the allocated memory
  free(output);

  // Return plaintext (test expects block to be modified in place)
  return plaintext;
}

unsigned char *aes_decrypt_block(unsigned char *ciphertext,
                                 unsigned char *key) {
  // TODO: Implement me!
  unsigned char *output =
      (unsigned char *)malloc(sizeof(unsigned char) * BLOCK_SIZE);
  unsigned char state[BLOCK_SIZE];
  if (output == NULL) {
    return NULL;  // Handle allocation failure
  }

  // Initialize output with the input block
  for (int i = 0; i < BLOCK_SIZE; i++) {
    output[i] = ciphertext[i];
  }

  // Expand the key
  unsigned char *expanded_key = expand_key(key);

  // Initial AddRoundKey (with the last round key)
  add_round_key(output, expanded_key + NUM_ROUNDS * BLOCK_SIZE);

  // 9 main rounds
  for (int round = NUM_ROUNDS - 1; round > 0; round--) {
    invert_shift_rows(output);
    invert_sub_bytes(output);
    add_round_key(output, expanded_key + round * BLOCK_SIZE);
    invert_mix_columns(output);
  }

  // Final round (no inverse MixColumns)
  invert_shift_rows(output);
  invert_sub_bytes(output);
  add_round_key(output, expanded_key);

  // Copy result back to ciphertext to satisfy test's in-place expectation
  memcpy(ciphertext, output, BLOCK_SIZE);

  // Free the allocated memory
  free(output);

  // Return ciphertext (test expects block to be modified in place)
  return ciphertext;
}
