/*
 * TODO: Add your name and student number here, along with
 *       a brief description of this code.
 *  Name: Rumaysa Babulkhair
 * Student Number: D24125711
 * Description: This files contains the function declarations for the algorithm.
 */

#ifndef RIJNDAEL_H
#define RIJNDAEL_H

#define BLOCK_ACCESS(block, row, col) block[(col * 4) + row]
#define BLOCK_SIZE 16

/*
// Constants defining AES key size, number of rounds, and expanded key size
*/
#define KEY_SIZE 16
#define NUM_ROUNDS 10
#define EXPANDED_KEY_SIZE (KEY_SIZE * (NUM_ROUNDS + 1))

/*
 * These should be the main encrypt/decrypt functions (i.e. the main
 * entry point to the library for programmes hoping to use it to
 * encrypt or decrypt data)
 */
unsigned char *aes_encrypt_block(unsigned char *plaintext, unsigned char *key);
unsigned char *aes_decrypt_block(unsigned char *ciphertext, unsigned char *key);

/*
 * Internal functions used to implement the AES algorithm
 */
void sub_bytes(unsigned char *block);
void shift_rows(unsigned char *block);
void mix_columns(unsigned char *block);
void add_round_key(unsigned char *block, unsigned char *round_key);
void invert_sub_bytes(unsigned char *block);
void invert_shift_rows(unsigned char *block);
void invert_mix_columns(unsigned char *block);
unsigned char *expand_key(unsigned char *cipher_key);

#endif
