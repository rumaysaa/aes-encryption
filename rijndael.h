/*
 * TODO: Add your name and student number here, along with
 *       a brief description of this code.
 *  Name: Rumaysa Babulkhair
 * Student Number: D24125711
 * Description: This files contains the function declarations for the algorithm.
 */

#ifndef RIJNDAEL_H
#define RIJNDAEL_H

#define BLOCK_ACCESS(block, row, col) (block[(row * 4) + col])
#define BLOCK_SIZE 16

/*
 * These should be the main encrypt/decrypt functions (i.e. the main
 * entry point to the library for programmes hoping to use it to
 * encrypt or decrypt data)
 */
unsigned char *aes_encrypt_block(unsigned char *plaintext, unsigned char *key);
unsigned char *aes_decrypt_block(unsigned char *ciphertext, unsigned char *key);

/*
 * Function to perform the SubBytes operation
 */
void sub_bytes(unsigned char *block);
/*
 * Function to perform the shift rows operation
 */
void shift_rows(unsigned char *block);

#endif
