#ifndef SOREING_DES_H
#define SOREING_DES_H

#include <cstdint>

// Bit Location structure
// Used to get 1 bit from 8 bytes
struct bloc {
  uint8_t byte;	// Byte number in an 8 byte structure
	uint8_t mask;	// Bit mask to get a bit from 1 byte
};

extern const bloc DES_IP_BOX[];
extern const bloc DES_P_BOX[];
extern const bloc DES_PC1_BOX[];
extern const bloc DES_PC2_BOX[];
extern const int DES_SHIFT_BOX[];

// Encrypts 8 bytes of plaintext with a set of 16 round keys
void DES_Encrypt(const uint8_t data[8], const uint8_t roundKeys[16][8], uint8_t result[8], int round = 16);

// Deecrypts 8 bytes of ciphertext with a set of 16 round keys
void DES_Decrypt(const uint8_t data[8], const uint8_t roundKeys[16][8], uint8_t result[8]);

// Creates 16 round keys from an input of a 64bit key
void DES_CreateKeys(const uint8_t key[8], uint8_t roundKeys[16][8], int round);

void feistel(const uint8_t* input, const uint8_t* key, uint8_t* result);

void permutation(const uint8_t input[], const bloc box[], const int size, uint8_t result[]);

#endif