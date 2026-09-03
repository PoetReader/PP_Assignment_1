#include <stdio.h>
#include <stdint.h>
#include "aes256.h"
#include "utils.h"

#define CHARSET_SIZE 62

// Character set used for passwords [0-9a-zA-Z]
char CHARSET[CHARSET_SIZE]={
  '0','1', '2', '3', '4', '5', '6', '7', '8', '9',
  'a','b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
  'A','B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z'
};

int main(int argc, char *argv[]) {
  uint8_t key[AES_256_KEY_LENGTH]; // Stores the generate AES key
  uint8_t ciphertext[100]; // Stores encrypted data
  uint8_t plaintext[100]; // Stores decrypted data
  uint8_t plaintext_checksum[SHA512_DIGEST_LENGTH]; // Stores the original file sha512 sum
  uint8_t computed_checksum[SHA512_DIGEST_LENGTH]; // Stores the decrypted file sha512 sum
  char password[]="abc"; // Stores the user supplied password
  pbkdf2(password, 3, key); // Generate the AES-256 key from the password
  uint32_t ciphertext_length = file_load("./files/myfile.enc", ciphertext); // Load encrypted file into memory
  file_load("/files/myfile.sha512",plaintext_checksum); // Load the original file checksum
  int32_t plaintext_length=decrypt(ciphertext, ciphertext_length, key, plaintext); // Try to decrypt and retrieve the decripted file length
  if(plaintext_length>=0){ // Ensure decryption succeeded
	sha512sum(plaintext,plaintext_length,computed_checksum); // Compute decrypted data sha512 sum
	if(sha512cmp(plaintext_checksum,computed_checksum)){ // If sha512 match with the original file we succeeded
	  plaintext[plaintext_length]='\0'; // Make plaintext data "printable"
	  printf("Encrypted file contains: %s\n",plaintext); // Print decrypted data
	}
  }
  return 0;
}
