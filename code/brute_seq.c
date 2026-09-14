#define _POSIX_C_SOURCE 199309L

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "aes256.h"
#include "utils.h"
#include "charset.h"

int main(int argc, char *argv[])
{

  // Check if correct number of arguments have been passed
  if (argc != 4)
  {
    printf("Missing something!\n%s <password_length> <.enc_file_path> <.sha512_file_path>\n", argv[0]);
    return 1;
  }
  // Parse given variables
  int password_length = atoi(argv[1]);
  const char *enc_path = argv[2];
  const char *sha_path = argv[3];
  // alloc buffer
  uint8_t key[AES_256_KEY_LENGTH];                  // Stores the generate AES key
  uint8_t *ciphertext = malloc(MAX_FILE_SIZE_B);    // Stores encrypted data
  uint8_t *plaintext = malloc(MAX_FILE_SIZE_B);     // Stores decrypted data
  uint8_t plaintext_checksum[SHA512_DIGEST_LENGTH]; // Stores the original file sha512 sum
  uint8_t computed_checksum[SHA512_DIGEST_LENGTH];  // Stores the decrypted file sha512 sum

  // load files from argv
  uint32_t ciphertext_length = file_load(enc_path, ciphertext);
  if (ciphertext_length <= 0)
  {
    printf("Failed to load .enc file\n");
    return 1;
  }

  uint32_t sha_length = file_load(sha_path, plaintext_checksum);

  if (sha_length != SHA512_DIGEST_LENGTH)
  {
    printf("Failed to load .sha file\n");
    return 1;
  
  }

  // testing it with single password
  /*
  char password[] = "abc";
  int length = 3;
  pbkdf2(password, length, key);
  int32_t plaintext_length = decrypt(ciphertext, ciphertext_length, key, plaintext);
  if (plaintext_length > 0)
  {
    sha512sum(plaintext, plaintext_length, computed_checksum);
    int32_t cmp = sha512cmp(plaintext_checksum, computed_checksum);
    if (cmp == 0)
    {
      printf("Password found: %s\n", password);
    } else
    {
      printf("Password wrong");
    }

  }
  */

  printf("Looking for password with length: %d\n", password_length);
  char *password = malloc(password_length + 1); // declare password to be searched for

  int64_t total = 1; // declare variable to get total amount of possible passwords
  for (int i = 0; i < password_length; i++)
  {
    total *= CHARSET_SIZE;
  }

  // start measuring the time
  struct timespec start, end;
  clock_gettime(CLOCK_MONOTONIC, &start);
  // bruteforce the password now.
  for (int64_t counter = 0; counter < total; counter++)
  {
    // variable n used to convert the counter to the password according to the CHARSET
    int64_t n = counter;
    // start with the most right position of the password
    for (int pos = password_length - 1; pos >= 0; pos--)
    {
      // using the base to CHARSET_SIZE (which is 62)
      // convert n to the password char by char
      password[pos] = CHARSET[n % CHARSET_SIZE];
      n /= CHARSET_SIZE;
    }
    password[password_length] = '\0'; // add the null terminator

    // test password
    pbkdf2(password, password_length, key);                                            // key generation of current password
    int32_t plaintext_length = decrypt(ciphertext, ciphertext_length, key, plaintext); // decryption with generated key
    if (plaintext_length >= 0)                                                         // check if decription has worked
    {
      sha512sum(plaintext, plaintext_length, computed_checksum); // Compute decrypted data sha512 sum
      if (!sha512cmp(plaintext_checksum, computed_checksum))
      {                                                        // If sha512 match with the original file we succeeded
        plaintext[plaintext_length] = '\0';                    // Make plaintext data "printable"
        printf("Encrypted file contains: %s\n", plaintext);    // Print decrypted data
        printf("The password to the file is: %s\n", password); // Print the password
        clock_gettime(CLOCK_MONOTONIC, &end);                  // finish measuring the time
        double elapsed = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
        printf("Time: %.3f seconds\n", elapsed);
        free(ciphertext); // free mem
        free(plaintext);  // free mem
        free(password); //free mem
        return 0;
      }
    }
  }

  printf("Password not found with given length: %d\n", password_length);
  clock_gettime(CLOCK_MONOTONIC, &end); // finish measuring the time
  double elapsed = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
  printf("Time: %.3f seconds\n", elapsed);
  free(ciphertext); // free mem
  free(plaintext);  // free mem
  free(password); //free mem

  return 1;
}