#define _POSIX_C_SOURCE 199309L

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <mpi.h>

#include "aes256.h"
#include "utils.h"
#include "charset.h"

int main(int argc, char *argv[])
{
  // each chunk brute forces its own range now
  //  start measuring the time
  struct timespec start_timer, end_timer;
  clock_gettime(CLOCK_MONOTONIC, &start_timer);

  MPI_Init(&argc, &argv);
  int rank, size;
  MPI_Comm_rank(MPI_COMM_WORLD, &rank); // Why MPICOMM WORLD
  MPI_Comm_size(MPI_COMM_WORLD, &size); // COmment needed
  // test if input is valid
  if (argc != 4)
  {
    if (rank == 0)
    {
      printf("Missing something!\n%s <password_length> <.enc_file_path> <.sha512_file_path>\n", argv[0]);
    }
    MPI_Finalize();
    return 0;
  }

  // Parse given variables
  int password_length = atoi(argv[1]);
  const char *enc_path = argv[2];
  const char *sha_path = argv[3];

  // test so only rank 0 prints out, so only once
  if (rank == 0)
  {
    printf("Looking for password with length = %d\n", password_length);
  }

  // all ranks load buffer
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
    return 0;
  }

  uint32_t sha_length = file_load(sha_path, plaintext_checksum);
  if (sha_length != SHA512_DIGEST_LENGTH)
  {
    printf("Failed to load .sha file\n");
    return 1;
  }

  //-----------------
  char *password = malloc(password_length + 1); // declare password to be searched for

  int64_t total = 1; // declare variable to get total amount of possible passwords
  for (int i = 0; i < password_length; i++)
  {
    total *= CHARSET_SIZE;
  }

  // compute total, start and end of range for each rank to visualize it ranges will be printed of the according rank
  int64_t chunk = total / size;
  int64_t start = chunk * rank;
  int64_t end;
  if (rank == size - 1)
  {
    end = total;
  }
  else
  {
    end = start + chunk;
  }
  printf("Rank: %d range start: %ld, and end: %ld\n", rank, start, end);


  // flag to check if msg is to be send to the other ranks
  int found = 0;

  // bruteforce the password now.

  for (int64_t counter = start; counter < end; counter++)
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
      {                                                                       // If sha512 match with the original file we succeeded
        plaintext[plaintext_length] = '\0';                                   // Make plaintext data "printable"
        printf("Encrypted file contains: %s\n", plaintext);                   // Print decrypted data
        printf("Rank %d: The password to the file is: %s\n", rank, password); // Print the password

        // set found to 1
        found = 1;

        MPI_Request reqs[64];
        int rc = 0;
        for (int i = 0; i < size; i++) {
          if (i != rank) MPI_Isend(&found, 1, MPI_INT, i, 0, MPI_COMM_WORLD, &reqs[rc++]);
        }
        MPI_Waitall(rc, reqs, MPI_STATUSES_IGNORE);
        break;
      }
    }
    // check if password has been found by another rank
    int flag = 0;
    MPI_Iprobe(MPI_ANY_SOURCE, 0, MPI_COMM_WORLD, &flag, MPI_STATUS_IGNORE);
    if (flag)
    {
      // receive the msg and remove it
      int msg = 0;
      MPI_Recv(&msg, 1, MPI_INT, MPI_ANY_SOURCE, 0, MPI_COMM_WORLD, MPI_STATUS_IGNORE);
      break;
    }
  }
  if (!found)
  {
    printf("Rank %d: Password not found with given length %d or in this rank.\n", rank, password_length);
  }
    free(ciphertext); // free mem
  free(plaintext);  // free mem
  free(password);   // free mem

  MPI_Finalize();

  clock_gettime(CLOCK_MONOTONIC, &end_timer); // finish measuring the time
  double elapsed = (end_timer.tv_sec - start_timer.tv_sec) + (end_timer.tv_nsec - start_timer.tv_nsec) / 1e9;
  printf("Rank: %d Time: %.3f seconds\n", rank, elapsed);

  return 0;
}