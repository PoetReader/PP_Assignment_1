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
  // Init MPI environment
  MPI_Init(&argc, &argv);

  int rank; // Id for the processes
  int size; // Total number of processes
  MPI_Comm_rank(MPI_COMM_WORLD, &rank);
  MPI_Comm_size(MPI_COMM_WORLD, &size);

  // Validation of input arguments: Program expects three arguments (password_length, .enc path, .sha512 path)
  if (argc != 4)
  {
    if (rank == 0)
    { // Only rank 0 prints to avoid duplication
      printf("Missing something!\n%s <password_length> <.enc_file_path> <.sha512_file_path>\n", argv[0]);
    }
    MPI_Finalize();
    return 0;
  }

  // Parse arguments
  int64_t password_length = atoi(argv[1]); // Password length to brute force
  const char *enc_path = argv[2];          // Path to encrypted file
  const char *sha_path = argv[3];          // Path to expected sha512 checksum

  // Validation of password length to avoid undefined behavior
  if (password_length <= 0 || password_length > 10)
  {
    if (rank == 0)
    {
      printf("Invalid password length %d\n", password_length);
    }
    MPI_Finalize();
    return 0;
  }

  // Info msg printed by rank 0
  if (rank == 0)
  {
    printf("Looking for password with length = %d with %d processes\n", password_length, size);
  }

  // Allocate buffers; each rank allocates their own buffers to read encrypted file and checksum for independence.
  // No communication needed
  uint8_t key[AES_256_KEY_LENGTH];                  // Stores the generate AES key
  uint8_t *ciphertext = malloc(MAX_FILE_SIZE_B);    // Stores encrypted data
  uint8_t *plaintext = malloc(MAX_FILE_SIZE_B);     // Stores decrypted data
  uint8_t plaintext_checksum[SHA512_DIGEST_LENGTH]; // Stores the original file sha512 sum
  uint8_t computed_checksum[SHA512_DIGEST_LENGTH];  // Stores the decrypted file sha512 sum

  // load encrypted file
  uint32_t ciphertext_length = file_load(enc_path, ciphertext);
  if (ciphertext_length <= 0)
  {
    printf("Failed to load .enc file\n");
    free(ciphertext); // free mem
    free(plaintext);  // free mem
    MPI_Finalize();
    return 0;
  }

  uint32_t sha_length = file_load(sha_path, plaintext_checksum);
  if (sha_length != SHA512_DIGEST_LENGTH)
  {
    printf("Failed to load .sha file\n");
    free(ciphertext); // free mem
    free(plaintext);  // free mem
    MPI_Finalize();
    return 0;
  }

  // Compute range size per process
  // total = CHARSET_SIZE ^ password_length
  int64_t total = 1; // int64_t larger length exceed range
  for (int i = 0; i < password_length; i++)
  {
    total *= CHARSET_SIZE;
  }

  // Data partitioning: Range is split into chunks. The last chunk absorbs remainder
  int64_t chunk = total / size;
  int64_t start = chunk * rank; // First password index for according rank
  int64_t end;
  if (rank == size - 1)
  {
    end = total; // Last rank takes the remainder
  }
  else
  {
    end = start + chunk;
  }

  // Potential password buffer with one extra byte for pbkdf2 and decrypt functions
  char *password = malloc(password_length + 1);

  // State for found password: 1 if this rank has found the password (found is set if a match has been found)
  // Fellow ranks are informed over MPI_ISend
  int found = 0;

  // Helper variables to call MPI_IProbe periodically and not in every loop iteration
  int reset_countdown = 100;
  int countdown = reset_countdown;

  // Start timer
  MPI_Barrier(MPI_COMM_WORLD);
  struct timespec start_timer, end_timer;
  clock_gettime(CLOCK_MONOTONIC, &start_timer);

  // ---- Bruteforce loop ----
  for (int64_t counter = start; counter < end; counter++)
  {
    // Convert the candidate index into a CHARSET_SIZE string.
    int64_t n = counter;
    // Start with the most right position of the password
    for (int pos = password_length - 1; pos >= 0; pos--)
    {
      password[pos] = CHARSET[n % CHARSET_SIZE];
      n /= CHARSET_SIZE;
    }
    password[password_length] = '\0'; // Add the null terminator

    // Attemt decryption with password
    pbkdf2(password, password_length, key);                                            // Key generation of current password
    int32_t plaintext_length = decrypt(ciphertext, ciphertext_length, key, plaintext); // Decryption with generated key
    if (plaintext_length >= 0)                                                         // Check if decription has worked
    {
      sha512sum(plaintext, plaintext_length, computed_checksum); // Compute decrypted data sha512 sum
      if (!sha512cmp(plaintext_checksum, computed_checksum))
      {                                                                       // If sha512 match with the original file we succeeded
        plaintext[plaintext_length] = '\0';                                   // Make plaintext data "printable"
        printf("Encrypted file contains: %s\n", plaintext);                   // Print decrypted data
        printf("Rank %d: The password to the file is: %s\n", rank, password); // Print the password

        found = 1;

        // Notify other ranks that password has been found, so the search is over
        MPI_Request reqs[size];
        int request_count = 0;
        for (int i = 0; i < size; i++)
        {
          if (i != rank)
            MPI_Isend(&found, 1, MPI_INT, i, 0, MPI_COMM_WORLD, &reqs[request_count++]);
        }
        // If another rank has finished the loop -> Wait all
        MPI_Waitall(request_count, reqs, MPI_STATUSES_IGNORE);
        break; // Stop the search
      }
    }
    // Check if password has been found by another rank
    countdown--;
    if (countdown == 0)
    {
      countdown = reset_countdown;

      int flag = 0;
      MPI_Iprobe(MPI_ANY_SOURCE, 0, MPI_COMM_WORLD, &flag, MPI_STATUS_IGNORE);
      if (flag)
      {
        // Receive the msg and remove it
        int msg = 0;
        MPI_Recv(&msg, 1, MPI_INT, MPI_ANY_SOURCE, 0, MPI_COMM_WORLD, MPI_STATUS_IGNORE);
        break; // Other rank has found the password -> Stop the search
      }
    }
  }
  // Print failure if this rank has not found the password
  /*
  if (!found)
  {
    printf("Rank %d: Password not found with given length %d or in this rank.\n", rank, password_length);
  }*/
  // Synchronize
  MPI_Barrier(MPI_COMM_WORLD);

  // Stop timer
  clock_gettime(CLOCK_MONOTONIC, &end_timer); // finish measuring the time
  double elapsed = (end_timer.tv_sec - start_timer.tv_sec) + (end_timer.tv_nsec - start_timer.tv_nsec) / 1e9;

  // Only one rank prints measured time
  if (rank == 0)
  {
  printf("Time: %.9f seconds\n", elapsed);
  }
  

  // Clean
  free(ciphertext); // free mem
  free(plaintext);  // free mem
  free(password);   // free mem

  MPI_Finalize();
  return 0;
}