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

  int err = 0;
  // Validation of password length to avoid undefined behavior
  if (password_length <= 0 || password_length > 10)
  {
    if (rank == 0)
    {
      printf("Invalid password length %d\n", (int)password_length);
    }
    err = 1;
  }

  // Allocate buffers
  uint8_t key[AES_256_KEY_LENGTH];                  // Stores the generated AES key
  uint8_t *ciphertext = malloc(MAX_FILE_SIZE_B);    // Stores encrypted data
  uint8_t *plaintext = malloc(MAX_FILE_SIZE_B);     // Stores decrypted data
  uint8_t plaintext_checksum[SHA512_DIGEST_LENGTH]; // Stores the original file sha512 sum
  uint8_t computed_checksum[SHA512_DIGEST_LENGTH];  // Stores the decrypted file sha512 sum

  // Load encrypted file only on rank 0
  uint32_t ciphertext_length = 0;
  uint32_t sha_length = 0;

  if (rank == 0)
  {
    ciphertext_length = file_load(enc_path, ciphertext);
    if (ciphertext_length <= 0)
    {
      printf("Failed to load .enc file\n");
      err = 1;
    }
    sha_length = file_load(sha_path, plaintext_checksum);
    if (sha_length != SHA512_DIGEST_LENGTH)
    {
      printf("Failed to load .sha file\n");
      err = 1;
    }
  }

  // Broadcast the err to the other ranks
  MPI_Bcast(&err, 1, MPI_INT, 0, MPI_COMM_WORLD);
  if (err)
  {
    free(ciphertext);
    free(plaintext);
    MPI_Finalize();
    return 0;
  }

  // Broadcast ciphertext, length and checksum to all ranks
  MPI_Bcast(&ciphertext_length, 1, MPI_UINT32_T, 0, MPI_COMM_WORLD);
  MPI_Bcast(&sha_length, 1, MPI_UINT32_T, 0, MPI_COMM_WORLD);
  MPI_Bcast(ciphertext, ciphertext_length, MPI_UINT8_T, 0, MPI_COMM_WORLD);
  MPI_Bcast(plaintext_checksum, SHA512_DIGEST_LENGTH, MPI_UINT8_T, 0, MPI_COMM_WORLD);

  // Weak scaling
  // Workload per rank fixed to 5,000,000
  // As process count grows, total space scales proportionally
  
  int64_t range_per_rank = 5000000;
  int64_t start = rank * range_per_rank;
  int64_t end = start + range_per_rank;

  if (rank == 0)
  {
    printf("Weak scaling: Length = %ld, Work per rank = %ld, Total space = %ld with %d ranks\n",
           password_length, range_per_rank, range_per_rank * size, size);
  }

  // Potential password buffer with one extra byte for pbkdf2 and decrypt functions
  char *password = malloc(password_length + 1);
  uint8_t *password_index = malloc(password_length);

  int found = 0;
  int64_t reset_countdown = 100;
  int64_t countdown = reset_countdown;

  // Start timer
  MPI_Barrier(MPI_COMM_WORLD);
  struct timespec start_timer, end_timer;
  clock_gettime(CLOCK_MONOTONIC, &start_timer);

  // Initial setup for starting password based on `start` index
  int64_t k = start;
  for (int pos = password_length - 1; pos >= 0; pos--)
  {
    password_index[pos] = k % CHARSET_SIZE;
    password[pos] = CHARSET[password_index[pos]];
    k /= CHARSET_SIZE;
  }
  password[password_length] = '\0'; // Null-terminate string ONCE.

  // ---- Bruteforce loop ----
  for (int64_t counter = start; counter < end; counter++)
  {
    // Test password
    pbkdf2(password, password_length, key);

    // Key generation of current password
    int32_t plaintext_length = decrypt(ciphertext, ciphertext_length, key, plaintext);

    if (plaintext_length >= 0) // Check if decryption worked
    {
      sha512sum(plaintext, plaintext_length, computed_checksum);
      if (!sha512cmp(plaintext_checksum, computed_checksum))
      {
        plaintext[plaintext_length] = '\0';

        printf("Encrypted file contains: %s\n", plaintext);
        printf("Rank %d: The password to the file is: %s\n", rank, password);

        found = 1;

        // Notify other ranks
        for (int i = 0; i < size; i++)
        {
          if (i != rank)
          {
            int dummy_msg = 1;
            MPI_Request req;
            MPI_Isend(&dummy_msg, 1, MPI_INT, i, 0, MPI_COMM_WORLD, &req);
            MPI_Request_free(&req);
          }
        }
        break;
      }
    }

    // Periodic check if password has been found by another rank
    countdown--;
    if (countdown == 0)
    {
      countdown = reset_countdown;
      int flag = 0;
      MPI_Iprobe(MPI_ANY_SOURCE, 0, MPI_COMM_WORLD, &flag, MPI_STATUS_IGNORE);
      if (flag)
      {
        int msg = 0;
        MPI_Recv(&msg, 1, MPI_INT, MPI_ANY_SOURCE, 0, MPI_COMM_WORLD, MPI_STATUS_IGNORE);
        break;
      }
    }

    // Odometer increment to next password
    for (int pos = password_length - 1; pos >= 0; pos--)
    {
      password_index[pos]++;

      if (password_index[pos] < CHARSET_SIZE)
      {
        password[pos] = CHARSET[password_index[pos]];
        break;
      }

      password_index[pos] = 0;
      password[pos] = CHARSET[0];
    }
  }

  // Synchronize
  MPI_Barrier(MPI_COMM_WORLD);

  // Stop timer
  clock_gettime(CLOCK_MONOTONIC, &end_timer);
  double elapsed = (end_timer.tv_sec - start_timer.tv_sec) + (end_timer.tv_nsec - start_timer.tv_nsec) / 1e9;

  if (rank == 0)
  {
    printf("Weak Scaling Time: %.9f seconds\n", elapsed);
  }

  // Clean up resources
  free(ciphertext);
  free(plaintext);
  free(password);
  free(password_index);

  MPI_Finalize();
  return 0;
}