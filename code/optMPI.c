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



  // all ranks load buffer
  uint8_t key[AES_256_KEY_LENGTH];                  // Stores the generate AES key
  uint8_t *ciphertext = malloc(MAX_FILE_SIZE_B);    // Stores encrypted data
  uint8_t *plaintext = malloc(MAX_FILE_SIZE_B);     // Stores decrypted data
  uint8_t plaintext_checksum[SHA512_DIGEST_LENGTH]; // Stores the original file sha512 sum
  uint8_t computed_checksum[SHA512_DIGEST_LENGTH];  // Stores the decrypted file sha512 sum

  // load files from argv

  uint32_t ciphertext_length = 0;
  uint32_t sha_length = 0;

if (rank == 0) {
    ciphertext_length = file_load(enc_path, ciphertext);
    if (ciphertext_length <= 0)
  {
    printf("Failed to load .enc file\n");
    MPI_Finalize();
    return 0;
  }
    sha_length = file_load(sha_path, plaintext_checksum);
    if (sha_length != SHA512_DIGEST_LENGTH)
  {
    printf("Failed to load .sha file\n");
    MPI_Finalize();
    return 0;
  }
}

MPI_Bcast(&ciphertext_length, 1, MPI_UINT32_T, 0, MPI_COMM_WORLD);
MPI_Bcast(&sha_length, 1, MPI_UINT32_T, 0, MPI_COMM_WORLD);
MPI_Bcast(ciphertext, ciphertext_length, MPI_UINT8_T, 0, MPI_COMM_WORLD);
MPI_Bcast(plaintext_checksum, SHA512_DIGEST_LENGTH, MPI_UINT8_T, 0, MPI_COMM_WORLD);

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
  //printf("Rank: %d range start: %ld, and end: %ld\n", rank, start, end);

 
  // flag to check if msg is to be send to the other ranks
  int found = 0;

  // optimization: add reset_countdown and countdown variable for periodic MPI_Iprobe call
  int64_t reset_countdown = 100;
  if (total < 100)
  {
    reset_countdown = 1;
  } // if the total number of
  int64_t countdown = reset_countdown;
  // flag for checking across ranks if password was found
  int flag = 0;

  // opt. turing the password into integer
  uint8_t password_index[password_length];

  int64_t n = start;
  // variable n used to find the starting password as an integer array of a ranks range
  // steup once per rank
  for (int pos = password_length - 1; pos >= 0; pos--)
  {
    password_index[pos] = n % CHARSET_SIZE;
    n /= CHARSET_SIZE;
  }



  
  // bruteforce the password now.
  for (int64_t counter = start; counter < end; counter++)
  {
   
    // build string from password to test
    for (int pos = 0; pos < password_length; pos++)
    {
      password[pos] = CHARSET[password_index[pos]];
    }
    password[password_length] = '\0';

     // each chunk brute forces its own range now


    // test password
    pbkdf2(password, password_length, key); 
    



    // key generation of current password
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

        // send msg to the other ranks that password has been found
        for (int i = 0; i < size; i++)
        {
          if (i != rank)
          {
            MPI_Send(&found, 1, MPI_INT, i, 0, MPI_COMM_WORLD);
          }
        }
        break;
      }
 
        
    }
    // check if password has been found by another rank
    // opt: to improve the usage of resources MPI_Iprobe called periodically
    
    countdown--;
    if (countdown == 0)
    {
      countdown = reset_countdown;
      int flag = 0;
  MPI_Iprobe(MPI_ANY_SOURCE, 0, MPI_COMM_WORLD, &flag, MPI_STATUS_IGNORE);
  if (flag)
  {
    // receive the msg and remove it
    int msg = 0;
    MPI_Recv(&msg, 1, MPI_INT, MPI_ANY_SOURCE, 0, MPI_COMM_WORLD, MPI_STATUS_IGNORE);
  }
      if (flag)
      {
        break;
      }
    }

    // decrement to the next password like an odometer
    for (int pos = password_length - 1; pos >= 0; pos--)
    {
      // increment to the next password starting from most right number
      password_index[pos]++;
      if (password_index[pos] < CHARSET_SIZE)
      {
        break;
      }
      // if position has reached 61 in Charset, the current position will be reset to 0
      password_index[pos] = 0;
    }

  }
  if (!found)
  {
    // check for msgs before calling MPI_Finalize()
    int flag = 0;
  MPI_Iprobe(MPI_ANY_SOURCE, 0, MPI_COMM_WORLD, &flag, MPI_STATUS_IGNORE);
  if (flag)
  {
    // receive the msg and remove it
    int msg = 0;
    MPI_Recv(&msg, 1, MPI_INT, MPI_ANY_SOURCE, 0, MPI_COMM_WORLD, MPI_STATUS_IGNORE);
  }
  }
                 //stop timer


  free(ciphertext); // free mem
  free(plaintext);  // free mem
  free(password);   // free mem

  MPI_Finalize();
      clock_gettime(CLOCK_MONOTONIC, &end_timer); // finish measuring the time
  double elapsed = (end_timer.tv_sec - start_timer.tv_sec) + (end_timer.tv_nsec - start_timer.tv_nsec) / 1e9;
  printf("Testing timing of beginning ---- Rank: %d Time: %.9f seconds\n", rank, elapsed);


  return 0;
}