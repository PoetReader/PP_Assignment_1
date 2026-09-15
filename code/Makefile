all: main encrypt

main: main.c aes256.c utils.c charset.c
	gcc $^ -o $@ -lcrypto

brute: brute_seq.c aes256.c utils.c charset.c
	gcc $^ -o $@ -lcrypto

encrypt: encrypt.c aes256.c utils.c
	gcc $^ -o $@ -lcrypto

mainMPI: mainMPI.c aes256.c utils.c charset.c
	mpicc $^ -o $@ -lcrypto

optMPI: mainMPI_opt.c aes256.c utils.c charset.c
	mpicc $^ -o $@ -lcrypto


clean:
	@rm main encrypt brute
