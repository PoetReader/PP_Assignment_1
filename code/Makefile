all: main encrypt

main: main.c aes256.c utils.c
	gcc $^ -o $@ -lcrypto

encrypt: encrypt.c aes256.c utils.c
	gcc $^ -o $@ -lcrypto

mainMPI: mainMPI.c aes256.c utils.c
	mpicc $^ -o $@ -lcrypto

clean:
	@rm main encrypt
