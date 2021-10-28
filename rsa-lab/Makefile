CC=gcc

all: genkeys modexp

genkeys: genkeys.c
	${CC} -o genkeys genkeys.c -lcrypto

modexp: modexp.c
	${CC} -o modexp modexp.c -lcrypto



clean:
	- rm -f genkeys modexp decrypt