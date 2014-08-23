all: blake2b sha256 sha512

blake2b: blake2b.c common.c
	$(CC) $(CFLAGS) -o blake2b blake2b.c common.c -lsodium

sha256: sha256.c common.c
	$(CC) $(CFLAGS) -o sha256 sha256.c common.c -lsodium

sha512: sha512.c common.c
	$(CC) $(CFLAGS) -o sha512 sha512.c common.c -lsodium

