
PROGS = blake2b blake2b-salt-personal ed25519 sha256 sha512 \
        x25519_base x25519_generic

RM = rm -f

all: $(PROGS)

blake2b: blake2b.c common.c
	$(CC) $(CFLAGS) -o blake2b blake2b.c common.c -lsodium

blake2b-salt-personal: blake2b-salt-personal.c common.c
	$(CC) $(CFLAGS) -o blake2b-salt-personal blake2b-salt-personal.c common.c -lsodium

ed25519: ed25519.c common.c
	$(CC) $(CFLAGS) -o ed25519 ed25519.c common.c -lsodium

sha256: sha256.c common.c
	$(CC) $(CFLAGS) -o sha256 sha256.c common.c -lsodium

sha512: sha512.c common.c
	$(CC) $(CFLAGS) -o sha512 sha512.c common.c -lsodium

x25519_base: x25519_base.c common.c
	$(CC) $(CFLAGS) -o x25519_base x25519_base.c common.c -lsodium

x25519_generic: x25519_generic.c common.c
	$(CC) $(CFLAGS) -o x25519_generic x25519_generic.c common.c -lsodium

clean:
	$(RM) $(PROGS)
