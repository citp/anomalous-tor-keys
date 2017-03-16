CFLAGS=-std=c99 -Wall -O4 -pthread -I./gmp-patched/include/ -Dmpz_raw_64
LDFLAGS=./gmp-patched/lib/libgmp.a

fastgcd: fastgcd.c
	$(CC) $(CFLAGS) $? $(LDFLAGS) -o $@

