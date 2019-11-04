CC:=gcc
CFLAGS:=-g -Og
PROGS:=test_afalg_cipher

all: $(PROGS)
clean:
	rm -f $(PROGS)
