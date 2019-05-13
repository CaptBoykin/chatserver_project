LDFLAGS	= -lssl -lcrypto -lsqlite3
CWD	= $(shell pwd)
CSRC	= $(wildcard src/*.c)
OBJ	= $(CSRC:.c=.o)
CC	= /usr/bin/gcc
CFLAGS	= -Wall -Wextra -pedantic -Wformat-security -fstack-protector-all -Wstack-protector -Wl,-z,relro,-z,now,-z,noexecstack -D_FORTIFY_SOURCE=2
EXE	= chatserver
EXE_D = chatserver_debug

all: chatserver
chatserver: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS)

debug: CFLAGS += -D_DEBUG -g
debug: $(OBJ)
	$(CC) -o $(EXE_D) $^ $(CFLAGS) $(LDFLAGS)

clean:
	rm -f $(EXE)* db/*.db  src/*.o  2>/dev/null
