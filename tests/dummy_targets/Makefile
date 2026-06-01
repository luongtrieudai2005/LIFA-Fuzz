CC      = gcc
CFLAGS  = -Wall -Wextra -O0 -g -fno-stack-protector
TARGET  = vulnerable_server
COV_TARGET = vulnerable_server_cov

all: $(TARGET)

$(TARGET): vulnerable_server.c
	$(CC) $(CFLAGS) -o $@ $<

coverage: $(COV_TARGET)

$(COV_TARGET): vulnerable_server.c
	$(CC) -fprofile-arcs -ftest-coverage -O0 -g -Wall -Wextra -o $@ $<

clean:
	rm -f $(TARGET) $(COV_TARGET) *.gcda *.gcno

.PHONY: all coverage clean
