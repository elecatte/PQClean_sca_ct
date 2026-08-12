CC = gcc
CFLAGS = -O3 -Wall -Wextra -march=native -I.. -I../common
LDFLAGS = -lm

# Directory PQClean (relativo a benchmarks/)
MCELIECE_DIR = ../crypto_kem/mceliece6960119/clean
HQC_DIR = ../crypto_kem/hqc-256/clean
COMMON_DIR = ../common

# File sorgente McEliece
MCELIECE_SOURCES = $(wildcard $(MCELIECE_DIR)/*.c)
MCELIECE_OBJECTS = $(MCELIECE_SOURCES:.c=.o)

# File sorgente HQC
HQC_SOURCES = $(wildcard $(HQC_DIR)/*.c)
HQC_OBJECTS = $(HQC_SOURCES:.c=.o)

# File sorgente comuni
COMMON_SOURCES = $(COMMON_DIR)/fips202.c \
		 $(COMMON_DIR)/sp800-185.c \
                 $(COMMON_DIR)/aes.c \
		 $(COMMON_DIR)/sha2.c \
                 $(COMMON_DIR)/nistseedexpander.c \
		 $(COMMON_DIR)/randombytes.c

COMMON_OBJECTS = $(COMMON_SOURCES:.c=.o)

# Target principale
TARGET = sca

all: $(TARGET)

$(TARGET): sca.o $(MCELIECE_OBJECTS) $(HQC_OBJECTS) $(COMMON_OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

sca.o: sca.c
	$(CC) $(CFLAGS) -I$(MCELIECE_DIR) -I$(HQC_DIR) -c $<

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(TARGET) *.o $(MCELIECE_OBJECTS) $(HQC_OBJECTS) $(COMMON_OBJECTS)

run: $(TARGET)
	./$(TARGET)

.PHONY: all clean run