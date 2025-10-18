CLANG ?= clang
LLC ?= llc
CC ?= gcc

BPF_CFLAGS := -O2 -g -Wall -target bpf

USER_CFLAGS := -O2 -g -Wall
USER_LDFLAGS := -lbpf

KERN_OBJ := covert_channel_kern.o
USER_BIN := covert_channel

all: $(KERN_OBJ) $(USER_BIN)

# Compile kernel BPF program
$(KERN_OBJ): covert_channel_kern.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

# Compile userspace program
$(USER_BIN): covert_channel.c
	$(CC) $(USER_CFLAGS) $< -o $@ $(USER_LDFLAGS)

clean:
	rm -f $(KERN_OBJ) $(USER_BIN)

.PHONY: all clean