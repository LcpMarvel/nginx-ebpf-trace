CLANG ?= clang
CFLAGS ?= -g -O2 -Wall
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

BPF_CFLAGS ?= -g -O2 -Wall -D__BPF__ \
				-target bpf \
				-D__TARGET_ARCH_$(ARCH) \
				-I$(shell dirname $(shell which clang))/../include

SRCS = src/nginx_trace.c
BPF_SRCS = src/nginx_trace.bpf.c
BPF_OBJS = $(BPF_SRCS:.c=.o)
SKEL_HDRS = $(BPF_SRCS:.bpf.c=.skel.h)

all: nginx-trace

.PHONY: clean

clean:
	rm -rf src/*.o src/*.skel.h nginx-trace

src/%.bpf.o: src/%.bpf.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

src/%.skel.h: src/%.bpf.o
	bpftool gen skeleton $< > $@

nginx-trace: $(SRCS) $(SKEL_HDRS)
	$(CC) $(CFLAGS) -I src/ -o $@ $(SRCS) -lbpf -lelf
