# kernel module Makefile for building eBPF objects
CLANG ?= clang
LLVM_STRIP ?= llvm-strip
BPF_CFLAGS := -O2 -g -target bpf -D__TARGET_ARCH_x86
BPF_CFLAGS += -Iheaders
BPF_CFLAGS += -Wall -Werror
BPF_CFLAGS += -mlittle-endian

SRCS := $(wildcard probes/**/*.bpf.c)
OBJS := $(SRCS:.bpf.c=.bpf.o)

.PHONY: all clean

all: $(OBJS)

%.bpf.o: %.bpf.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	$(LLVM_STRIP) -g $@

clean:
	rm -f probes/**/*.bpf.o probes/**/*.ll
